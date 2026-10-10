//! The `kv` command line.

use std::fmt;
use std::io::{self, BufRead, IsTerminal};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};
use kv_core::policy::{Mode, Policy};
use kv_core::proto::{
    AgentRequest, AgentResponse, ControlCommand, ControlErrorCode, ControlRequest, ControlResponse,
    DeviceCredential, PolicyPatch, Status,
};
use kv_core::secret::{AuthPlacement, HandleInfo, Secret, SecretText, SecretValue};
use kv_core::vault::device_slots;
use tokio::io::AsyncWriteExt;
use zeroize::Zeroizing;

use crate::client::{self, RunEnd, RunStream};
use crate::daemon::{self, Outcome, Settings};
use crate::device;
use crate::paths::Paths;

#[derive(Parser)]
#[command(
    name = "kv",
    version,
    about = "Lets AI agents use your secrets without seeing them"
)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new vault
    Init {
        #[arg(long, hide = true)]
        insecure_fast_kdf: bool,
    },
    /// Unlock the vault so agents can use its handles
    Unlock,
    /// Lock the vault
    Lock,
    /// Lock the vault and stop the daemon
    Stop,
    /// Show whether the vault is locked
    Status,
    /// List handles and their policies (never values)
    List {
        /// Print JSON instead of a table
        #[arg(long)]
        json: bool,
    },
    /// Add a secret
    Add(AddArgs),
    /// Remove a secret
    Rm { name: String },
    /// Change a secret's policy
    Policy {
        name: String,
        #[command(flatten)]
        policy: PolicyArgs,
    },
    /// Change the vault passphrase
    Passwd,
    /// Unlock with Touch ID (macOS) or Windows Hello instead of the passphrase
    Biometric {
        #[command(subcommand)]
        action: BiometricAction,
    },
    /// Serve MCP on stdin and stdout, for agents such as Claude Code
    Mcp,
    /// Approve agent requests, see handles and lock the vault in a terminal UI
    Tui,
    /// Start a handle's run command with its variables set, on this
    /// process's stdin and stdout (for an MCP client that should talk to
    /// one server directly)
    Run {
        /// An env handle with a run command
        handle: String,
    },
    /// Run the daemon in the foreground (other commands start it on demand)
    Daemon {
        /// Lock the vault after it has gone unused for this long. Daemons
        /// started on demand read KV_IDLE_LOCK.
        #[arg(long, env = "KV_IDLE_LOCK", default_value = "8h", value_parser = humantime::parse_duration)]
        idle_lock: Duration,
        /// Exit after this long with no requests while locked
        #[arg(long, default_value = "10m", value_parser = humantime::parse_duration, hide = true)]
        locked_exit: Duration,
        /// Started by another command: exit quietly if a daemon already runs
        #[arg(long, hide = true)]
        autostart: bool,
        /// Show a desktop notification when a request waits for approval:
        /// on or off. Daemons started on demand read KV_NOTIFY.
        #[arg(
            long,
            env = "KV_NOTIFY",
            action = clap::ArgAction::Set,
            num_args = 0..=1,
            default_value = "on",
            default_missing_value = "on",
            value_name = "ON|OFF",
            hide_possible_values = true,
            value_parser = clap::builder::BoolishValueParser::new()
        )]
        notify: bool,
    },
}

#[derive(Subcommand)]
enum BiometricAction {
    /// Turn it on: asks for the passphrase, then a fingerprint or Hello
    Enable,
    /// Turn it off
    Disable,
}

#[derive(Args)]
struct AddArgs {
    /// Handle name agents use, e.g. openrouter or prod-db
    name: String,
    #[arg(long, value_enum)]
    kind: Kind,
    #[arg(long, default_value = "")]
    description: String,
    /// http: header that carries the token
    #[arg(long, default_value = "Authorization")]
    header: String,
    /// http: header value, with {} where the token goes
    #[arg(long, default_value = "Bearer {}")]
    template: String,
    /// http: send the token as this query parameter instead of a header
    #[arg(long, conflicts_with_all = ["header", "template"])]
    query_param: Option<String>,
    /// http: keep the service's address hidden too. Prompts for a base URL
    /// such as https://dokploy.example.com/api; agents then send only paths
    #[arg(long)]
    base_url: bool,
    /// env: variable to inject (repeat for several); each value is prompted for
    #[arg(long = "var", value_name = "NAME")]
    vars: Vec<String>,
    /// Overwrite an existing handle with this name
    #[arg(long)]
    replace: bool,
    #[command(flatten)]
    policy: PolicyArgs,
}

#[derive(Clone, Copy, ValueEnum)]
enum Kind {
    Http,
    Postgres,
    Redis,
    Env,
}

#[derive(Args)]
struct PolicyArgs {
    #[arg(long, value_enum)]
    mode: Option<ModeArg>,
    /// http: host or host:port the token may be sent to (repeat; "" clears)
    #[arg(long = "host", value_name = "HOST")]
    hosts: Vec<String>,
    /// http: allow plain http:// URLs
    #[arg(long, value_name = "BOOL")]
    allow_plain_http: Option<bool>,
    /// http: allowed method (repeat; "" clears, meaning any method)
    #[arg(long = "method", value_name = "METHOD")]
    methods: Vec<String>,
    /// postgres/redis: refuse writes
    #[arg(long, value_name = "BOOL")]
    read_only: Option<bool>,
    /// env: program allowed to receive the variables, a bare name or an
    /// absolute path (repeat; "" clears)
    #[arg(long = "cmd", value_name = "PROGRAM")]
    cmds: Vec<String>,
    /// How long "allow for session" approvals last
    #[arg(long, value_parser = humantime::parse_duration)]
    grant_ttl: Option<Duration>,
    /// env: the exact command kv run and kv mcp start, given after `--`,
    /// e.g. --run -- bunx -y ssh-mcp@1.2.3 --host=10.0.0.5
    #[arg(long, requires = "run_argv")]
    run: bool,
    /// env: remove the handle's run command
    #[arg(long, conflicts_with = "run")]
    no_run: bool,
    #[arg(last = true, value_name = "COMMAND", requires = "run")]
    run_argv: Vec<String>,
}

#[derive(Clone, Copy, ValueEnum)]
enum ModeArg {
    Auto,
    Ask,
    Deny,
}

impl From<ModeArg> for Mode {
    fn from(mode: ModeArg) -> Self {
        match mode {
            ModeArg::Auto => Mode::Auto,
            ModeArg::Ask => Mode::Ask,
            ModeArg::Deny => Mode::Deny,
        }
    }
}

impl PolicyArgs {
    fn patch(&self) -> PolicyPatch {
        let list = |values: &[String]| {
            (!values.is_empty()).then(|| {
                values
                    .iter()
                    .filter(|v| !v.is_empty())
                    .cloned()
                    .collect::<Vec<_>>()
            })
        };
        PolicyPatch {
            mode: self.mode.map(Mode::from),
            allowed_hosts: list(&self.hosts),
            allow_plain_http: self.allow_plain_http,
            allowed_methods: list(&self.methods),
            read_only: self.read_only,
            allowed_cmds: list(&self.cmds),
            run: if self.no_run {
                Some(Vec::new())
            } else if self.run {
                Some(self.run_argv.clone())
            } else {
                None
            },
            grant_ttl: self.grant_ttl,
        }
    }
}

struct CliError(String);

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<io::Error> for CliError {
    fn from(error: io::Error) -> Self {
        Self(error.to_string())
    }
}

type Result<T> = std::result::Result<T, CliError>;

pub fn main() -> ExitCode {
    let cli = Cli::parse();
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("kv: cannot start the async runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    if let Command::Run { handle } = &cli.command {
        let code = runtime.block_on(run_handle(handle));
        // Exit at once: a read blocked on this terminal's stdin would keep the
        // runtime from shutting down.
        std::process::exit(code);
    }
    match runtime.block_on(run(cli)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("kv: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<()> {
    let paths = Paths::from_env()?;
    let mut input = Input::new();
    match cli.command {
        Command::Daemon {
            idle_lock,
            locked_exit,
            autostart,
            notify,
        } => {
            let outcome = daemon::run(
                paths,
                Settings {
                    idle_lock,
                    locked_exit,
                    notify,
                    ..Settings::default()
                },
            )
            .await?;
            if outcome == Outcome::AlreadyRunning && !autostart {
                return Err(CliError(
                    "a daemon is already running; run `kv stop` first".into(),
                ));
            }
            Ok(())
        }
        Command::Init { insecure_fast_kdf } => {
            let passphrase = input.new_passphrase("New vault passphrase: ")?;
            control(
                &paths,
                Some(passphrase),
                ControlCommand::Init { insecure_fast_kdf },
            )
            .await?;
            println!("vault created and unlocked");
            Ok(())
        }
        Command::Unlock => {
            authorized(&paths, &mut input, ControlCommand::Unlock).await?;
            println!("unlocked");
            Ok(())
        }
        Command::Lock => {
            stop_or_lock(&paths, ControlCommand::Lock).await?;
            println!("locked");
            Ok(())
        }
        Command::Stop => {
            stop_or_lock(&paths, ControlCommand::Stop).await?;
            println!("stopped");
            Ok(())
        }
        Command::Status => {
            match client::agent(&paths, None, &AgentRequest::Status).await? {
                AgentResponse::Status { status } => println!("{}", describe_status(&status)),
                other => return Err(unexpected(&other)),
            }
            Ok(())
        }
        Command::List { json } => {
            let handles = match client::agent(&paths, None, &AgentRequest::ListHandles).await? {
                AgentResponse::Handles { handles } => handles,
                AgentResponse::Error { message, .. } => return Err(CliError(message)),
                other => return Err(unexpected(&other)),
            };
            if json {
                let text =
                    serde_json::to_string_pretty(&handles).map_err(|e| CliError(e.to_string()))?;
                println!("{text}");
            } else {
                print!("{}", handle_table(&handles));
            }
            Ok(())
        }
        Command::Add(args) => {
            let credential = input
                .credential(&paths, &adding(&args.name, args.replace))
                .await?;
            let value = read_value(&args, &mut input)?;
            let mut policy = Policy::default();
            args.policy.patch().apply(&mut policy);
            // Checked here, where the URL already is, so a slow database
            // never holds up the daemon.
            let role_url = match &value {
                SecretValue::Postgres { url } if policy.read_only => Some(url.clone()),
                _ => None,
            };
            let secret = Secret {
                name: args.name.clone(),
                description: args.description.clone(),
                value,
                policy,
                created_at: 0,
                updated_at: 0,
            };
            let command = ControlCommand::Add {
                secret,
                replace: args.replace,
            };
            send_as(&paths, &mut input, credential, command).await?;
            println!("added {}", args.name);
            if let Some(url) = role_url {
                match crate::broker::db::check_role(&args.name, url.expose()).await {
                    Ok(None) => {}
                    Ok(Some(warning)) => eprintln!("warning: {warning}"),
                    Err(why) => eprintln!(
                        "note: could not check the database role ({why}); kv checks it again on first use"
                    ),
                }
            }
            Ok(())
        }
        Command::Rm { name } => {
            let command = ControlCommand::Remove { name: name.clone() };
            authorized(&paths, &mut input, command).await?;
            println!("removed {name}");
            Ok(())
        }
        Command::Policy { name, policy } => {
            let patch = policy.patch();
            if patch == PolicyPatch::default() {
                return Err(CliError(
                    "nothing to change; pass at least one policy flag".into(),
                ));
            }
            let command = ControlCommand::SetPolicy {
                name: name.clone(),
                patch,
            };
            authorized(&paths, &mut input, command).await?;
            println!("updated {name}");
            Ok(())
        }
        Command::Mcp => {
            crate::mcp::serve(paths).await?;
            Ok(())
        }
        Command::Tui => {
            crate::tui::run(paths).await?;
            Ok(())
        }
        Command::Run { .. } => unreachable!("main runs kv run before this"),
        Command::Passwd => {
            let passphrase = input.secret("Current passphrase: ")?;
            let new_passphrase = input.new_passphrase("New passphrase: ")?;
            let enrolled = device_slots(&paths.vault).unwrap_or_default();
            control(
                &paths,
                Some(passphrase),
                ControlCommand::ChangePassphrase { new_passphrase },
            )
            .await?;
            // The new vault key has no device slots: their keys open nothing.
            if let Some(native) = device::native() {
                for slot in enrolled.iter().filter(|slot| slot.kind == native.kind()) {
                    native.forget(&slot.id);
                }
            }
            println!("passphrase changed");
            Ok(())
        }
        Command::Biometric {
            action: BiometricAction::Enable,
        } => enable_device(&paths, &mut input).await,
        Command::Biometric {
            action: BiometricAction::Disable,
        } => disable_device(&paths, &mut input).await,
    }
}

/// `kv run`: relays this process's stdin, stdout and stderr to the
/// handle's program, and returns the exit status to use: the program's,
/// 128 + the signal that ended it, or 1 when kv refused or ended it.
async fn run_handle(handle: &str) -> i32 {
    let paths = match Paths::from_env() {
        Ok(paths) => paths,
        Err(e) => {
            eprintln!("kv run: {e}");
            return 1;
        }
    };
    let started = match client::run_stream(&paths, None, handle).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(AgentResponse::Error { code, message })) => {
            eprintln!("kv run: {}: {message}", code.as_str());
            return 1;
        }
        Ok(Err(other)) => {
            eprintln!("kv run: unexpected reply from the daemon: {other:?}");
            return 1;
        }
        Err(e) => {
            eprintln!("kv run: daemon_unavailable: {e}");
            return 1;
        }
    };
    let RunStream {
        mut stdin,
        mut stdout,
        mut stderr,
        ended,
        guard,
    } = started;
    let input = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut tokio::io::stdin(), &mut stdin).await;
        let _ = stdin.shutdown().await;
    });
    let output = tokio::spawn(async move {
        let mut out = tokio::io::stdout();
        let _ = tokio::io::copy(&mut stdout, &mut out).await;
        let _ = out.flush().await;
    });
    let errors = tokio::spawn(async move {
        let mut err = tokio::io::stderr();
        while let Some(chunk) = stderr.recv().await {
            let _ = err.write_all(&chunk).await;
            let _ = err.flush().await;
        }
    });
    let end = ended.await.unwrap_or(RunEnd::Lost);
    let _ = output.await;
    let _ = errors.await;
    input.abort();
    drop(guard);
    match end {
        RunEnd::Exited {
            code: Some(code), ..
        } => code,
        RunEnd::Exited {
            signal: Some(signal),
            ..
        } => 128 + signal,
        RunEnd::Exited { .. } => 1,
        RunEnd::Ended(reason) => {
            eprintln!("kv run: {reason}");
            1
        }
        RunEnd::Lost => {
            eprintln!("kv run: kv stopped");
            1
        }
    }
}

async fn enable_device(paths: &Paths, input: &mut Input) -> Result<()> {
    let Some(device) = device::platform() else {
        return Err(CliError(no_device()));
    };
    device.available().map_err(CliError)?;
    let passphrase = input.secret("Vault passphrase: ")?;
    let previous = device_slots(&paths.vault)
        .unwrap_or_default()
        .into_iter()
        .find(|slot| slot.kind == device.kind());
    let (enrolled, device) = tokio::task::spawn_blocking(move || {
        let enrolled = device::enroll(device.as_ref());
        (enrolled, device)
    })
    .await
    .map_err(|e| CliError(e.to_string()))?;
    let (slot, key) = enrolled.map_err(CliError)?;
    let id = slot.id.clone();
    if let Err(e) = control(paths, Some(passphrase), device::enroll_command(slot, &key)).await {
        device.forget(&id);
        return Err(e);
    }
    if let Some(previous) = previous {
        device.forget(&previous.id);
    }
    println!("{} unlock is on", device.kind().label());
    Ok(())
}

async fn disable_device(paths: &Paths, input: &mut Input) -> Result<()> {
    let Some(device) = device::native() else {
        return Err(CliError(no_device()));
    };
    let kind = device.kind();
    let Some(slot) = device_slots(&paths.vault)
        .map_err(|e| CliError(e.to_string()))?
        .into_iter()
        .find(|slot| slot.kind == kind)
    else {
        return Err(CliError(format!("{} unlock is not on", kind.label())));
    };
    authorized(paths, input, ControlCommand::RemoveDevice { kind }).await?;
    device.forget(&slot.id);
    println!("{} unlock is off", kind.label());
    Ok(())
}

fn no_device() -> String {
    match device::native() {
        Some(device) => format!(
            "{} unlock is turned off by KV_BIOMETRIC; unset it to use it",
            device.kind().label()
        ),
        None => "there is no biometric unlock kv can use on this platform (it uses Touch ID on \
                 macOS and Windows Hello on Windows)"
            .into(),
    }
}

/// How a command proves it comes from the user.
enum Credential {
    Passphrase(SecretText),
    Device(DeviceCredential),
}

/// Sends `command` with the credential `Input::credential` picks.
async fn authorized(paths: &Paths, input: &mut Input, command: ControlCommand) -> Result<()> {
    let credential = input.credential(paths, &device_reason(&command)).await?;
    send_as(paths, input, credential, command).await
}

/// What a Touch ID prompt for `command` says kv is trying to do.
fn device_reason(command: &ControlCommand) -> String {
    match command {
        ControlCommand::Add { secret, replace } => adding(&secret.name, *replace),
        ControlCommand::Remove { name } => format!("remove the handle {name} from the kv vault"),
        ControlCommand::SetPolicy { name, .. } => {
            format!("change the policy of the kv handle {name}")
        }
        ControlCommand::RemoveDevice { kind } => {
            format!("turn off {} unlock for the kv vault", kind.label())
        }
        _ => "unlock the kv vault".into(),
    }
}

fn adding(name: &str, replace: bool) -> String {
    if replace {
        format!("replace the handle {name} in the kv vault")
    } else {
        format!("add the handle {name} to the kv vault")
    }
}

/// Sends `command` with `credential`. If the daemon turns down a device key
/// (the vault changed since it was set up), asks for the passphrase and
/// sends it again.
async fn send_as(
    paths: &Paths,
    input: &mut Input,
    credential: Credential,
    command: ControlCommand,
) -> Result<()> {
    let device = match credential {
        Credential::Passphrase(passphrase) => {
            return control(paths, Some(passphrase), command).await;
        }
        Credential::Device(device) => device,
    };
    match send(paths, None, Some(device), command.clone()).await? {
        Ok(()) => Ok(()),
        Err((ControlErrorCode::WrongDeviceKey, message)) => {
            eprintln!("{message}; run `kv biometric enable` to set it up again");
            let passphrase = input.secret("Vault passphrase: ")?;
            control(paths, Some(passphrase), command).await
        }
        Err((_, message)) => Err(CliError(message)),
    }
}

/// Sends a control command and prints its warnings. Errors become `CliError`.
async fn control(
    paths: &Paths,
    passphrase: Option<SecretText>,
    command: ControlCommand,
) -> Result<()> {
    send(paths, passphrase, None, command)
        .await?
        .map_err(|(_, message)| CliError(message))
}

/// Sends a control command and prints its warnings; the outer `Err` is a
/// failure to reach the daemon, the inner one the daemon's refusal.
async fn send(
    paths: &Paths,
    passphrase: Option<SecretText>,
    device: Option<DeviceCredential>,
    command: ControlCommand,
) -> Result<std::result::Result<(), (ControlErrorCode, String)>> {
    let request = ControlRequest {
        passphrase,
        device,
        token: None,
        command,
    };
    match client::control(paths, &request, true).await? {
        ControlResponse::Done { warnings } => {
            for warning in warnings {
                eprintln!("warning: {warning}");
            }
            Ok(Ok(()))
        }
        ControlResponse::Error { code, message } => Ok(Err((code, message))),
        other => Err(CliError(format!(
            "unexpected reply from the daemon: {other:?}"
        ))),
    }
}

/// `lock` and `stop` succeed without doing anything when no daemon runs.
async fn stop_or_lock(paths: &Paths, command: ControlCommand) -> Result<()> {
    let request = ControlRequest {
        passphrase: None,
        device: None,
        token: None,
        command,
    };
    match client::control_if_running(paths, &request).await? {
        None | Some(ControlResponse::Done { .. }) => Ok(()),
        Some(ControlResponse::Error { message, .. }) => Err(CliError(message)),
        Some(other) => Err(CliError(format!(
            "unexpected reply from the daemon: {other:?}"
        ))),
    }
}

fn read_value(args: &AddArgs, input: &mut Input) -> Result<SecretValue> {
    let name = &args.name;
    Ok(match args.kind {
        Kind::Http => {
            let placement = match &args.query_param {
                Some(param) => AuthPlacement::Query {
                    param: param.clone(),
                },
                None => AuthPlacement::Header {
                    name: args.header.clone(),
                    template: args.template.clone(),
                },
            };
            let token = trimmed(input.secret(&format!("Token for {name}: "))?);
            let base_url = if args.base_url {
                let base = trimmed(input.secret(&format!("Base URL for {name}: "))?);
                Some(base.expose().to_owned())
            } else {
                None
            };
            SecretValue::Http {
                token,
                placement,
                base_url,
            }
        }
        Kind::Postgres => SecretValue::Postgres {
            url: trimmed(input.secret(&format!("Connection URL for {name}: "))?),
        },
        Kind::Redis => SecretValue::Redis {
            url: trimmed(input.secret(&format!("Connection URL for {name}: "))?),
        },
        Kind::Env => {
            if args.vars.is_empty() && !args.policy.run {
                return Err(CliError(
                    "an env secret needs at least one --var NAME, or a --run command".into(),
                ));
            }
            let mut vars = std::collections::BTreeMap::new();
            for var in &args.vars {
                vars.insert(var.clone(), input.secret(&format!("Value for {var}: "))?);
            }
            SecretValue::Env { vars }
        }
    })
}

/// Tokens and connection URLs never mean anything with surrounding
/// whitespace, which is easy to pick up when pasting.
fn trimmed(value: SecretText) -> SecretText {
    let trimmed = value.expose().trim();
    if trimmed.len() == value.expose().len() {
        value
    } else {
        SecretText::new(trimmed)
    }
}

/// Reads secrets from the terminal without echo, or one line each from stdin
/// when stdin is not a terminal (scripts and tests). Passphrases keep every
/// character except the line ending.
struct Input {
    interactive: bool,
}

impl Input {
    fn new() -> Self {
        Self {
            interactive: io::stdin().is_terminal(),
        }
    }

    /// Touch ID or Windows Hello when the vault has a slot for this
    /// platform's device and stdin is a terminal (so scripts keep reading
    /// the passphrase from stdin), or else the passphrase.
    async fn credential(&mut self, paths: &Paths, reason: &str) -> io::Result<Credential> {
        if self.interactive
            && let Some(device) = device::platform()
        {
            let label = device.kind().label();
            let vault = paths.vault.clone();
            let reason = reason.to_owned();
            let asked = tokio::task::spawn_blocking(move || {
                device::credential(&vault, device.as_ref(), &reason)
            })
            .await
            .map_err(io::Error::other)?;
            match asked {
                Some(Ok(credential)) => return Ok(Credential::Device(credential)),
                Some(Err(why)) => eprintln!("{label}: {why}"),
                None => {}
            }
        }
        self.secret("Vault passphrase: ")
            .map(Credential::Passphrase)
    }

    fn secret(&mut self, prompt: &str) -> io::Result<SecretText> {
        if self.interactive {
            return rpassword::prompt_password(prompt).map(SecretText::new);
        }
        let mut line = Zeroizing::new(String::new());
        if io::stdin().lock().read_line(&mut line)? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!(
                    "stdin ended before: {}",
                    prompt.trim_end_matches([' ', ':'])
                ),
            ));
        }
        let end = line.trim_end_matches(['\n', '\r']).len();
        line.truncate(end);
        Ok(SecretText::new(std::mem::take(&mut *line)))
    }

    /// Asks twice on a terminal so a typo does not lock the user out.
    fn new_passphrase(&mut self, prompt: &str) -> Result<SecretText> {
        let first = self.secret(prompt)?;
        if self.interactive {
            let second = self.secret("Repeat it: ")?;
            if first.expose() != second.expose() {
                return Err(CliError("the passphrases do not match".into()));
            }
        }
        Ok(first)
    }
}

fn describe_status(status: &Status) -> String {
    if !status.vault_exists {
        return "no vault yet: run `kv init`".into();
    }
    let mut line = if status.locked {
        "locked: run `kv unlock`".to_owned()
    } else {
        let count = status.handle_count.unwrap_or(0);
        let plural = if count == 1 { "" } else { "s" };
        match status.locks_in_secs {
            Some(secs) => format!(
                "unlocked: {count} handle{plural}, locks after {} unused",
                humantime::format_duration(Duration::from_secs(secs))
            ),
            None => format!("unlocked: {count} handle{plural}"),
        }
    };
    for kind in &status.devices {
        line.push_str(&format!("\n{} unlock is on", kind.label()));
    }
    match status.pending_approvals {
        0 => {}
        1 => line.push_str("\n1 request is waiting for approval: run `kv tui`"),
        n => line.push_str(&format!(
            "\n{n} requests are waiting for approval: run `kv tui`"
        )),
    }
    line
}

fn handle_table(handles: &[HandleInfo]) -> String {
    if handles.is_empty() {
        return "no handles yet: add one with `kv add`\n".into();
    }
    let rows: Vec<[String; 5]> = handles
        .iter()
        .map(|h| {
            [
                h.name.clone(),
                format!("{:?}", h.kind).to_lowercase(),
                format!("{:?}", h.mode).to_lowercase(),
                constraints(h),
                h.description.clone(),
            ]
        })
        .collect();
    let header = ["NAME", "KIND", "MODE", "ALLOWS", "DESCRIPTION"].map(String::from);
    let mut widths = header.clone().map(|h| h.len());
    for row in &rows {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.chars().count());
        }
    }
    let mut out = String::new();
    for row in std::iter::once(&header).chain(&rows) {
        let cells: Vec<String> = row
            .iter()
            .zip(widths)
            .map(|(cell, width)| format!("{cell:width$}"))
            .collect();
        out.push_str(cells.join("  ").trim_end());
        out.push('\n');
    }
    out
}

fn constraints(handle: &HandleInfo) -> String {
    let mut parts = Vec::new();
    if !handle.allowed_hosts.is_empty() {
        parts.push(format!("hosts={}", handle.allowed_hosts.join(",")));
    }
    if handle.takes_path {
        parts.push("paths-only".into());
    }
    if handle.allow_plain_http {
        parts.push("plain-http".into());
    }
    if !handle.allowed_methods.is_empty() {
        parts.push(format!("methods={}", handle.allowed_methods.join(",")));
    }
    if !handle.allowed_cmds.is_empty() {
        parts.push(format!("cmds={}", handle.allowed_cmds.join(",")));
    }
    if !handle.env_vars.is_empty() {
        parts.push(format!("vars={}", handle.env_vars.join(",")));
    }
    if let Some(program) = &handle.runs {
        parts.push(format!("runs={program}"));
    }
    if handle.read_only {
        parts.push("read-only".into());
    }
    if parts.is_empty() {
        "-".into()
    } else {
        parts.join(" ")
    }
}

fn unexpected(response: &AgentResponse) -> CliError {
    match response {
        AgentResponse::Error { message, .. } => CliError(message.clone()),
        other => CliError(format!("unexpected reply from the daemon: {other:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kv_core::vault::DeviceKind;

    #[test]
    fn notify_takes_on_or_off() {
        let notify = |args: &[&str]| match Cli::try_parse_from([&["kv", "daemon"], args].concat()) {
            Ok(Cli {
                command: Command::Daemon { notify, .. },
                ..
            }) => notify,
            Ok(_) => unreachable!(),
            Err(e) => panic!("{args:?}: {e}"),
        };
        assert!(!notify(&["--notify", "off"]));
        assert!(!notify(&["--notify=false"]));
        assert!(notify(&["--notify", "on"]));
        assert!(notify(&["--notify"]));
    }

    #[test]
    fn trimmed_strips_surrounding_whitespace_only() {
        assert_eq!(
            trimmed(SecretText::new("  sk-abc def \n")).expose(),
            "sk-abc def"
        );
        assert_eq!(trimmed(SecretText::new("sk-abc")).expose(), "sk-abc");
    }

    #[test]
    fn run_takes_everything_after_the_double_dash() {
        let policy =
            |args: &[&str]| match Cli::try_parse_from([&["kv", "policy", "srv"], args].concat()) {
                Ok(Cli {
                    command: Command::Policy { policy, .. },
                }) => Ok(policy.patch().run),
                Ok(_) => unreachable!(),
                Err(e) => Err(e.to_string()),
            };
        assert_eq!(
            policy(&[
                "--run",
                "--",
                "bunx",
                "-y",
                "ssh-mcp@1.2.3",
                "--host=10.0.0.5"
            ]),
            Ok(Some(vec![
                "bunx".into(),
                "-y".into(),
                "ssh-mcp@1.2.3".into(),
                "--host=10.0.0.5".into()
            ]))
        );
        assert_eq!(policy(&["--no-run"]), Ok(Some(Vec::new())));
        assert_eq!(policy(&["--mode", "auto"]).unwrap(), None);
        assert!(policy(&["--run"]).is_err());
        assert!(policy(&["--", "bunx"]).is_err());
        assert!(policy(&["--run", "--no-run", "--", "bunx"]).is_err());
    }

    #[test]
    fn policy_flags_build_a_patch_and_empty_string_clears_a_list() {
        let args = PolicyArgs {
            mode: Some(ModeArg::Auto),
            hosts: vec![String::new()],
            allow_plain_http: None,
            methods: vec!["GET".into()],
            read_only: Some(true),
            cmds: Vec::new(),
            grant_ttl: None,
            run: false,
            no_run: false,
            run_argv: Vec::new(),
        };
        let patch = args.patch();
        assert_eq!(patch.mode, Some(Mode::Auto));
        assert_eq!(patch.allowed_hosts, Some(Vec::new()));
        assert_eq!(patch.allowed_methods, Some(vec!["GET".to_string()]));
        assert_eq!(patch.allowed_cmds, None);
        assert_eq!(patch.read_only, Some(true));
    }

    #[test]
    fn the_device_prompt_names_the_change() {
        let name = || "prod-db".to_owned();
        assert_eq!(
            device_reason(&ControlCommand::Unlock),
            "unlock the kv vault"
        );
        assert_eq!(
            device_reason(&ControlCommand::Remove { name: name() }),
            "remove the handle prod-db from the kv vault"
        );
        assert_eq!(
            device_reason(&ControlCommand::SetPolicy {
                name: name(),
                patch: PolicyPatch::default(),
            }),
            "change the policy of the kv handle prod-db"
        );
        assert_eq!(
            device_reason(&ControlCommand::RemoveDevice {
                kind: DeviceKind::TouchId
            }),
            "turn off Touch ID unlock for the kv vault"
        );
        assert_eq!(
            adding("prod-db", false),
            "add the handle prod-db to the kv vault"
        );
        assert_eq!(
            adding("prod-db", true),
            "replace the handle prod-db in the kv vault"
        );
    }

    #[test]
    fn status_says_which_devices_can_unlock() {
        let status = |locked, devices| Status {
            vault_exists: true,
            locked,
            handle_count: (!locked).then_some(2),
            locks_in_secs: None,
            pending_approvals: 0,
            devices,
        };
        assert_eq!(
            describe_status(&status(true, vec![])),
            "locked: run `kv unlock`"
        );
        assert_eq!(
            describe_status(&status(true, vec![DeviceKind::TouchId])),
            "locked: run `kv unlock`\nTouch ID unlock is on"
        );
        assert_eq!(
            describe_status(&status(false, vec![DeviceKind::WindowsHello])),
            "unlocked: 2 handles\nWindows Hello unlock is on"
        );
    }

    #[test]
    fn cli_definition_is_valid() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }
}
