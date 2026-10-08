//! The `kv` command line.

use std::fmt;
use std::io::{self, BufRead, IsTerminal};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};
use kv_core::policy::{Mode, Policy};
use kv_core::proto::{
    AgentRequest, AgentResponse, ControlCommand, ControlRequest, ControlResponse, PolicyPatch,
    Status,
};
use kv_core::secret::{AuthPlacement, HandleInfo, Secret, SecretText, SecretValue};
use zeroize::Zeroizing;

use crate::client;
use crate::daemon::{self, Outcome, Settings};
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
    /// Serve MCP on stdin and stdout, for agents such as Claude Code
    Mcp,
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
        #[arg(long, env = "KV_NOTIFY", default_value = "on", value_parser = clap::builder::BoolishValueParser::new())]
        notify: bool,
    },
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
            let passphrase = input.secret("Vault passphrase: ")?;
            control(&paths, Some(passphrase), ControlCommand::Unlock).await?;
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
            let passphrase = input.secret("Vault passphrase: ")?;
            let value = read_value(&args, &mut input)?;
            let mut policy = Policy::default();
            args.policy.patch().apply(&mut policy);
            let secret = Secret {
                name: args.name.clone(),
                description: args.description.clone(),
                value,
                policy,
                created_at: 0,
                updated_at: 0,
            };
            control(
                &paths,
                Some(passphrase),
                ControlCommand::Add {
                    secret,
                    replace: args.replace,
                },
            )
            .await?;
            println!("added {}", args.name);
            Ok(())
        }
        Command::Rm { name } => {
            let passphrase = input.secret("Vault passphrase: ")?;
            control(
                &paths,
                Some(passphrase),
                ControlCommand::Remove { name: name.clone() },
            )
            .await?;
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
            let passphrase = input.secret("Vault passphrase: ")?;
            control(
                &paths,
                Some(passphrase),
                ControlCommand::SetPolicy {
                    name: name.clone(),
                    patch,
                },
            )
            .await?;
            println!("updated {name}");
            Ok(())
        }
        Command::Mcp => {
            crate::mcp::serve(paths).await?;
            Ok(())
        }
        Command::Passwd => {
            let passphrase = input.secret("Current passphrase: ")?;
            let new_passphrase = input.new_passphrase("New passphrase: ")?;
            control(
                &paths,
                Some(passphrase),
                ControlCommand::ChangePassphrase { new_passphrase },
            )
            .await?;
            println!("passphrase changed");
            Ok(())
        }
    }
}

/// Sends a control command and prints its warnings. Errors become `CliError`.
async fn control(
    paths: &Paths,
    passphrase: Option<SecretText>,
    command: ControlCommand,
) -> Result<()> {
    let request = ControlRequest {
        passphrase,
        token: None,
        command,
    };
    match client::control(paths, &request, true).await? {
        ControlResponse::Done { warnings } => {
            for warning in warnings {
                eprintln!("warning: {warning}");
            }
            Ok(())
        }
        ControlResponse::Error { message, .. } => Err(CliError(message)),
        other => Err(CliError(format!(
            "unexpected reply from the daemon: {other:?}"
        ))),
    }
}

/// `lock` and `stop` succeed without doing anything when no daemon runs.
async fn stop_or_lock(paths: &Paths, command: ControlCommand) -> Result<()> {
    let request = ControlRequest {
        passphrase: None,
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
            if args.vars.is_empty() {
                return Err(CliError(
                    "an env secret needs at least one --var NAME".into(),
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
    if status.locked {
        return "locked: run `kv unlock`".into();
    }
    let count = status.handle_count.unwrap_or(0);
    let plural = if count == 1 { "" } else { "s" };
    let mut line = match status.locks_in_secs {
        Some(secs) => format!(
            "unlocked: {count} handle{plural}, locks after {} unused",
            humantime::format_duration(Duration::from_secs(secs))
        ),
        None => format!("unlocked: {count} handle{plural}"),
    };
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

    #[test]
    fn trimmed_strips_surrounding_whitespace_only() {
        assert_eq!(
            trimmed(SecretText::new("  sk-abc def \n")).expose(),
            "sk-abc def"
        );
        assert_eq!(trimmed(SecretText::new("sk-abc")).expose(), "sk-abc");
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
        };
        let patch = args.patch();
        assert_eq!(patch.mode, Some(Mode::Auto));
        assert_eq!(patch.allowed_hosts, Some(Vec::new()));
        assert_eq!(patch.allowed_methods, Some(vec!["GET".to_string()]));
        assert_eq!(patch.allowed_cmds, None);
        assert_eq!(patch.read_only, Some(true));
    }

    #[test]
    fn cli_definition_is_valid() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }
}
