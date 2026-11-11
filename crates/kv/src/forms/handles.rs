//! The forms for handles, and the effect each one saves as.

use std::collections::BTreeMap;
use std::time::Duration;

use kv_core::policy::{Mode, Policy};
use kv_core::proto::{PolicyPatch, RequestedHandle};
use kv_core::secret::{AuthPlacement, HandleInfo, Secret, SecretKind, SecretText, SecretValue};

use super::{Explained, Field, Form};
use crate::tui::app::Effect;

const KINDS: &[&str] = &["http", "env", "postgres", "redis"];

/// The kinds in the words of what an agent will do with the secret: someone
/// adding their first handle knows they have "an OpenAI key", not that it
/// is an http handle. A handle's kind cannot be changed after it is added.
const KINDS_EXPLAINED: &[Explained] = &[
    Explained {
        value: "http",
        title: "Call a web API",
        detail: "An API key or token for a service such as OpenAI, GitHub or Stripe. \
                 Agents call the service with http_request, and kv sends the token \
                 only to the hosts you allow.",
    },
    Explained {
        value: "env",
        title: "Run a program or CLI",
        detail: "Environment variables a program reads, such as AWS keys for aws or \
                 terraform, or an MCP server's password. Agents run the commands you \
                 allow with exec.",
    },
    Explained {
        value: "postgres",
        title: "Query a Postgres database",
        detail: "A postgres:// connection URL. Agents run SQL with db_query or \
                 db_connect, and the handle can be made read only.",
    },
    Explained {
        value: "redis",
        title: "Use a Redis server",
        detail: "A redis:// connection URL. Agents run commands with db_query or \
                 db_connect, and the handle can be made read only.",
    },
];
const MODES: &[&str] = &["ask", "auto", "deny"];
const NO_YES: &[&str] = &["no", "yes"];

/// What a form is for.
pub enum Purpose {
    Add,
    Edit(HandleInfo),
    Policy(HandleInfo),
}

pub fn new_handle() -> Form {
    let mut fields = vec![
        Field::choice("kind", "Kind", KINDS)
            .explained(KINDS_EXPLAINED)
            .hint("can't be changed after the handle is added"),
        Field::text("name", "Name"),
        Field::text("description", "Description"),
    ];
    fields.extend(value_fields());
    fields.extend([
        Field::text("hosts", "Allowed hosts")
            .hint("comma-separated, e.g. api.example.com")
            .when("kind", &["http"]),
        Field::text("cmds", "Allowed commands")
            .hint("comma-separated, e.g. terraform, aws")
            .when("kind", &["env"]),
        Field::choice("mode", "Mode", MODES),
    ]);
    Form::new("New handle", fields)
}

/// The New handle form filled in from an agent's request, with the focus
/// on the secret: the one thing the agent could not say.
pub fn requested_handle(requested: &RequestedHandle) -> Form {
    let request = &requested.request;
    let mut form = new_handle();
    let kind = kind_name(request.kind);
    form.field_mut("kind").set_choice(kind);
    form.field_mut("name").text = request.name.clone().into();
    form.field_mut("description").text = request.description.clone().into();
    match &request.auth {
        Some(AuthPlacement::Header { name, template }) => {
            form.field_mut("header").text = name.clone().into();
            form.field_mut("template").text = template.clone().into();
        }
        Some(AuthPlacement::Query { param }) => {
            form.field_mut("placement").set_choice("query");
            form.field_mut("param").text = param.clone().into();
        }
        None => {}
    }
    if request.base_url {
        form.field_mut("base_url").hint =
            "asked for: agents send only a path; type the service's URL".into();
    }
    form.field_mut("hosts").text = request.allowed_hosts.join(", ").into();
    // A program the agent names could be a shell that runs anything, so
    // it is only offered: the user types or picks the ones they allow.
    if !request.allowed_cmds.is_empty() {
        let cmds = form.field_mut("cmds");
        cmds.hint = format!(
            "asked for {}; type or pick the ones you allow",
            request.allowed_cmds.join(", ")
        );
        cmds.suggested = request.allowed_cmds.clone();
    }
    // The variables' names come in, so the user types only the values.
    if !request.env_vars.is_empty() {
        let vars = form.field_mut("vars");
        vars.hint = format!(
            "NAME=value, Enter adds; asked for {}",
            request.env_vars.join(", ")
        );
        vars.suggested = request.env_vars.clone();
    }
    form.focus_on(match kind {
        "http" => "token",
        "env" => "vars",
        _ => "url",
    });
    form
}

pub fn edit_handle(handle: &HandleInfo) -> Form {
    let kind = kind_name(handle.kind);
    let mut fields = vec![Field::text("description", "Description").with_text(&handle.description)];
    for field in value_fields() {
        let field = match field.depends_on() {
            Some(("kind", kinds)) if !kinds.contains(&kind) => continue,
            Some(("kind", _)) => field.without_condition(),
            Some(("placement", _)) if kind != "http" => continue,
            _ => field,
        };
        fields.push(prefill(field, handle));
    }
    if handle.kind == SecretKind::Env {
        // The window draws a row for each variable the handle has, by name;
        // kv tui, which has no rows, takes the names to remove as text.
        if let Some(vars) = fields.iter_mut().find(|f| f.key == "vars") {
            vars.existing = handle.env_vars.clone();
        }
        fields.push(
            Field::text("remove", "Remove variables")
                .hint(format!(
                    "comma-separated; has {}",
                    handle.env_vars.join(", ")
                ))
                .tui_only(),
        );
    }
    Form::new(format!("Edit {}", handle.name), fields)
}

pub fn edit_policy(handle: &HandleInfo) -> Form {
    let mut fields = vec![Field::choice("mode", "Mode", MODES).with_choice(mode_name(handle.mode))];
    match handle.kind {
        SecretKind::Http => fields.extend([
            Field::text("hosts", "Allowed hosts")
                .with_text(&handle.allowed_hosts.join(", "))
                .hint("comma-separated; empty denies all"),
            Field::choice("plain_http", "Allow plain http://", NO_YES)
                .with_choice(yes_no(handle.allow_plain_http)),
            Field::text("methods", "Allowed methods")
                .with_text(&handle.allowed_methods.join(", "))
                .hint("comma-separated; empty allows any"),
        ]),
        SecretKind::Env | SecretKind::File => fields.push(
            Field::text("cmds", "Allowed commands")
                .with_text(&handle.allowed_cmds.join(", "))
                .hint("comma-separated; empty denies all"),
        ),
        SecretKind::Postgres | SecretKind::Redis => fields.push(
            Field::choice("read_only", "Read only", NO_YES).with_choice(yes_no(handle.read_only)),
        ),
    }
    fields.push(
        Field::text("grant_ttl", "Grant lasts")
            .with_text(&humantime::format_duration(handle.grant_ttl).to_string())
            .hint("how long allow for session lasts, e.g. 15m or 1h"),
    );
    Form::new(format!("Policy for {}", handle.name), fields)
}

/// The effect to send, or what is wrong with the form.
pub fn submit(purpose: &Purpose, form: &Form) -> Result<Effect, String> {
    match purpose {
        Purpose::Add => add(form),
        Purpose::Edit(handle) => update(handle, form),
        Purpose::Policy(handle) => policy(handle, form),
    }
}

/// The fields that make up a value, shown for the kinds they belong to.
fn value_fields() -> Vec<Field> {
    vec![
        Field::hidden("token", "Token").when("kind", &["http"]),
        Field::choice("placement", "Token goes in", &["header", "query"]).when("kind", &["http"]),
        Field::text("header", "Header name")
            .with_text("Authorization")
            .when("placement", &["header"]),
        Field::text("template", "Header value")
            .with_text("Bearer {}")
            .hint("{} is where the token goes")
            .when("placement", &["header"]),
        Field::text("param", "Query parameter").when("placement", &["query"]),
        Field::text("base_url", "Base URL")
            .hint("optional; agents then send only a path")
            .when("kind", &["http"]),
        Field::pairs("vars", "Variables")
            .hint("NAME=value, Enter adds")
            .when("kind", &["env"]),
        Field::hidden("url", "URL").when("kind", &["postgres", "redis"]),
    ]
}

/// Fills a value field with what is known about the handle; secrets stay
/// blank, and blank keeps them.
fn prefill(field: Field, handle: &HandleInfo) -> Field {
    match (field.key, &handle.auth) {
        ("token", _) => field.hint("blank keeps the current token"),
        ("url", _) => field.hint("blank keeps the current URL"),
        ("base_url", _) => field.hint("blank keeps the current one"),
        ("vars", _) => field.hint("NAME=value, Enter adds or changes one; the others stay"),
        ("placement", Some(AuthPlacement::Query { .. })) => field.with_choice("query"),
        ("header", Some(AuthPlacement::Header { name, .. })) => field.with_text(name),
        ("template", Some(AuthPlacement::Header { template, .. })) => field.with_text(template),
        ("param", Some(AuthPlacement::Query { param })) => field.with_text(param),
        _ => field,
    }
}

fn add(form: &Form) -> Result<Effect, String> {
    let name = form.text("name");
    if name.is_empty() {
        return Err("the name is required".into());
    }
    let kind = form.chosen("kind");
    let value = value(form, kind)?.ok_or_else(|| match kind {
        "http" => "the token is required".to_owned(),
        "env" => "add at least one variable: NAME=value, then Enter".to_owned(),
        _ => "the URL is required".to_owned(),
    })?;
    let policy = Policy {
        mode: parse_mode(form.chosen("mode")),
        allowed_hosts: shown_list(form, "hosts"),
        allowed_cmds: shown_list(form, "cmds"),
        ..Policy::default()
    };
    Ok(Effect::Add(Secret {
        name: name.to_owned(),
        description: form.text("description").to_owned(),
        value,
        policy,
        created_at: 0,
        updated_at: 0,
        from_share: None,
    }))
}

fn update(handle: &HandleInfo, form: &Form) -> Result<Effect, String> {
    let description = form.text("description");
    let description = (description != handle.description).then(|| description.to_owned());
    if handle.kind == SecretKind::Env {
        return edit_vars(handle, form, description);
    }
    let value = value(form, kind_name(handle.kind))?;
    if value.is_none() && handle.kind == SecretKind::Http {
        if !form.text("base_url").is_empty() {
            return Err("type the token again to change the base URL".into());
        }
        if Some(placement(form)) != handle.auth {
            return Err("type the token again to change where it goes".into());
        }
    }
    if description.is_none() && value.is_none() {
        return Err("nothing changed".into());
    }
    Ok(Effect::Update {
        name: handle.name.clone(),
        description,
        value,
    })
}

/// An `env` handle's edit: the variables typed are set over the ones it
/// has, the ones named under Remove go, and the rest keep their values
/// without being typed again.
fn edit_vars(
    handle: &HandleInfo,
    form: &Form,
    description: Option<String>,
) -> Result<Effect, String> {
    let field = form.field("vars");
    if !field.text.is_empty() {
        return Err("press Enter to add the variable you typed".into());
    }
    let set: BTreeMap<String, SecretText> = field.pairs.iter().cloned().collect();
    let remove = list(form.text("remove"));
    if let Some(unknown) = remove.iter().find(|name| !handle.env_vars.contains(name)) {
        return Err(format!("{} has no variable {unknown}", handle.name));
    }
    if set.is_empty() && remove.is_empty() {
        return match description {
            Some(description) => Ok(Effect::Update {
                name: handle.name.clone(),
                description: Some(description),
                value: None,
            }),
            None => Err("nothing changed".into()),
        };
    }
    Ok(Effect::EditVars {
        name: handle.name.clone(),
        description,
        set,
        remove,
    })
}

/// The value the form describes, or `None` if its secret part is blank.
fn value(form: &Form, kind: &str) -> Result<Option<SecretValue>, String> {
    Ok(match kind {
        "http" => {
            let token = form.field("token").text.as_str();
            if token.is_empty() {
                return Ok(None);
            }
            let base_url = form.text("base_url");
            Some(SecretValue::Http {
                token: SecretText::new(token),
                placement: placement(form),
                base_url: (!base_url.is_empty()).then(|| base_url.to_owned()),
            })
        }
        "env" => {
            let field = form.field("vars");
            if !field.text.is_empty() {
                return Err("press Enter to add the variable you typed".into());
            }
            if field.pairs.is_empty() {
                return Ok(None);
            }
            let vars: BTreeMap<String, SecretText> = field.pairs.iter().cloned().collect();
            Some(SecretValue::Env { vars })
        }
        _ => {
            let url = form.field("url").text.as_str();
            if url.is_empty() {
                return Ok(None);
            }
            let url = SecretText::new(url);
            Some(if kind == "redis" {
                SecretValue::Redis { url }
            } else {
                SecretValue::Postgres { url }
            })
        }
    })
}

fn placement(form: &Form) -> AuthPlacement {
    if form.chosen("placement") == "query" {
        AuthPlacement::Query {
            param: form.text("param").to_owned(),
        }
    } else {
        AuthPlacement::Header {
            name: form.text("header").to_owned(),
            template: form.text("template").to_owned(),
        }
    }
}

fn policy(handle: &HandleInfo, form: &Form) -> Result<Effect, String> {
    let grant_ttl: Duration = humantime::parse_duration(form.text("grant_ttl"))
        .map_err(|_| "the grant time must be a duration such as 15m or 1h".to_owned())?;
    let mut patch = PolicyPatch {
        mode: changed(parse_mode(form.chosen("mode")), handle.mode),
        grant_ttl: changed(grant_ttl, handle.grant_ttl),
        ..PolicyPatch::default()
    };
    if form.has("hosts") {
        patch.allowed_hosts = changed(list(form.text("hosts")), handle.allowed_hosts.clone());
        patch.allow_plain_http =
            changed(form.chosen("plain_http") == "yes", handle.allow_plain_http);
        let methods = list(form.text("methods"))
            .into_iter()
            .map(|m| m.to_uppercase())
            .collect();
        patch.allowed_methods = changed(methods, handle.allowed_methods.clone());
    }
    if form.has("cmds") {
        patch.allowed_cmds = changed(list(form.text("cmds")), handle.allowed_cmds.clone());
    }
    if form.has("read_only") {
        patch.read_only = changed(form.chosen("read_only") == "yes", handle.read_only);
    }
    if patch == PolicyPatch::default() {
        return Err("nothing changed".into());
    }
    Ok(Effect::SetPolicy {
        name: handle.name.clone(),
        patch,
    })
}

/// Only what the user can see counts: hosts typed before switching the
/// kind to env are not saved.
fn shown_list(form: &Form, key: &str) -> Vec<String> {
    if form.is_shown_key(key) {
        list(form.text(key))
    } else {
        Vec::new()
    }
}

fn changed<T: PartialEq>(new: T, old: T) -> Option<T> {
    (new != old).then_some(new)
}

fn list(text: &str) -> Vec<String> {
    text.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

fn kind_name(kind: SecretKind) -> &'static str {
    match kind {
        SecretKind::Http => "http",
        SecretKind::Env => "env",
        SecretKind::File => "file",
        SecretKind::Postgres => "postgres",
        SecretKind::Redis => "redis",
    }
}

fn mode_name(mode: Mode) -> &'static str {
    match mode {
        Mode::Ask => "ask",
        Mode::Auto => "auto",
        Mode::Deny => "deny",
    }
}

fn parse_mode(name: &str) -> Mode {
    match name {
        "auto" => Mode::Auto,
        "deny" => Mode::Deny,
        _ => Mode::Ask,
    }
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}
