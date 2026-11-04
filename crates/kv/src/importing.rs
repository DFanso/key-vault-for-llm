//! Turning a `.env` or JSON settings file into one `env` handle, the same
//! way for `kv import` and kv's window: which variables start ticked, what
//! the handle is called, and what the user is told. The file is read by
//! `kv_core::import`; the handle is saved through the ordinary Add.

use std::collections::BTreeMap;

use kv_core::envvars;
use kv_core::import::{Format, Imported};
use kv_core::policy::Policy;
use kv_core::secret::{Secret, SecretText, SecretValue, validate_handle};

/// What the user is told about a settings file before saving it. Until
/// kv can show a code for a share's contents, a forged settings file sent
/// by someone else could point an app at their server.
pub const JSON_NOTE: &str = "don't share a handle made from a settings file such as \
     appsettings.json yet: kv cannot yet show a code for what a share holds, so a forged one \
     could point your app at someone else's server";

/// A handle name made from the file's name: `.env` gives `env`,
/// `appsettings.Production.json` gives `appsettings-production`.
pub fn suggested_name(file_name: &str) -> String {
    let base = file_name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(file_name)
        .trim_start_matches('.');
    let base = base
        .strip_suffix(".json")
        .or_else(|| base.strip_suffix(".JSON"))
        .unwrap_or(base);
    let mut name = String::new();
    for c in base.chars() {
        let c = c.to_ascii_lowercase();
        if c.is_ascii_alphanumeric() || c == '_' {
            name.push(c);
        } else if !name.ends_with('-') {
            name.push('-');
        }
    }
    let name: String = name.trim_matches('-').chars().take(63).collect();
    let name = name.trim_end_matches('-').to_owned();
    if validate_handle(&name).is_ok() {
        name
    } else {
        "imported".into()
    }
}

/// The variables ticked at first: all but the ones that change how a
/// program runs or where it connects, which the user ticks on purpose.
pub fn default_keep(imported: &Imported) -> Vec<String> {
    imported
        .vars
        .iter()
        .map(|(name, _)| name)
        .filter(|name| !envvars::is_risky(name))
        .cloned()
        .collect()
}

/// What to tell the user about `imported`: the parser's notes, the names
/// left unticked, and the note for settings files.
pub fn notes(imported: &Imported) -> Vec<String> {
    let mut notes = imported.notes.clone();
    let risky = envvars::risky(imported.vars.iter().map(|(name, _)| name));
    if !risky.is_empty() {
        notes.push(format!(
            "{} change how a program runs or where it connects, so they start unticked",
            envvars::list(&risky)
        ));
    }
    if imported.format == Format::Json {
        notes.push(JSON_NOTE.into());
    }
    notes
}

/// The handle to add: the kept variables, in ask mode unless `policy`
/// says otherwise.
pub fn secret(
    name: &str,
    description: &str,
    vars: BTreeMap<String, SecretText>,
    policy: Policy,
) -> Secret {
    Secret {
        name: name.to_owned(),
        description: description.to_owned(),
        value: SecretValue::Env { vars },
        policy,
        created_at: 0,
        updated_at: 0,
        from_share: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kv_core::import;

    #[test]
    fn names_come_from_the_file_name() {
        assert_eq!(suggested_name(".env"), "env");
        assert_eq!(suggested_name("/srv/app/.env.local"), "env-local");
        assert_eq!(
            suggested_name("C:\\app\\appsettings.Production.json"),
            "appsettings-production"
        );
        assert_eq!(suggested_name("..."), "imported");
    }

    #[test]
    fn risky_variables_start_unticked_and_settings_files_get_the_note() {
        let imported =
            import::parse(Format::Env, b"API_KEY=sk-test-0123\nNODE_OPTIONS=--x\n").unwrap();
        assert_eq!(default_keep(&imported), ["API_KEY"]);
        assert!(notes(&imported)[0].contains("NODE_OPTIONS"));
        let json = import::parse(Format::Json, br#"{"A": "1"}"#).unwrap();
        assert!(notes(&json).iter().any(|n| n == JSON_NOTE));
    }
}
