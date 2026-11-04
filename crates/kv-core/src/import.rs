//! Reads a `.env` file or a JSON settings file (such as .NET's
//! `appsettings.json`) into the variables of one `env` handle.
//!
//! Nothing here touches the disk: callers pass the file's bytes. Values are
//! kept as `SecretText`; notes and errors name variables and line numbers,
//! never values.
//!
//! JSON is flattened the way .NET reads settings from the environment:
//! `{"Logging": {"LogLevel": {"Default": "Warning"}}}` becomes
//! `Logging__LogLevel__Default`, array items take their index, numbers and
//! booleans become text, and `null` is left out. That is a view for a program
//! that reads its settings from the environment; it does not rebuild the file.

use std::collections::BTreeMap;
use std::fmt;

use crate::envvars::{self, MAX_ENV_VARS};
use crate::secret::SecretText;

/// The largest file kv imports, in bytes.
pub const MAX_FILE_LEN: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    /// `NAME=value` lines.
    Env,
    /// A JSON object, flattened with `__`.
    Json,
}

impl Format {
    /// JSON for a `.json` file or text that starts with `{`, else `.env`.
    pub fn guess(file_name: &str, text: &str) -> Format {
        let json_name = file_name.to_ascii_lowercase().ends_with(".json");
        let json_text = text
            .trim_start_matches('\u{feff}')
            .trim_start()
            .starts_with('{');
        if json_name || json_text {
            Format::Json
        } else {
            Format::Env
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Format::Env => ".env",
            Format::Json => "JSON",
        }
    }
}

/// What a file holds, in the order it gives it.
pub struct Imported {
    pub format: Format,
    pub vars: Vec<(String, SecretText)>,
    /// What was left out or changed, for the user: names and line numbers,
    /// never values.
    pub notes: Vec<String>,
}

impl fmt::Debug for Imported {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Imported")
            .field("format", &self.format)
            .field("vars", &self.names())
            .field("notes", &self.notes)
            .finish()
    }
}

impl Imported {
    pub fn names(&self) -> Vec<&str> {
        self.vars.iter().map(|(name, _)| name.as_str()).collect()
    }

    /// The variables named in `keep`, as an `env` handle's value holds them.
    pub fn keep(&self, keep: &[String]) -> BTreeMap<String, SecretText> {
        self.vars
            .iter()
            .filter(|(name, _)| keep.contains(name))
            .cloned()
            .collect()
    }
}

/// Why a file cannot be imported. Never holds a value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportError(pub String);

impl fmt::Display for ImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ImportError {}

fn fail<T>(message: impl Into<String>) -> Result<T, ImportError> {
    Err(ImportError(message.into()))
}

/// Reads `bytes` as `format`.
pub fn parse(format: Format, bytes: &[u8]) -> Result<Imported, ImportError> {
    if bytes.len() > MAX_FILE_LEN {
        return fail("the file is larger than 64 KiB, which kv does not import");
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return fail("the file is not UTF-8 text");
    };
    let text = text.trim_start_matches('\u{feff}');
    let imported = match format {
        Format::Env => parse_env(text)?,
        Format::Json => parse_json(text)?,
    };
    if imported.vars.is_empty() {
        return fail("the file holds no variables kv can import");
    }
    if imported.vars.len() > MAX_ENV_VARS {
        return fail(format!(
            "the file holds {} variables; an env handle holds at most 256",
            imported.vars.len()
        ));
    }
    Ok(imported)
}

/// Collects variables, keeping the last of a name given twice.
#[derive(Default)]
struct Vars {
    vars: Vec<(String, SecretText)>,
    notes: Vec<String>,
}

impl Vars {
    fn set(&mut self, name: String, value: String) {
        let value = SecretText::new(value);
        match self.vars.iter_mut().find(|(n, _)| *n == name) {
            Some(slot) => {
                let note = format!("{name} is set more than once; the last one is kept");
                if !self.notes.contains(&note) {
                    self.notes.push(note);
                }
                slot.1 = value;
            }
            None => self.vars.push((name, value)),
        }
    }
}

fn parse_env(text: &str) -> Result<Imported, ImportError> {
    let text = text.replace("\r\n", "\n");
    let lines: Vec<&str> = text.split('\n').collect();
    let mut out = Vars::default();
    let mut index = 0;
    while index < lines.len() {
        let number = index + 1;
        let line = lines[index].trim_start();
        index += 1;
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = match line.strip_prefix("export") {
            Some(rest) if rest.starts_with([' ', '\t']) => rest.trim_start(),
            _ => line,
        };
        let Some(eq) = line.find('=') else {
            out.notes
                .push(format!("line {number} has no = and was left out"));
            continue;
        };
        let name = line[..eq].trim();
        let rest = line[eq + 1..].trim_start_matches([' ', '\t']);
        if let Some(problem) = envvars::name_problem(name) {
            out.notes
                .push(format!("line {number} was left out: {problem}"));
            // A quoted value may run over the next lines; skip them too.
            if let Some(quote @ ('"' | '\'')) = rest.chars().next() {
                index = skip_quoted(&lines, index, &rest[1..], quote);
            }
            continue;
        }
        let value = match rest.chars().next() {
            Some('\'') => {
                let (value, next) = quoted(&lines, index, &rest[1..], '\'', number)?;
                index = next;
                value
            }
            Some('"') => {
                let (raw, next) = quoted(&lines, index, &rest[1..], '"', number)?;
                index = next;
                unescape(&raw)
            }
            _ => unquoted(rest),
        };
        if rest.starts_with('\'') {
            // Single quotes keep `$` as it is, as shells do.
        } else if looks_interpolated(&value) {
            out.notes.push(format!(
                "{name} looks like it refers to another variable ($...); kv keeps it as written"
            ));
        }
        out.set(name.to_owned(), value);
    }
    Ok(Imported {
        format: Format::Env,
        vars: out.vars,
        notes: out.notes,
    })
}

/// The text of a value in `quote`s that starts with `first` (the rest of
/// the line after the opening quote) and may run over the lines from
/// `next` on, and the index of the line after it. Escaped quotes do not
/// close a double-quoted value.
fn quoted(
    lines: &[&str],
    mut next: usize,
    first: &str,
    quote: char,
    number: usize,
) -> Result<(String, usize), ImportError> {
    let mut text = String::new();
    let mut part = first;
    loop {
        if let Some(end) = closing(part, quote) {
            text.push_str(&part[..end]);
            return Ok((text, next));
        }
        text.push_str(part);
        let Some(line) = lines.get(next) else {
            return fail(format!("the quote on line {number} is never closed"));
        };
        text.push('\n');
        part = line;
        next += 1;
    }
}

/// Like `quoted`, for a line that is left out: where the value ends.
fn skip_quoted(lines: &[&str], next: usize, first: &str, quote: char) -> usize {
    quoted(lines, next, first, quote, 0).map_or(lines.len(), |(_, next)| next)
}

/// Where `quote` closes the value in `part`, if it does.
fn closing(part: &str, quote: char) -> Option<usize> {
    let mut escaped = false;
    for (at, c) in part.char_indices() {
        if quote == '"' && escaped {
            escaped = false;
            continue;
        }
        if quote == '"' && c == '\\' {
            escaped = true;
            continue;
        }
        if c == quote {
            return Some(at);
        }
    }
    None
}

/// The escapes a double-quoted `.env` value may hold.
fn unescape(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some(other @ ('"' | '\\' | '$' | '\'')) => out.push(other),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

/// An unquoted value: up to a ` #` comment, without trailing space.
fn unquoted(rest: &str) -> String {
    let end = rest
        .char_indices()
        .find(|&(at, c)| c == '#' && at > 0 && rest[..at].ends_with([' ', '\t']))
        .map_or(rest.len(), |(at, _)| at);
    rest[..end].trim_end().to_owned()
}

fn looks_interpolated(value: &str) -> bool {
    value.match_indices('$').any(|(at, _)| {
        value[at + 1..]
            .chars()
            .next()
            .is_some_and(|c| c == '{' || c == '_' || c.is_ascii_alphabetic())
    })
}

fn parse_json(text: &str) -> Result<Imported, ImportError> {
    let value: serde_json::Value = match serde_json::from_str(text) {
        Ok(value) => value,
        Err(e) => {
            return fail(format!(
                "the file is not valid JSON (line {}, column {})",
                e.line(),
                e.column()
            ));
        }
    };
    let serde_json::Value::Object(map) = value else {
        return fail("the file's JSON is not an object of settings");
    };
    let mut out = Vars::default();
    let mut nulls = 0;
    for (key, value) in map {
        flatten(key, value, &mut out, &mut nulls);
    }
    if nulls > 0 {
        out.notes
            .push(format!("{nulls} null setting(s) were left out"));
    }
    // .NET reads settings without regard to case, and `A__B` is the same
    // setting as `{"A": {"B": ...}}`: two that end up with one name would
    // silently lose one.
    let mut seen: BTreeMap<String, &str> = BTreeMap::new();
    let mut clashes = Vec::new();
    for (name, _) in &out.vars {
        if let Some(other) = seen.insert(name.to_ascii_uppercase(), name) {
            clashes.push(format!("{other} and {name}"));
        }
    }
    if !clashes.is_empty() {
        return fail(format!(
            "settings in the file would set the same variable: {}",
            clashes.join("; ")
        ));
    }
    Ok(Imported {
        format: Format::Json,
        vars: out.vars,
        notes: out.notes,
    })
}

fn flatten(name: String, value: serde_json::Value, out: &mut Vars, nulls: &mut usize) {
    use serde_json::Value;
    let text = match value {
        Value::Object(map) => {
            for (key, value) in map {
                flatten(format!("{name}__{key}"), value, out, nulls);
            }
            return;
        }
        Value::Array(items) => {
            for (at, value) in items.into_iter().enumerate() {
                flatten(format!("{name}__{at}"), value, out, nulls);
            }
            return;
        }
        Value::Null => {
            *nulls += 1;
            return;
        }
        Value::String(text) => text,
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
    };
    if let Some(problem) = envvars::name_problem(&name) {
        out.notes.push(format!("a setting was left out: {problem}"));
        return;
    }
    if out.vars.iter().any(|(n, _)| *n == name) {
        // Only `A__B` next to `{"A": {"B"}}` can do this; caught as a clash.
        out.vars.push((name, SecretText::new(text)));
        return;
    }
    out.set(name, text);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(text: &str) -> Imported {
        parse(Format::Env, text.as_bytes()).unwrap()
    }

    fn values(imported: &Imported) -> Vec<(&str, &str)> {
        imported
            .vars
            .iter()
            .map(|(n, v)| (n.as_str(), v.expose()))
            .collect()
    }

    #[test]
    fn a_dotenv_file_reads_as_shells_and_dotenv_libraries_do() {
        let file = "\u{feff}# settings\r\n\
                    export API_KEY=sk-test-0123456789\r\n\
                    PLAIN = spaced value   # a comment\n\
                    HASH=abc#def\n\
                    SINGLE='literal $HOME \\n'\n\
                    DOUBLE=\"line one\\nline \\\"two\\\"\"\n\
                    MULTI=\"first\n\
                    second\"\n\
                    EMPTY=\n\
                    \n";
        let imported = env(file);
        assert_eq!(
            values(&imported),
            [
                ("API_KEY", "sk-test-0123456789"),
                ("PLAIN", "spaced value"),
                ("HASH", "abc#def"),
                ("SINGLE", "literal $HOME \\n"),
                ("DOUBLE", "line one\nline \"two\""),
                ("MULTI", "first\nsecond"),
                ("EMPTY", ""),
            ]
        );
        assert!(imported.notes.is_empty(), "{:?}", imported.notes);
    }

    #[test]
    fn duplicates_keep_the_last_and_bad_lines_are_noted_without_values() {
        let imported = env("A=one\nnot a line\n1BAD=secret-value-1\nA=two\nB=\"x\"\n");
        assert_eq!(values(&imported), [("A", "two"), ("B", "x")]);
        let notes = imported.notes.join(" | ");
        assert!(notes.contains("line 2 has no ="), "{notes}");
        assert!(notes.contains("line 3 was left out"), "{notes}");
        assert!(notes.contains("A is set more than once"), "{notes}");
        assert!(!notes.contains("secret-value-1"), "{notes}");
    }

    #[test]
    fn an_unclosed_quote_is_an_error() {
        let err = parse(Format::Env, b"A=\"never closed\nB=2\n").unwrap_err();
        assert!(err.0.contains("line 1"), "{err}");
        assert!(!err.0.contains("never closed\n"), "{err}");
    }

    #[test]
    fn references_to_other_variables_are_kept_as_written_with_a_note() {
        let imported = env("URL=postgres://${USER}@db\nPRICE='$5'\n");
        assert_eq!(imported.vars[0].1.expose(), "postgres://${USER}@db");
        assert_eq!(imported.notes.len(), 1, "{:?}", imported.notes);
        assert!(imported.notes[0].starts_with("URL"));
    }

    #[test]
    fn json_settings_flatten_the_way_dotnet_reads_the_environment() {
        let json = r#"{
            "ConnectionStrings": {"Default": "Server=db.example.test;Database=demo"},
            "Logging": {"LogLevel": {"Default": "Warning", "Microsoft.AspNetCore": "Warning"}},
            "Servers": [{"Host": "a"}, {"Host": "b"}],
            "Retries": 3,
            "Enabled": true,
            "Unset": null
        }"#;
        let imported = parse(Format::Json, json.as_bytes()).unwrap();
        assert_eq!(
            values(&imported),
            [
                (
                    "ConnectionStrings__Default",
                    "Server=db.example.test;Database=demo"
                ),
                ("Enabled", "true"),
                ("Logging__LogLevel__Default", "Warning"),
                ("Retries", "3"),
                ("Servers__0__Host", "a"),
                ("Servers__1__Host", "b"),
            ]
        );
        let notes = imported.notes.join(" | ");
        assert!(
            notes.contains("Logging__LogLevel__Microsoft?AspNetCore"),
            "{notes}"
        );
        assert!(notes.contains("1 null"), "{notes}");
    }

    #[test]
    fn json_settings_that_would_set_the_same_variable_are_refused() {
        for json in [
            r#"{"A__B": "1", "A": {"B": "2"}}"#,
            r#"{"Key": "1", "key": "2"}"#,
        ] {
            let err = parse(Format::Json, json.as_bytes()).unwrap_err();
            assert!(err.0.contains("same variable"), "{err}");
            assert!(!err.0.contains('1') || err.0.contains("A__B"), "{err}");
        }
    }

    #[test]
    fn what_is_not_a_settings_file_is_refused() {
        assert!(parse(Format::Json, b"[1, 2]").is_err());
        assert!(parse(Format::Json, b"{not json").is_err());
        assert!(parse(Format::Env, b"# only comments\n").is_err());
        assert!(parse(Format::Env, &[0xff, 0xfe, 0x00]).is_err());
        let big = "A=".to_owned() + &"x".repeat(MAX_FILE_LEN);
        assert!(parse(Format::Env, big.as_bytes()).is_err());
        let many: String = (0..257).map(|i| format!("V{i}=x\n")).collect();
        assert!(
            parse(Format::Env, many.as_bytes())
                .unwrap_err()
                .0
                .contains("256")
        );
    }

    #[test]
    fn the_format_is_guessed_from_the_name_or_the_text() {
        assert_eq!(Format::guess("appsettings.json", ""), Format::Json);
        assert_eq!(Format::guess("settings", "  {\"a\": 1}"), Format::Json);
        assert_eq!(Format::guess(".env.local", "A=1"), Format::Env);
    }

    #[test]
    fn keep_takes_only_the_ticked_variables() {
        let imported = env("A=1\nB=2\nC=3\n");
        let kept = imported.keep(&["A".into(), "C".into()]);
        assert_eq!(kept.keys().collect::<Vec<_>>(), ["A", "C"]);
        assert!(!format!("{imported:?}").contains('2'));
    }
}
