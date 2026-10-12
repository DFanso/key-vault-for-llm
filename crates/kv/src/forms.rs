//! The handle forms `kv tui` and the `kv tray` window share: their fields,
//! the effect each saves as (`handles`), and, for the window, a form as
//! data (`describe`) and the window's answers put back into it (`fill`).

mod handles;

use std::collections::BTreeMap;

use kv_core::secret::SecretText;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub use handles::{Purpose, edit_handle, edit_policy, new_handle, requested_handle, submit};

pub enum Input {
    Text,
    /// Typed like text, drawn as dots.
    Hidden,
    Choice(&'static [&'static str]),
    /// NAME=value pairs: Enter adds the typed pair; only names are drawn.
    Pairs,
}

pub struct Field {
    pub key: &'static str,
    pub label: &'static str,
    pub input: Input,
    pub text: Zeroizing<String>,
    pub choice: usize,
    pub pairs: Vec<(String, SecretText)>,
    /// Drawn dimmed after the field, e.g. what leaving it blank means.
    pub hint: String,
    /// Shown only while the choice field `.0` is set to one of `.1`.
    pub(crate) when: Option<(&'static str, &'static [&'static str])>,
}

impl Field {
    fn new(key: &'static str, label: &'static str, input: Input) -> Self {
        Self {
            key,
            label,
            input,
            text: Zeroizing::new(String::new()),
            choice: 0,
            pairs: Vec::new(),
            hint: String::new(),
            when: None,
        }
    }

    pub fn text(key: &'static str, label: &'static str) -> Self {
        Self::new(key, label, Input::Text)
    }

    pub fn hidden(key: &'static str, label: &'static str) -> Self {
        Self::new(key, label, Input::Hidden)
    }

    pub fn choice(
        key: &'static str,
        label: &'static str,
        options: &'static [&'static str],
    ) -> Self {
        Self::new(key, label, Input::Choice(options))
    }

    pub fn pairs(key: &'static str, label: &'static str) -> Self {
        Self::new(key, label, Input::Pairs)
    }

    pub fn with_text(mut self, text: &str) -> Self {
        self.text = Zeroizing::new(text.to_owned());
        self
    }

    pub fn with_choice(mut self, option: &str) -> Self {
        self.set_choice(option);
        self
    }

    /// Selects `option` in a choice field, or the first one if it has no
    /// such option.
    pub fn set_choice(&mut self, option: &str) {
        if let Input::Choice(options) = self.input {
            self.choice = options.iter().position(|o| *o == option).unwrap_or(0);
        }
    }

    pub fn hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = hint.into();
        self
    }

    pub fn when(mut self, key: &'static str, options: &'static [&'static str]) -> Self {
        self.when = Some((key, options));
        self
    }

    pub fn depends_on(&self) -> Option<(&'static str, &'static [&'static str])> {
        self.when
    }

    pub fn without_condition(mut self) -> Self {
        self.when = None;
        self
    }

    /// The selected option of a choice field.
    pub fn chosen(&self) -> &'static str {
        match self.input {
            Input::Choice(options) => options[self.choice],
            _ => "",
        }
    }
}

pub struct Form {
    title: String,
    pub(crate) fields: Vec<Field>,
    /// `fields.len()` is the Save row.
    pub(crate) focus: usize,
}

impl Form {
    pub fn new(title: impl Into<String>, fields: Vec<Field>) -> Self {
        let mut form = Self {
            title: title.into(),
            fields,
            focus: 0,
        };
        if !form.is_shown(0) {
            form.move_focus(1);
        }
        form
    }

    pub fn title(&self) -> &str {
        &self.title
    }

    /// The key of the focused field, or `None` on the Save row.
    pub fn focused(&self) -> Option<&str> {
        self.fields.get(self.focus).map(|f| f.key)
    }

    /// The fields on screen, with whether each has the focus.
    pub fn shown(&self) -> impl Iterator<Item = (&Field, bool)> {
        self.fields
            .iter()
            .enumerate()
            .filter(|(i, _)| self.is_shown(*i))
            .map(|(i, f)| (f, i == self.focus))
    }

    pub fn save_focused(&self) -> bool {
        self.focus == self.fields.len()
    }

    pub fn field(&self, key: &str) -> &Field {
        self.fields
            .iter()
            .find(|f| f.key == key)
            .unwrap_or_else(|| panic!("the form has no field {key}"))
    }

    pub fn field_mut(&mut self, key: &str) -> &mut Field {
        self.fields
            .iter_mut()
            .find(|f| f.key == key)
            .unwrap_or_else(|| panic!("the form has no field {key}"))
    }

    /// Puts the focus on a field, if it is shown.
    pub fn focus_on(&mut self, key: &str) {
        if let Some(index) = self.fields.iter().position(|f| f.key == key)
            && self.is_shown(index)
        {
            self.focus = index;
        }
    }

    pub fn has(&self, key: &str) -> bool {
        self.fields.iter().any(|f| f.key == key)
    }

    /// The trimmed text of a field, or "" if the form has no such field.
    pub fn text(&self, key: &str) -> &str {
        self.fields
            .iter()
            .find(|f| f.key == key)
            .map_or("", |f| f.text.trim())
    }

    pub fn chosen(&self, key: &str) -> &'static str {
        self.field(key).chosen()
    }

    pub fn is_shown_key(&self, key: &str) -> bool {
        self.fields
            .iter()
            .position(|f| f.key == key)
            .is_some_and(|i| self.is_shown(i))
    }

    pub(crate) fn is_shown(&self, index: usize) -> bool {
        let Some(field) = self.fields.get(index) else {
            return true;
        };
        let Some((key, options)) = field.when else {
            return true;
        };
        self.fields
            .iter()
            .position(|f| f.key == key)
            .is_some_and(|i| self.is_shown(i) && options.contains(&self.fields[i].chosen()))
    }

    /// Steps to the next or previous shown row, wrapping past Save.
    pub(crate) fn move_focus(&mut self, step: isize) {
        let rows = self.fields.len() + 1;
        let mut next = self.focus;
        for _ in 0..rows {
            next = (next as isize + step).rem_euclid(rows as isize) as usize;
            if self.is_shown(next) {
                break;
            }
        }
        self.focus = next;
    }
}

pub(crate) const PAIR_HELP: &str =
    "type a variable as NAME=value (letters, digits and _ in the name), then press Enter";

/// `NAME=value` with a variable name and a value, or `None`.
pub(crate) fn parse_pair(text: &str) -> Option<(String, SecretText)> {
    let (name, value) = text.split_once('=')?;
    let name = name.trim();
    (is_variable_name(name) && !value.is_empty()).then(|| (name.to_owned(), SecretText::new(value)))
}

/// Letters, digits and `_`, not starting with a digit: what shells accept,
/// and what the TUI is willing to draw before the value.
pub fn is_variable_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// A form as the `kv tray` window draws it. Secret fields carry no text.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FormView {
    pub title: String,
    pub fields: Vec<FieldView>,
    /// The field to put the cursor in.
    pub focus: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldView {
    pub key: String,
    pub label: String,
    pub kind: FieldKind,
    /// A choice field's options.
    pub options: Vec<String>,
    /// The text of a text field or the option of a choice field; empty for
    /// secrets and variables.
    pub value: String,
    pub hint: String,
    /// Shown only while each of these choice fields has one of its options:
    /// the field this one depends on, then the one that depends on, and so
    /// on, so a field is hidden along with the field it hangs from.
    pub when: Vec<When>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldKind {
    Text,
    Secret,
    Choice,
    /// `NAME=value` lines.
    Pairs,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct When {
    pub key: String,
    pub options: Vec<String>,
}

pub fn describe(form: &Form) -> FormView {
    FormView {
        title: form.title().to_owned(),
        focus: form.focused().map(str::to_owned),
        fields: form
            .fields
            .iter()
            .map(|field| {
                let (kind, options, value) = match field.input {
                    Input::Text => (FieldKind::Text, Vec::new(), field.text.to_string()),
                    Input::Hidden => (FieldKind::Secret, Vec::new(), String::new()),
                    Input::Pairs => (FieldKind::Pairs, Vec::new(), String::new()),
                    Input::Choice(options) => (
                        FieldKind::Choice,
                        options.iter().map(|o| (*o).to_owned()).collect(),
                        field.chosen().to_owned(),
                    ),
                };
                FieldView {
                    key: field.key.to_owned(),
                    label: field.label.to_owned(),
                    kind,
                    options,
                    value,
                    hint: field.hint.clone(),
                    when: conditions(form, field),
                }
            })
            .collect(),
    }
}

/// What must hold for `field` to be shown, nearest first; the same chain
/// `Form::is_shown` follows.
fn conditions(form: &Form, field: &Field) -> Vec<When> {
    let mut when = Vec::new();
    let mut next = field.when;
    // Each step moves to another field, so a chain is never longer than
    // the form.
    while let Some((key, options)) = next {
        if when.len() == form.fields.len() {
            break;
        }
        when.push(When {
            key: key.to_owned(),
            options: options.iter().map(|o| (*o).to_owned()).collect(),
        });
        next = form
            .fields
            .iter()
            .find(|f| f.key == key)
            .and_then(|f| f.when);
    }
    when
}

/// Puts what the window sent into `form`: text as typed, a choice by its
/// option, and variables one `NAME=value` per line, replacing the ones the
/// form had. Keys the form does not have are ignored. On an error the form
/// is left as it was.
pub fn fill(form: &mut Form, values: &BTreeMap<String, SecretText>) -> Result<(), String> {
    let mut updates = Vec::new();
    for (key, value) in values {
        let Some(index) = form.fields.iter().position(|f| f.key == key) else {
            continue;
        };
        let field = &form.fields[index];
        let update = match field.input {
            Input::Text | Input::Hidden => Update::Text(Zeroizing::new(value.expose().to_owned())),
            Input::Choice(options) => {
                let choice = options
                    .iter()
                    .position(|o| *o == value.expose())
                    .ok_or_else(|| {
                        format!("{}: choose one of {}", field.label, options.join(", "))
                    })?;
                Update::Choice(choice)
            }
            Input::Pairs => {
                let mut pairs: Vec<(String, SecretText)> = Vec::new();
                for line in value
                    .expose()
                    .lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty())
                {
                    let (name, value) = parse_pair(line)
                        .ok_or_else(|| format!("{}: one NAME=value per line", field.label))?;
                    pairs.retain(|(n, _)| *n != name);
                    pairs.push((name, value));
                }
                Update::Pairs(pairs)
            }
        };
        updates.push((index, update));
    }
    for (index, update) in updates {
        let field = &mut form.fields[index];
        match update {
            Update::Text(text) => field.text = text,
            Update::Choice(choice) => field.choice = choice,
            Update::Pairs(pairs) => {
                field.text = Zeroizing::new(String::new());
                field.pairs = pairs;
            }
        }
    }
    Ok(())
}

enum Update {
    Text(Zeroizing<String>),
    Choice(usize),
    Pairs(Vec<(String, SecretText)>),
}
