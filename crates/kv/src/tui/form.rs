//! A small form: text, hidden and choice fields, and a list of NAME=value
//! pairs, followed by a Save row.

use kv_core::secret::SecretText;
use ratatui::crossterm::event::{KeyCode, KeyEvent};
use zeroize::Zeroizing;

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
    when: Option<(&'static str, &'static [&'static str])>,
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

/// What a key did to the form.
pub enum Reply {
    Nothing,
    Cancel,
    Submit,
    Message(String),
}

pub struct Form {
    title: String,
    fields: Vec<Field>,
    /// `fields.len()` is the Save row.
    focus: usize,
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

    pub fn handle_key(&mut self, key: KeyEvent) -> Reply {
        match key.code {
            KeyCode::Esc => return Reply::Cancel,
            KeyCode::Tab | KeyCode::Down => self.move_focus(1),
            KeyCode::BackTab | KeyCode::Up => self.move_focus(-1),
            KeyCode::Enter if self.save_focused() => return Reply::Submit,
            // Without bracketed paste a pasted newline arrives as Enter;
            // moving on would send the rest of a secret into the next,
            // visible field. Tab moves on from a hidden field.
            KeyCode::Enter if matches!(self.fields[self.focus].input, Input::Hidden) => {
                return Reply::Nothing;
            }
            KeyCode::Enter => return self.enter(),
            _ => {}
        }
        let Some(field) = self.fields.get_mut(self.focus) else {
            return Reply::Nothing;
        };
        match (&field.input, key.code) {
            (Input::Choice(options), KeyCode::Right | KeyCode::Char(' ')) => {
                field.choice = (field.choice + 1) % options.len();
            }
            (Input::Choice(options), KeyCode::Left) => {
                field.choice = (field.choice + options.len() - 1) % options.len();
            }
            (Input::Choice(_), _) => {}
            (Input::Pairs, KeyCode::Backspace) if field.text.is_empty() => {
                field.pairs.pop();
            }
            (_, KeyCode::Backspace) => {
                field.text.pop();
            }
            (_, KeyCode::Char(c)) => field.text.push(c),
            _ => {}
        }
        Reply::Nothing
    }

    /// Pasted text goes into the focused field as one input: line breaks
    /// and surrounding spaces are dropped from text and hidden fields, and
    /// a pairs field takes one `NAME=value` per line. Nothing else takes a
    /// paste.
    pub fn paste(&mut self, text: &str) -> Reply {
        let Some(field) = self.fields.get_mut(self.focus) else {
            return Reply::Nothing;
        };
        match field.input {
            Input::Text | Input::Hidden => {
                let one_line: String = text.chars().filter(|c| !matches!(c, '\n' | '\r')).collect();
                field.text.push_str(one_line.trim());
                Reply::Nothing
            }
            Input::Pairs => {
                let mut pairs = Vec::new();
                for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
                    match parse_pair(line) {
                        Some(pair) => pairs.push(pair),
                        None => return Reply::Message(PAIR_HELP.into()),
                    }
                }
                for (name, value) in pairs {
                    field.pairs.retain(|(n, _)| *n != name);
                    field.pairs.push((name, value));
                }
                Reply::Nothing
            }
            Input::Choice(_) => Reply::Nothing,
        }
    }

    /// Enter adds a typed pair, or moves on.
    fn enter(&mut self) -> Reply {
        let field = &mut self.fields[self.focus];
        if matches!(field.input, Input::Pairs) && !field.text.is_empty() {
            let Some((name, value)) = parse_pair(&field.text) else {
                return Reply::Message(PAIR_HELP.into());
            };
            field.pairs.retain(|(n, _)| *n != name);
            field.pairs.push((name, value));
            field.text.clear();
            return Reply::Nothing;
        }
        self.move_focus(1);
        Reply::Nothing
    }

    fn is_shown(&self, index: usize) -> bool {
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
    fn move_focus(&mut self, step: isize) {
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

const PAIR_HELP: &str =
    "type a variable as NAME=value (letters, digits and _ in the name), then press Enter";

/// `NAME=value` with a variable name and a value, or `None`.
fn parse_pair(text: &str) -> Option<(String, SecretText)> {
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
