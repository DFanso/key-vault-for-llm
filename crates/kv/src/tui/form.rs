//! Typing into a form in `kv tui`: what each key does. The form itself is
//! `kv::forms`, shared with the `kv tray` window.

use ratatui::crossterm::event::{KeyCode, KeyEvent};

pub use crate::forms::{Field, Form, Input, is_variable_name};
use crate::forms::{PAIR_HELP, parse_pair};

/// What a key did to the form.
pub enum Reply {
    Nothing,
    Cancel,
    Submit,
    Message(String),
}

impl Form {
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
}
