//! Draws `App`. Everything here reads state; nothing changes it.

use std::time::Duration;

use kv_core::policy::Mode;
use kv_core::proto::{Approval, Overview, RequestedHandle};
use kv_core::secret::HandleInfo;
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Clear, Paragraph, Wrap};

use super::app::{App, Screen, Tab};
use super::form::{Field, Form, Input, is_variable_name};
use crate::audit::Entry;

pub fn draw(frame: &mut Frame, app: &App) {
    match app.screen() {
        Screen::Unlock => draw_unlock(frame, app),
        Screen::Main => draw_main(frame, app),
    }
}

fn draw_unlock(frame: &mut Frame, app: &App) {
    let [_, middle, _] = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(7),
        Constraint::Fill(1),
    ])
    .areas(frame.area());
    let [_, area, _] = Layout::horizontal([
        Constraint::Fill(1),
        Constraint::Length(60),
        Constraint::Fill(1),
    ])
    .areas(middle);
    let mut lines = vec![
        Line::from(vec![
            Span::raw("Passphrase: "),
            Span::raw("•".repeat(app.passphrase_len())),
        ]),
        Line::raw(""),
    ];
    if let Some(message) = app.message() {
        lines.push(Line::styled(
            message.to_owned(),
            Style::new().fg(Color::Yellow),
        ));
    }
    lines.push(Line::styled("Enter unlock · Esc quit", dim()));
    let block = Block::bordered().title(" kv: unlock ");
    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_main(frame: &mut Frame, app: &App) {
    let [header, tabs, body, footer, message] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Fill(1),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(frame.area());
    frame.render_widget(Paragraph::new(status_line(app.overview())), header);
    frame.render_widget(Paragraph::new(tab_line(app)), tabs);
    match app.tab() {
        Tab::Approvals => draw_approvals(frame, app, body),
        Tab::Handles => draw_handles(frame, app, body),
        Tab::Audit => draw_audit(frame, app.audit(), body),
    }
    if let Some(form) = app.form() {
        draw_form(frame, form, body);
    }
    let footer_line = match app.removing() {
        Some(name) => Line::styled(
            format!("Remove {name}? y removes it, any other key keeps it"),
            Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        ),
        None => Line::styled(key_hints(app), dim()),
    };
    frame.render_widget(Paragraph::new(footer_line), footer);
    if let Some(text) = app.message() {
        frame.render_widget(
            Paragraph::new(Line::styled(
                text.to_owned(),
                Style::new().fg(Color::Yellow),
            )),
            message,
        );
    }
}

fn status_line(overview: Option<&Overview>) -> Line<'static> {
    let Some(overview) = overview else {
        return Line::raw("kv · loading…");
    };
    let status = &overview.status;
    let count = status.handle_count.unwrap_or(0);
    let mut text = format!(
        "kv · unlocked · {count} handle{}",
        if count == 1 { "" } else { "s" }
    );
    if let Some(secs) = status.locks_in_secs {
        let rounded = Duration::from_secs(secs / 60 * 60);
        text.push_str(&format!(
            " · locks after {} unused",
            humantime::format_duration(rounded)
        ));
    }
    let mut spans = vec![Span::raw(text)];
    if status.pending_approvals > 0 {
        spans.push(Span::styled(
            format!(" · {} waiting", status.pending_approvals),
            Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        ));
    }
    if !overview.handle_requests.is_empty() {
        spans.push(Span::styled(
            format!(" · {} requested", overview.handle_requests.len()),
            Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        ));
    }
    Line::from(spans)
}

fn tab_line(app: &App) -> Line<'static> {
    let waiting = app.overview().map_or(0, |o| o.approvals.len());
    let requested = app.overview().map_or(0, |o| o.handle_requests.len());
    let handles = if requested > 0 {
        format!("2 Handles ({requested} requested)")
    } else {
        "2 Handles".into()
    };
    let tab = |label: String, active: bool| {
        let style = if active {
            Style::new().add_modifier(Modifier::REVERSED)
        } else {
            Style::new()
        };
        Span::styled(format!(" {label} "), style)
    };
    Line::from(vec![
        tab(
            format!("1 Approvals ({waiting})"),
            app.tab() == Tab::Approvals,
        ),
        Span::raw(" "),
        tab(handles, app.tab() == Tab::Handles),
        Span::raw(" "),
        tab("3 Audit".into(), app.tab() == Tab::Audit),
    ])
}

fn draw_approvals(frame: &mut Frame, app: &App, area: Rect) {
    let approvals = app.overview().map_or(&[][..], |o| &o.approvals[..]);
    let block = Block::bordered().title(" Waiting for approval ");
    if approvals.is_empty() {
        let text = Line::styled("Nothing is waiting for approval.", dim());
        frame.render_widget(Paragraph::new(text).block(block), area);
        return;
    }
    let cards: Vec<Vec<Line>> = approvals
        .iter()
        .map(|approval| {
            let mut lines = approval_lines(approval, Some(approval.id) == app.selected());
            lines.push(Line::raw(""));
            lines
        })
        .collect();
    // Skip whole cards from the top until the selected one fits, so it is
    // never decided while off screen.
    let width = area.width.saturating_sub(2).max(1) as usize;
    let height = area.height.saturating_sub(2) as usize;
    let rows = |card: &Vec<Line>| -> usize {
        card.iter()
            .map(|line| line.width().div_ceil(width).max(1))
            .sum()
    };
    let selected = approvals
        .iter()
        .position(|a| Some(a.id) == app.selected())
        .unwrap_or(0);
    let mut skip = 0;
    while skip < selected && 1 + cards[skip..=selected].iter().map(rows).sum::<usize>() > height {
        skip += 1;
    }
    let mut text = Text::default();
    if skip > 0 {
        text.push_line(Line::styled(format!("↑ {skip} more"), dim()));
    }
    for card in cards.into_iter().skip(skip) {
        text.extend(card);
    }
    frame.render_widget(
        Paragraph::new(text).block(block).wrap(Wrap { trim: false }),
        area,
    );
}

fn approval_lines(approval: &Approval, selected: bool) -> Vec<Line<'static>> {
    let marker = if selected { "▶ " } else { "  " };
    let client = approval.client.as_deref().map_or_else(
        || "an agent with no session".to_owned(),
        |client| format!("{client} (self-reported)"),
    );
    let style = if selected {
        Style::new().add_modifier(Modifier::BOLD)
    } else {
        Style::new()
    };
    let mut lines = vec![
        Line::styled(
            format!(
                "{marker}#{} {client} · {} · {}",
                approval.id,
                approval.tool,
                approval.handles.join(", ")
            ),
            style,
        ),
        Line::raw(format!("    {}", approval.detail)),
    ];
    if let Some(cwd) = &approval.cwd {
        lines.push(Line::raw(format!("    in {cwd}")));
    }
    lines.push(Line::styled(
        format!("    answer within {}s", approval.expires_in_secs),
        dim(),
    ));
    lines
}

fn draw_handles(frame: &mut Frame, app: &App, area: Rect) {
    let (requests, handles) = app.overview().map_or((&[][..], &[][..]), |o| {
        (&o.handle_requests[..], &o.handles[..])
    });
    let block = Block::bordered().title(" Handles ");
    if requests.is_empty() && handles.is_empty() {
        let text = Line::styled("No handles yet. Press n to add one.", dim());
        frame.render_widget(Paragraph::new(text).block(block), area);
        return;
    }
    let selected = app.selected_handle();
    let mut lines: Vec<Line> = Vec::new();
    for (index, request) in requests.iter().enumerate() {
        lines.extend(request_lines(request, index == selected));
    }
    if !requests.is_empty() && !handles.is_empty() {
        lines.push(Line::raw(""));
    }
    for (index, handle) in handles.iter().enumerate() {
        lines.push(handle_line(handle, requests.len() + index == selected));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        area,
    );
}

/// A handle an agent asked for: what it would be, then who asked and why.
fn request_lines(requested: &RequestedHandle, selected: bool) -> Vec<Line<'static>> {
    let request = &requested.request;
    let kind = format!("{:?}", request.kind).to_lowercase();
    let marker = if selected { "▶ " } else { "  " };
    let mut text = format!("{marker}{:<20} {kind:<9} requested", request.name);
    if !request.description.is_empty() {
        text.push_str(&format!(" {}", request.description));
    }
    let style = Style::new().fg(Color::Yellow);
    let first = if selected {
        Line::styled(text, style.add_modifier(Modifier::BOLD))
    } else {
        Line::styled(text, style)
    };
    let client = requested.client.as_deref().map_or_else(
        || "an agent with no session".to_owned(),
        |client| format!("{client} (self-reported)"),
    );
    let mut why = format!("    asked by {client}");
    if !request.reason.is_empty() {
        why.push_str(&format!(": {}", request.reason));
    }
    vec![first, Line::styled(why, dim())]
}

fn handle_line(handle: &HandleInfo, selected: bool) -> Line<'static> {
    let mode = match handle.mode {
        Mode::Auto => "auto",
        Mode::Ask => "ask",
        Mode::Deny => "deny",
    };
    let kind = format!("{:?}", handle.kind).to_lowercase();
    let marker = if selected { "▶ " } else { "  " };
    let mut text = format!("{marker}{:<20} {kind:<9} {mode:<5}", handle.name);
    if !handle.description.is_empty() {
        text.push_str(&format!(" {}", handle.description));
    }
    if selected {
        Line::styled(text, Style::new().add_modifier(Modifier::BOLD))
    } else {
        Line::raw(text)
    }
}

fn draw_audit(frame: &mut Frame, entries: &[Entry], area: Rect) {
    let block = Block::bordered().title(" Audit log, newest first (UTC) ");
    if entries.is_empty() {
        let text = Line::styled("No audit entries yet.", dim());
        frame.render_widget(Paragraph::new(text).block(block), area);
        return;
    }
    let lines: Vec<Line> = entries.iter().flat_map(audit_lines).collect();
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

/// What happened on one line, and what was asked for under it.
fn audit_lines(entry: &Entry) -> Vec<Line<'static>> {
    // `2026-10-08T12:03:04.123Z` → `2026-10-08 12:03:04`
    let time: String = entry
        .ts
        .chars()
        .take(19)
        .map(|c| if c == 'T' { ' ' } else { c })
        .collect();
    let decision = entry.decision.as_deref().unwrap_or("");
    let style = match decision {
        "denied" | "policy" | "locked" => Style::new().fg(Color::Red),
        "approved" => Style::new().fg(Color::Green),
        _ => Style::new(),
    };
    let mut spans = vec![
        Span::styled(format!("{time}  "), dim()),
        Span::raw(format!(
            "{:<14} {:<16} ",
            entry.action,
            entry.handle.as_deref().unwrap_or("")
        )),
        Span::styled(format!("{decision:<9}"), style),
        Span::raw(format!("{:<16}", entry.outcome)),
    ];
    if let Some(ms) = entry.duration_ms {
        spans.push(Span::styled(format!("{ms}ms"), dim()));
    }
    let mut lines = vec![Line::from(spans)];
    if let Some(summary) = &entry.summary {
        lines.push(Line::raw(format!("    {summary}")));
    }
    lines
}

fn draw_form(frame: &mut Frame, form: &Form, area: Rect) {
    let mut lines: Vec<Line> = Vec::new();
    let mut focused_line = None;
    for (field, focused) in form.shown() {
        if focused {
            focused_line = Some(lines.len());
        }
        lines.push(field_line(field, focused));
    }
    lines.push(Line::raw(""));
    let save = if form.save_focused() {
        focused_line = Some(lines.len());
        Span::styled(" Save ", Style::new().add_modifier(Modifier::REVERSED))
    } else {
        Span::raw(" Save ")
    };
    lines.push(Line::from(vec![Span::raw("  "), save]));
    lines.push(Line::raw(""));
    lines.push(Line::styled(
        "  Tab next · ←→ choose · Enter next or save · Esc cancel",
        dim(),
    ));
    let width = area.width.min(90);
    // Sized and scrolled by wrapped rows, so long text (an agent's hosts,
    // say) can never push the focused field out of sight.
    let inner = width.saturating_sub(2).max(1);
    let rows: Vec<usize> = lines
        .iter()
        .map(|line| {
            Paragraph::new(line.clone())
                .wrap(Wrap { trim: false })
                .line_count(inner)
                .max(1)
        })
        .collect();
    let total: usize = rows.iter().sum();
    let visible = area.height.saturating_sub(2) as usize;
    let scroll = focused_line.map_or(0, |i| {
        let start: usize = rows[..i].iter().sum();
        let end = start + rows[i];
        end.saturating_sub(visible).min(start)
    });
    let height = (total as u16 + 2).min(area.height);
    let popup = Rect {
        x: area.x + (area.width - width) / 2,
        y: area.y,
        width,
        height,
    };
    frame.render_widget(Clear, popup);
    let block = Block::bordered().title(format!(" {} ", form.title()));
    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false })
            .scroll((scroll as u16, 0)),
        popup,
    );
}

fn field_line(field: &Field, focused: bool) -> Line<'static> {
    let marker = if focused { "▶ " } else { "  " };
    let label = Span::styled(
        format!("{marker}{:<16} ", field.label),
        if focused {
            Style::new().add_modifier(Modifier::BOLD)
        } else {
            Style::new()
        },
    );
    let mut spans = vec![label];
    match &field.input {
        Input::Text => spans.push(Span::raw(field.text.to_string())),
        Input::Hidden => spans.push(Span::raw("•".repeat(field.text.chars().count()))),
        Input::Choice(options) => {
            for (index, option) in options.iter().enumerate() {
                let style = if index == field.choice {
                    Style::new().add_modifier(Modifier::REVERSED)
                } else {
                    dim()
                };
                spans.push(Span::styled(format!(" {option} "), style));
            }
        }
        Input::Pairs => {
            let names: Vec<&str> = field.pairs.iter().map(|(name, _)| name.as_str()).collect();
            if !names.is_empty() {
                spans.push(Span::raw(format!("{} ", names.join(", "))));
            }
            // The name shows once `=` is typed; until then the text could
            // be a value pasted on its own.
            let dots = |text: &str| "•".repeat(text.chars().count());
            let typed = match field.text.split_once('=') {
                Some((name, value)) if is_variable_name(name.trim()) => {
                    format!("{name}={}", dots(value))
                }
                _ => dots(&field.text),
            };
            if focused || !typed.is_empty() {
                spans.push(Span::styled(format!("+ {typed}"), dim()));
            }
        }
    }
    if focused && !matches!(field.input, Input::Choice(_)) {
        spans.push(Span::raw("▏"));
    }
    if !field.hint.is_empty() {
        spans.push(Span::styled(format!("  {}", field.hint), dim()));
    }
    Line::from(spans)
}

fn key_hints(app: &App) -> String {
    let mut hints = Vec::new();
    if app.tab() == Tab::Approvals {
        let approvals = app.overview().map_or(&[][..], |o| &o.approvals[..]);
        if let Some(approval) = approvals.iter().find(|a| Some(a.id) == app.selected()) {
            hints.push("a allow once");
            if approval.can_grant {
                hints.push("s allow for session");
            }
            hints.extend(["d deny", "D deny always", "↑↓ select"]);
        }
    }
    if app.tab() == Tab::Handles {
        hints.push("n new");
        let (requests, handles) = app
            .overview()
            .map_or((0, 0), |o| (o.handle_requests.len(), o.handles.len()));
        if app.selected_handle() < requests {
            hints.extend(["Enter fill in", "x dismiss"]);
        } else if handles > 0 {
            hints.extend(["e edit", "p policy", "x remove"]);
        }
        if requests + handles > 1 {
            hints.push("↑↓ select");
        }
    }
    hints.extend(["1/2/3 tabs", "L lock", "q quit"]);
    hints.join(" · ")
}

fn dim() -> Style {
    Style::new().fg(Color::DarkGray)
}
