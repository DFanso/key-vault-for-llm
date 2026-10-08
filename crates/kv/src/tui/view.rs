//! Draws `App`. Everything here reads state; nothing changes it.

use std::time::Duration;

use kv_core::policy::Mode;
use kv_core::proto::{Approval, Overview};
use kv_core::secret::HandleInfo;
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Paragraph, Wrap};

use super::app::{App, Screen, Tab};

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
        Tab::Handles => draw_handles(frame, app.overview(), body),
    }
    frame.render_widget(Paragraph::new(Line::styled(key_hints(app), dim())), footer);
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
    Line::from(spans)
}

fn tab_line(app: &App) -> Line<'static> {
    let waiting = app.overview().map_or(0, |o| o.approvals.len());
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
        tab("2 Handles".into(), app.tab() == Tab::Handles),
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
    let mut text = Text::default();
    for (index, approval) in approvals.iter().enumerate() {
        text.extend(approval_lines(approval, index == app.selected()));
        text.push_line(Line::raw(""));
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
                "{marker}{client} · {} · {}",
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

fn draw_handles(frame: &mut Frame, overview: Option<&Overview>, area: Rect) {
    let handles = overview.map_or(&[][..], |o| &o.handles[..]);
    let block = Block::bordered().title(" Handles ");
    if handles.is_empty() {
        let text = Line::styled("No handles yet.", dim());
        frame.render_widget(Paragraph::new(text).block(block), area);
        return;
    }
    let lines: Vec<Line> = handles.iter().map(handle_line).collect();
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn handle_line(handle: &HandleInfo) -> Line<'static> {
    let mode = match handle.mode {
        Mode::Auto => "auto",
        Mode::Ask => "ask",
        Mode::Deny => "deny",
    };
    let kind = format!("{:?}", handle.kind).to_lowercase();
    let mut text = format!("{:<20} {kind:<9} {mode:<5}", handle.name);
    if !handle.description.is_empty() {
        text.push_str(&format!(" {}", handle.description));
    }
    Line::raw(text)
}

fn key_hints(app: &App) -> String {
    let mut hints = Vec::new();
    if app.tab() == Tab::Approvals {
        let approvals = app.overview().map_or(&[][..], |o| &o.approvals[..]);
        if let Some(approval) = approvals.get(app.selected()) {
            hints.push("a allow once");
            if approval.can_grant {
                hints.push("s allow for session");
            }
            hints.extend(["d deny", "D deny always", "↑↓ select"]);
        }
    }
    hints.extend(["1/2 tabs", "L lock", "q quit"]);
    hints.join(" · ")
}

fn dim() -> Style {
    Style::new().fg(Color::DarkGray)
}
