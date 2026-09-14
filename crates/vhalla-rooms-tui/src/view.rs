//! Ratatui rendering for [`App`]. Pure projection → frame; no state.

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap},
    Frame,
};

use vhalla_rooms_app::PendingState;

use crate::{App, Modal, View};

const ACCENT: Color = Color::Cyan;
const DIM: Color = Color::DarkGray;

/// Draws the whole frame: header, body, pending strip, status line,
/// help line, and the open modal when one exists.
pub fn draw(app: &App, frame: &mut Frame) {
    let area = frame.area();
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(3),
            Constraint::Length(pending_height(app)),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .split(area);

    header(app, frame, rows[0]);
    body(app, frame, rows[1]);
    pending(app, frame, rows[2]);
    status(app, frame, rows[3]);
    help(app, frame, rows[4]);
    if let Some(modal) = &app.modal {
        draw_modal(modal, frame, area);
    }
}

fn header(app: &App, frame: &mut Frame, area: Rect) {
    let (height, revision) = app
        .projection
        .as_ref()
        .map(|p| (p.height, p.revision))
        .unwrap_or((0, 0));
    let title = match &app.view {
        View::Directory => "directory".to_owned(),
        View::Room { slug } => format!("room {slug}"),
        View::Account { owner } => format!("account {}", short(owner)),
    };
    let line = Line::from(vec![
        Span::styled(" vhalla ", Style::default().fg(Color::Black).bg(ACCENT)),
        Span::raw("  rooms "),
        Span::styled(title, Style::default().fg(ACCENT)),
        Span::styled(
            format!("   height {height} · revision {revision}"),
            Style::default().fg(DIM),
        ),
    ]);
    frame.render_widget(Paragraph::new(line), area);
}

fn body(app: &App, frame: &mut Frame, area: Rect) {
    match &app.view {
        View::Directory => directory(app, frame, area),
        View::Room { slug } => room(app, slug, frame, area),
        View::Account { .. } => account(app, frame, area),
    }
}

fn directory(app: &App, frame: &mut Frame, area: Rect) {
    let block = Block::default().borders(Borders::ALL).title(Span::styled(
        format!(" rooms /{} ", app.filter),
        Style::default().fg(if app.filter_active { ACCENT } else { DIM }),
    ));
    let rows = app.rows();
    if rows.is_empty() {
        let text = if app.filter.is_empty() {
            "No committed rooms yet. Press n to create the first."
        } else {
            "No committed rooms match the filter."
        };
        frame.render_widget(
            Paragraph::new(text).block(block).wrap(Wrap { trim: true }),
            area,
        );
        return;
    }
    let items: Vec<ListItem> = rows
        .iter()
        .map(|r| {
            let flag = if r.archived { " (archived)" } else { "" };
            ListItem::new(Line::from(vec![
                Span::styled(format!("{:<24}", r.slug), Style::default().fg(ACCENT)),
                Span::raw(format!("{}{}", r.description, flag)),
                Span::styled(
                    format!("  · owner {} · rev {}", short(&r.owner), r.revisions),
                    Style::default().fg(DIM),
                ),
            ]))
        })
        .collect();
    let mut state = ListState::default();
    state.select(Some(app.selected));
    let list = List::new(items)
        .block(block)
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));
    frame.render_stateful_widget(list, area, &mut state);
}

fn room(app: &App, slug: &str, frame: &mut Frame, area: Rect) {
    let block = Block::default().borders(Borders::ALL).title(" room ");
    let Some(row) = app.rows().iter().find(|r| r.slug == slug) else {
        frame.render_widget(
            Paragraph::new(format!("No committed room is named \"{slug}\"."))
                .block(block)
                .wrap(Wrap { trim: true }),
            area,
        );
        return;
    };
    let fields = [
        ("slug", row.slug.clone()),
        ("description", row.description.clone()),
        ("owner", row.owner.clone()),
        ("agent", row.agent.clone()),
        ("slot", row.slot.to_string()),
        ("charge", row.charge.to_string()),
        ("revisions", row.revisions.to_string()),
        ("created", row.created_at.to_string()),
        ("genesis record", row.record.clone()),
        ("head", row.head.clone()),
        (
            "status",
            if row.archived { "archived" } else { "live" }.to_owned(),
        ),
    ];
    let lines: Vec<Line> = fields
        .iter()
        .map(|(k, v)| {
            Line::from(vec![
                Span::styled(format!("{k:<16}"), Style::default().fg(DIM)),
                Span::raw(v.clone()),
            ])
        })
        .collect();
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn account(app: &App, frame: &mut Frame, area: Rect) {
    let block = Block::default().borders(Borders::ALL).title(" account ");
    let Some(p) = &app.projection else {
        frame.render_widget(Paragraph::new("loading…").block(block), area);
        return;
    };
    let Some(a) = &p.account else {
        frame.render_widget(
            Paragraph::new("Owner missing from committed social state.").block(block),
            area,
        );
        return;
    };
    let mut lines = vec![
        Line::from(vec![
            Span::styled("earned          ", Style::default().fg(DIM)),
            Span::raw(a.earned.to_string()),
        ]),
        Line::from(vec![
            Span::styled("spent           ", Style::default().fg(DIM)),
            Span::raw(a.spent.to_string()),
        ]),
        Line::from(vec![
            Span::styled("lifetime slots  ", Style::default().fg(DIM)),
            Span::raw(a.lifetime_slots.to_string()),
        ]),
    ];
    if let Some((slot, charge)) = p.quote {
        lines.push(Line::from(vec![
            Span::styled("next slot       ", Style::default().fg(DIM)),
            Span::raw(format!("{slot} · charge {charge}")),
        ]));
    }
    if !p.rooms.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "open rooms",
            Style::default().fg(DIM),
        )));
        for r in &p.rooms {
            lines.push(Line::from(format!(
                "  {:<24} rev {} {}",
                r.slug,
                r.revisions,
                if r.archived { "(archived)" } else { "" }
            )));
        }
    }
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn pending_height(app: &App) -> u16 {
    let n = app.pending().len() as u16;
    if n == 0 {
        0
    } else {
        (n + 2).min(8)
    }
}

fn pending(app: &App, frame: &mut Frame, area: Rect) {
    if app.pending().is_empty() {
        return;
    }
    let items: Vec<ListItem> = app
        .pending()
        .iter()
        .map(|p| {
            let (label, color) = match p.state {
                PendingState::Queued => ("queued", Color::Yellow),
                PendingState::Submitted => ("in flight", Color::Yellow),
                PendingState::Committed => ("committed", Color::Green),
                PendingState::Collision => ("collision", Color::Red),
                PendingState::Rejected => ("rejected", Color::Red),
            };
            ListItem::new(Line::from(vec![
                Span::styled(format!("{label:<10}"), Style::default().fg(color)),
                Span::raw(p.slug.clone().unwrap_or_else(|| short(&p.name))),
            ]))
        })
        .collect();
    frame.render_widget(
        List::new(items).block(Block::default().borders(Borders::ALL).title(" pending ")),
        area,
    );
}

fn status(app: &App, frame: &mut Frame, area: Rect) {
    let line = if let Some(e) = &app.error {
        Line::from(Span::styled(
            format!(" error: {e}"),
            Style::default().fg(Color::Red),
        ))
    } else if let Some(s) = &app.status {
        Line::from(Span::styled(
            format!(" {s}"),
            Style::default().fg(Color::Green),
        ))
    } else {
        Line::from("")
    };
    frame.render_widget(Paragraph::new(line), area);
}

fn help(app: &App, frame: &mut Frame, area: Rect) {
    let keys = match (&app.view, app.modal.is_some(), app.filter_active) {
        (_, true, _) => "enter submit · tab next field · esc cancel",
        (_, _, true) => "enter/esc done · type to filter",
        (View::Directory, ..) => {
            "j/k move · enter open · / filter · n new room · a account · r refresh · q quit"
        }
        (View::Room { .. }, ..) => "d describe · x archive · o owner · b back",
        (View::Account { .. }, ..) => "b back",
    };
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            format!(" {keys}"),
            Style::default().fg(DIM),
        ))),
        area,
    );
}

fn draw_modal(modal: &Modal, frame: &mut Frame, area: Rect) {
    match modal {
        Modal::Create(f) | Modal::Describe { form: f, .. } => {
            let height = (f.fields.len() as u16 + 4).min(area.height.saturating_sub(2));
            let width = area.width.min(72);
            let rect = centered(width, height, area);
            frame.render_widget(Clear, rect);
            let mut lines: Vec<Line> = Vec::new();
            for (i, field) in f.fields.iter().enumerate() {
                let cursor = if i == f.focus { "▌" } else { "" };
                lines.push(Line::from(vec![
                    Span::styled(
                        format!("{:<44}", field.label),
                        Style::default().fg(if i == f.focus { ACCENT } else { DIM }),
                    ),
                    Span::raw(format!("{}{cursor}", field.value)),
                ]));
            }
            frame.render_widget(
                Paragraph::new(lines).block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(format!(" {} ", f.title)),
                ),
                rect,
            );
        }
        Modal::Archive { slug, key } => {
            let rect = centered(area.width.min(64), 7, area);
            frame.render_widget(Clear, rect);
            let lines = vec![
                Line::from(format!("Archive \"{slug}\"? The slug stays reserved.")),
                Line::from(""),
                Line::from(vec![
                    Span::styled("owner identity dir ", Style::default().fg(DIM)),
                    Span::raw(format!("{key}▌")),
                ]),
                Line::from(""),
                Line::from(Span::styled(
                    "enter sign + submit · esc cancel",
                    Style::default().fg(DIM),
                )),
            ];
            frame.render_widget(
                Paragraph::new(lines)
                    .block(Block::default().borders(Borders::ALL).title(" archive ")),
                rect,
            );
        }
    }
}

fn centered(width: u16, height: u16, area: Rect) -> Rect {
    let v = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(area.height.saturating_sub(height) / 2),
            Constraint::Length(height),
            Constraint::Min(0),
        ])
        .split(area);
    let h = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(area.width.saturating_sub(width) / 2),
            Constraint::Length(width),
            Constraint::Min(0),
        ])
        .split(v[1]);
    h[1]
}

fn short(hex: &str) -> String {
    hex.chars().take(12).collect()
}
