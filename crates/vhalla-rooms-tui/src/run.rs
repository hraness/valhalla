//! The terminal lifecycle: raw mode, alternate screen, event poll, and a
//! fixed refresh tick. Everything stateful lives in [`App`]; this file is
//! only the unix terminal plumbing around it.

use std::io::{self, Stdout};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ratatui::crossterm::{
    event::{self, Event},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};

use vhalla_rooms_app::Error;

use crate::{view, App, Source};

/// How often the replica re-syncs and the projection re-renders even
/// without input — cheap pulls over local files.
const TICK: Duration = Duration::from_millis(500);

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

struct Guard {
    term: Terminal<CrosstermBackend<Stdout>>,
}

impl Guard {
    fn enter() -> io::Result<Self> {
        enable_raw_mode()?;
        let mut out = io::stdout();
        execute!(out, EnterAlternateScreen)?;
        let term = Terminal::new(CrosstermBackend::new(out))?;
        Ok(Self { term })
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(self.term.backend_mut(), LeaveAlternateScreen);
    }
}

/// Runs `app` against `src` until the user quits. Restores the terminal
/// on every exit path — `Guard` is dropped before the error propagates.
pub fn run(app: &mut App, src: &mut dyn Source) -> Result<(), Error> {
    let mut guard = Guard::enter().map_err(|e| Error::Io(format!("terminal init: {e}")))?;
    app.refresh(src);
    let mut last = Instant::now();
    while !app.quit {
        guard
            .term
            .draw(|frame| view::draw(app, frame))
            .map_err(|e| Error::Io(format!("draw: {e}")))?;
        let timeout = TICK.saturating_sub(last.elapsed());
        if event::poll(timeout).map_err(|e| Error::Io(format!("poll: {e}")))? {
            match event::read().map_err(|e| Error::Io(format!("read: {e}")))? {
                Event::Key(key) => app.key(key, src),
                Event::Resize(..) => {}
                _ => {}
            }
        }
        if last.elapsed() >= TICK {
            app.now = now();
            app.refresh(src);
            last = Instant::now();
        }
    }
    Ok(())
}
