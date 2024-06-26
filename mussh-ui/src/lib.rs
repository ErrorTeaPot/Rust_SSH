mod widgets;

pub use crossterm;

use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture, Event, KeyCode, MouseEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use ratatui::{
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame, Terminal,
};
use std::io::{self, Stdout};
use widgets::Input;

pub type MyTerminal = Terminal<CrosstermBackend<io::Stdout>>;

#[derive(Copy, Clone, PartialEq)]
enum InputMode {
    Normal,
    Editing,
}

#[derive(Debug, Default)]
pub(crate) struct Pane {
    history: Vec<String>,
    offset: usize,
    /// Current value of the input box
    input: Input,
    has_unread_message: bool,
}

/// App holds the state of the application
#[derive(Default)]
pub struct App {
    state: AppState,
    terminal: Option<Terminal<CrosstermBackend<Stdout>>>,
    // input_width: u16,  TODO: find the input width is useful
}

pub struct AppState {
    /// Current input mode
    input_mode: InputMode,
    /// Notification to display.
    notif: Option<String>,

    /// Main zone
    pane: Pane,
}

impl Default for AppState {
    fn default() -> AppState {
        AppState {
            input_mode: InputMode::Normal,
            notif: None,
            pane: Pane::default(),
        }
    }
}

impl App {
    pub fn start(&mut self) -> io::Result<()> {
        self.terminal = Some(start_ui()?);
        Ok(())
    }
    pub fn draw(&mut self) -> io::Result<()> {
        self.terminal.as_mut().expect("App::draw() can only be called after a successful call to App::start(), and cannot be called after an errorring call to App::draw()")
        .draw(|f| ui(f, &mut self.state)).map(|_| ())
    }
}

impl Drop for App {
    fn drop(&mut self) {
        self.terminal.iter_mut().for_each(|terminal| {
            let _ = stop_ui(terminal); // we can only ignore the error - it's now too late to react
        })
    }
}

pub fn start_ui() -> io::Result<MyTerminal> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    Terminal::new(backend)
}

pub fn stop_ui(terminal: &mut MyTerminal) -> io::Result<()> {
    // restore terminal
    disable_raw_mode()?;
    terminal
        .backend_mut()
        .execute(LeaveAlternateScreen)?
        .execute(DisableMouseCapture)?;
    terminal.show_cursor()
}

pub enum KeyReaction {
    UserInput(String),
    Quit,
}

impl App {
    pub fn react_to_event(&mut self, event: Event) -> Option<KeyReaction> {
        // Mode-indepent actions
        let input_mode = self.state.input_mode;
        let pane = &mut self.state.pane;

        if let Event::Mouse(mouse_event) = event {
            match mouse_event.kind {
                MouseEventKind::ScrollUp => {
                    pane.offset = std::cmp::min(pane.history.len(), pane.offset + 1);
                }

                MouseEventKind::ScrollDown => {
                    pane.offset = pane.offset.saturating_sub(1);
                    if pane.offset == 0 {
                        pane.has_unread_message = false;
                    }
                }

                _ => {}
            }
        }

        match input_mode {
            InputMode::Normal => {
                if let Event::Key(key) = event {
                    match key.code {
                        KeyCode::Char('e') => {
                            self.state.input_mode = InputMode::Editing;
                        }
                        KeyCode::Char('q') => {
                            return Some(KeyReaction::Quit);
                        }

                        _ => {}
                    }
                }
            }

            InputMode::Editing => {
                if let Event::Key(key) = event {
                    match key.code {
                        KeyCode::Enter => {
                            let s = pane.input.submit();
                            let res = KeyReaction::UserInput(s);
                            return Some(res);
                        }

                        KeyCode::Char(c) => {
                            //Find the first character for which the cumulated width is larger than current offset
                            pane.input.insert_at_cursor(c);
                        }
                        KeyCode::Backspace => {
                            pane.input.delete_behind_cursor();
                        }

                        KeyCode::Delete => {
                            pane.input.delete_at_cursor();
                        }
                        KeyCode::Esc => {
                            self.state.input_mode = InputMode::Normal;
                        }
                        KeyCode::Left => {
                            pane.input.cursor_move_left();
                        }
                        KeyCode::Right => {
                            pane.input.cursor_move_right();
                        }
                        _ => {}
                    }
                }
            }
        }

        None
    }

    pub fn push_message(&mut self, message: String) {
        let pane = &mut self.state.pane;
        pane.history.push(message);
    }

    /// Set a new notification to print.
    /// Might erase an old one.
    pub fn set_notification(&mut self, notif: String) {
        self.state.notif = Some(notif);
    }

    /// Clear the current notification.
    pub fn clear_notif(&mut self) {
        self.state.notif.take();
    }
}

pub fn ui<B: Backend>(f: &mut Frame<B>, app_state: &mut AppState) {
    let input_mode = app_state.input_mode;

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints(
            [
                Constraint::Min(1),
                Constraint::Length(1),
                Constraint::Length(3),
                Constraint::Length(3),
                // Constraint::Length(3),
            ]
            .as_ref(),
        )
        .split(f.size());

    let (msg, style) = match app_state.input_mode {
        InputMode::Normal => (
            vec![
                Span::raw("Press "),
                Span::styled("q", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(" to exit, "),
                Span::styled("e", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(" to enter messages."),
            ],
            Style::default(),
            //Style::default().add_modifier(Modifier::RAPID_BLINK),
        ),
        InputMode::Editing => (
            vec![
                Span::raw("Press "),
                Span::styled("Esc", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(" to stop editing, "),
                Span::styled("Enter", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(" to send the message"),
            ],
            Style::default(),
        ),
    };
    let mut text = Text::from(Line::from(msg));
    text.patch_style(style);
    let help_message = Paragraph::new(text);
    f.render_widget(help_message, chunks[1]);

    let messages = &mut app_state.pane;

    messages.input.resize(chunks[2].width - 2);
    let input = Paragraph::new(messages.input.get_display_string())
        .style(match input_mode {
            InputMode::Normal => Style::default(),
            InputMode::Editing => Style::default().fg(Color::Yellow),
        })
        .block(Block::default().borders(Borders::ALL).title("Input"));

    f.render_widget(input, chunks[2]);

    match input_mode {
        InputMode::Normal =>
            // Hide the cursor. `Frame` does this by default, so we don't need to do anything here
            {}

        InputMode::Editing => {
            // Make the cursor visible and ask tui-rs to put it at the specified coordinates after rendering
            f.set_cursor(
                // Put cursor past the end of the input text
                chunks[2].x + messages.input.get_cursor_offset() + 1,
                // Move one line down, from the border to the input line
                chunks[2].y + 1,
            )
        }
    }

    let main_windows = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(15)].as_ref())
        .split(chunks[0]);

    let max_messages = (main_windows[0].height - 2) as usize; // TODO s'arrêter proprement si taille trop faible
    let to_skip = if messages.history.len() <= max_messages {
        0
    } else {
        messages.offset = std::cmp::min(messages.offset, messages.history.len() - max_messages);
        (messages.history.len() - max_messages).saturating_sub(messages.offset)
    };

    let messages: Vec<ListItem> = messages
        .history
        .iter()
        .skip(to_skip)
        .map(|m| {
            let content = vec![Line::from(Span::raw(m.clone()))];
            ListItem::new(content)
        })
        .collect();
    let mut all_messages = vec![ListItem::new(" "); max_messages.saturating_sub(messages.len())];
    all_messages.extend(messages);
    let messages =
        List::new(all_messages).block(Block::default().borders(Borders::ALL).title("Messages"));

    f.render_widget(messages, main_windows[0]);

    // Zone de notification pour les messages d'erreur
    let notif = app_state.notif.as_deref().unwrap_or_default();

    let notif = Paragraph::new(Text::from(notif)).block(
        Block::default()
            .borders(Borders::ALL)
            .title("Notifications"),
    );
    f.render_widget(notif, chunks[3]);
    //f.render_widget(messages, main_windows[1]);

    // f.render_widget(main_windows, chunks[0]);
}
