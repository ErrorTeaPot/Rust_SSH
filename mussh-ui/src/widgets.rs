/*pub use crossterm;*/

use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

fn get_byte_offset(input: &str, offset: u16) -> Option<(usize, char)> {
    let mut prefix_width = 0;
    for (i, c) in input.char_indices() {
        if prefix_width >= offset as usize {
            return Some((i, c));
        } else {
            prefix_width += c.width().unwrap_or(1);
        }
    }
    None
}
fn get_byte_offset_before(input: &str, offset: u16) -> Option<(usize, char)> {
    let mut prefix_width = 0;
    if offset == 0 {
        return None;
    }
    for (i, c) in input.char_indices() {
        prefix_width += c.width().unwrap_or(1);
        if prefix_width >= offset as usize {
            return Some((i, c));
        }
    }
    panic!("Should not happen");
    //    return None;
}

#[derive(Hash, PartialEq, PartialOrd, Eq, Ord, Debug, Default)]
pub struct Input {
    /// Text contained in the input widget
    pub text: String,
    /// Cursor offset, relative to the text offset, in caracter width
    pub cursor_offset: u16,
    /// Text offset from which the texte should be displayed, in bytes
    pub text_offset: usize,
    /// Determines whether the widget reacts to input
    pub enabled: bool,

    /// Display width in the UI
    pub display_width: u16,
}

impl Input {
    #[allow(dead_code)] // To satisfy clippy
    pub fn resize(&mut self, new_size: u16) {
        if new_size < 2 {
            panic!("Cannot display such a small input widget");
        }

        self.display_width = new_size;
        if self.cursor_offset >= new_size {
            self.cursor_offset = new_size
                - get_byte_offset_before(self.get_display_string(), new_size)
                    .unwrap_or((0, ' '))
                    .1
                    .width()
                    .unwrap_or(1) as u16;
        }
    }
    pub fn get_display_string(&self) -> &str {
        &self.text[self.text_offset..]
    }

    #[allow(dead_code)] // To satisfy clippy
    pub fn get_cursor_offset(&self) -> u16 {
        self.cursor_offset
    }

    #[allow(dead_code)] // To satisfy clippy
    pub fn submit(&mut self) -> String {
        self.cursor_offset = 0;
        self.text_offset = 0;
        self.text.drain(..).collect()
    }

    pub fn insert_at_cursor(&mut self, c: char) {
        // Find the byte offset in the string corresponding to the current cursor
        match get_byte_offset(self.get_display_string(), self.cursor_offset) {
            None => {
                self.text.push(c);
            }
            Some((i, _)) => {
                self.text.insert(i + self.text_offset, c);
            }
        }

        // Move the cursor
        self.cursor_offset += c.width().unwrap_or(1) as u16;

        // If the cursor leaves the current displayed widget, apply an offset to the displayed string
        if self.cursor_offset >= self.display_width {
            let input_shift = std::cmp::max(1, self.display_width / 2);
            if let Some((extra_offset, _)) = get_byte_offset(self.get_display_string(), input_shift)
            {
                self.text_offset += extra_offset;
                self.cursor_offset = std::cmp::min(
                    self.cursor_offset.saturating_sub(input_shift),
                    self.get_display_string().width() as u16,
                );
            }
        }
    }

    pub fn cursor_move_left(&mut self) {
        if self.cursor_offset == 0 && self.text_offset != 0 {
            // Move left !
            let old_text_offset = self.text_offset;
            let input_shift = std::cmp::max(1, self.display_width / 2);
            let text_shift =
                (self.text[0..self.text_offset].width() as u16).saturating_sub(input_shift);
            let (new_offset, _) =
                get_byte_offset_before(&self.text, text_shift).unwrap_or((0, ' '));
            self.cursor_offset = self.text[new_offset..old_text_offset].width() as u16;
            self.text_offset = new_offset;
        }
        {
            if let Some((_, c)) =
                get_byte_offset_before(self.get_display_string(), self.cursor_offset)
            {
                self.cursor_offset = self
                    .cursor_offset
                    .saturating_sub(std::cmp::max(1, c.width().unwrap_or(1) as u16));
            }
        }
    }

    pub fn cursor_move_right(&mut self) {
        let current_char = get_byte_offset(self.get_display_string(), self.cursor_offset)
            .unwrap_or((0, ' '))
            .1;
        if self.cursor_offset
            >= self
                .display_width
                .saturating_sub(current_char.width().unwrap_or(1) as u16)
        {
            //Move right !
            let input_shift = std::cmp::max(1, self.display_width / 2);
            if let Some((extra_offset, _)) = get_byte_offset(self.get_display_string(), input_shift)
            {
                let old_text_offset = self.text_offset;
                self.text_offset += extra_offset;
                self.cursor_offset = self
                    .cursor_offset
                    .saturating_sub(self.text[old_text_offset..self.text_offset].width() as u16);
                // the text was (visually) moved this much
            }
        }

        if let Some((_, c)) = get_byte_offset(self.get_display_string(), self.cursor_offset) {
            self.cursor_offset = std::cmp::min(
                self.cursor_offset
                    .saturating_add(std::cmp::max(1, c.width().unwrap_or(1) as u16)),
                self.text.width().try_into().unwrap_or(u16::MAX),
            );
        }
    }

    pub fn delete_at_cursor(&mut self) {
        match get_byte_offset(self.get_display_string(), self.cursor_offset) {
            None => {}
            Some((i, _)) => {
                self.text.remove(i + self.text_offset);
            }
        };
    }

    pub fn delete_behind_cursor(&mut self) {
        let deleted_c = match get_byte_offset_before(
            self.get_display_string(),
            std::cmp::min(
                self.cursor_offset,
                self.text.width().try_into().unwrap_or(u16::MAX),
            ),
        ) {
            None =>
            // Delete the last character before the displayed string
            {
                match self.text[0..self.text_offset].char_indices().last() {
                    Some((i, _)) => {
                        self.text_offset = i;
                        Some(self.text.remove(i))
                    }
                    None => None,
                }
            }
            Some((i, _)) => Some(self.text.remove(i + self.text_offset)),
        };

        if self.cursor_offset == 0 {
            self.cursor_move_left();
            //if self.text_offset != 0 {
            self.cursor_move_right();
            self.cursor_move_right();
            //}
        } else if let Some(c) = deleted_c {
            self.cursor_offset = self
                .cursor_offset
                .saturating_sub(c.width().unwrap_or(1) as u16);
        }
    }
}
