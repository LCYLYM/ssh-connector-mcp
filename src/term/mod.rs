//! VT100 terminal-emulator wrapper.
//!
//! Wraps [`vt100::Parser`] with a monotonic sequence counter and provides
//! structured snapshots suitable for AI consumption.

use crate::types::{AttrSpan, KeyName, ScreenSnapshot};

/// A VT100 terminal emulator instance backed by [`vt100::Parser`].
///
/// Maintains a monotonic sequence number that increments on every call to
/// [`process`](TerminalEmulator::process), allowing callers to detect new
/// output without comparing screen contents.
pub struct TerminalEmulator {
    parser: vt100::Parser,
    rows: u16,
    cols: u16,
    seq: u64,
}

impl TerminalEmulator {
    /// Create a new emulator with the given dimensions and scrollback 0.
    pub fn new(rows: u16, cols: u16) -> Self {
        Self {
            parser: vt100::Parser::new(rows, cols, 0),
            rows,
            cols,
            seq: 0,
        }
    }

    /// Feed raw PTY bytes from the remote. Increments the sequence counter.
    /// Returns the new sequence number.
    pub fn process(&mut self, bytes: &[u8]) -> u64 {
        self.parser.process(bytes);
        self.seq += 1;
        self.seq
    }

    /// Resize the emulated screen. Does not increment seq.
    pub fn resize(&mut self, rows: u16, cols: u16) {
        self.rows = rows;
        self.cols = cols;
        self.parser.screen_mut().set_size(rows, cols);
    }

    /// Current monotonic sequence number.
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// Render the current screen state as a structured snapshot.
    pub fn snapshot(&self) -> ScreenSnapshot {
        let screen = self.parser.screen();
        let (rows, cols) = screen.size();
        let (cursor_row, cursor_col) = screen.cursor_position();
        let cursor_visible = !screen.hide_cursor();
        let alt_screen = screen.alternate_screen();

        // Build one plain-text string per visible row.
        // screen.rows(start_col, width) returns an iterator of Strings per row.
        let screen_rows: Vec<String> = screen.rows(0, cols).collect();

        // Build attribute spans: contiguous runs of cells with inverse or bold.
        let mut attrs: Vec<AttrSpan> = Vec::new();
        for row_idx in 0..rows {
            let mut run: Option<(u16, bool, bool)> = None; // (col_start, inverse, bold)

            for col_idx in 0..cols {
                if let Some(cell) = screen.cell(row_idx, col_idx) {
                    let inv = cell.inverse();
                    let bld = cell.bold();
                    let interesting = inv || bld;

                    match run {
                        Some((_, ri, rb)) if ri == inv && rb == bld && interesting => {
                            // Current run continues unchanged.
                        }
                        Some((start, ri, rb)) => {
                            // Run broken: emit it if interesting.
                            if ri || rb {
                                attrs.push(AttrSpan {
                                    row: row_idx,
                                    col_start: start,
                                    col_end: col_idx,
                                    inverse: ri,
                                    bold: rb,
                                });
                            }
                            run = if interesting {
                                Some((col_idx, inv, bld))
                            } else {
                                None
                            };
                        }
                        None => {
                            if interesting {
                                run = Some((col_idx, inv, bld));
                            }
                        }
                    }
                } else {
                    // Cell out-of-bounds: close any open run.
                    if let Some((start, ri, rb)) = run.take() {
                        if ri || rb {
                            attrs.push(AttrSpan {
                                row: row_idx,
                                col_start: start,
                                col_end: col_idx,
                                inverse: ri,
                                bold: rb,
                            });
                        }
                    }
                }
            }

            // Close a run that reaches the end of the row.
            if let Some((start, ri, rb)) = run.take() {
                if ri || rb {
                    attrs.push(AttrSpan {
                        row: row_idx,
                        col_start: start,
                        col_end: cols,
                        inverse: ri,
                        bold: rb,
                    });
                }
            }
        }

        ScreenSnapshot {
            rows,
            cols,
            cursor_row,
            cursor_col,
            cursor_visible,
            screen: screen_rows,
            attrs,
            alt_screen,
            seq: self.seq,
        }
    }
}

/// Map a semantic [`KeyName`] to the byte sequence a terminal sends for it.
///
/// Arrow keys and navigation keys use standard xterm/VT100 sequences.
/// Function keys F1–F4 use the SS3 form (`ESC O P/Q/R/S`); F5–F12 use
/// the CSI tilde form (`ESC [ Nn ~`).
pub fn key_to_bytes(key: &KeyName) -> Vec<u8> {
    match key {
        KeyName::Enter => b"\r".to_vec(),
        KeyName::Tab => b"\t".to_vec(),
        KeyName::Escape => b"\x1b".to_vec(),
        KeyName::Backspace => b"\x7f".to_vec(),

        // Arrow keys — standard xterm DECCKM-off (non-application) sequences.
        KeyName::Up => b"\x1b[A".to_vec(),
        KeyName::Down => b"\x1b[B".to_vec(),
        KeyName::Right => b"\x1b[C".to_vec(),
        KeyName::Left => b"\x1b[D".to_vec(),

        // Navigation keys.
        KeyName::Home => b"\x1b[H".to_vec(),
        KeyName::End => b"\x1b[F".to_vec(),
        KeyName::PageUp => b"\x1b[5~".to_vec(),
        KeyName::PageDown => b"\x1b[6~".to_vec(),
        KeyName::Delete => b"\x1b[3~".to_vec(),

        // Control characters.
        KeyName::CtrlC => vec![0x03],
        KeyName::CtrlD => vec![0x04],
        KeyName::CtrlZ => vec![0x1a],
        KeyName::CtrlL => vec![0x0c],
        KeyName::CtrlA => vec![0x01],
        KeyName::CtrlE => vec![0x05],
        KeyName::CtrlU => vec![0x15],
        KeyName::CtrlK => vec![0x0b],

        // Function keys.
        // F1–F4: SS3 sequences (ESC O P/Q/R/S).
        KeyName::F(1) => b"\x1bOP".to_vec(),
        KeyName::F(2) => b"\x1bOQ".to_vec(),
        KeyName::F(3) => b"\x1bOR".to_vec(),
        KeyName::F(4) => b"\x1bOS".to_vec(),
        // F5–F12: CSI tilde sequences.
        KeyName::F(5) => b"\x1b[15~".to_vec(),
        KeyName::F(6) => b"\x1b[17~".to_vec(),
        KeyName::F(7) => b"\x1b[18~".to_vec(),
        KeyName::F(8) => b"\x1b[19~".to_vec(),
        KeyName::F(9) => b"\x1b[20~".to_vec(),
        KeyName::F(10) => b"\x1b[21~".to_vec(),
        KeyName::F(11) => b"\x1b[23~".to_vec(),
        KeyName::F(12) => b"\x1b[24~".to_vec(),
        // Any other F-key: send nothing (unsupported).
        KeyName::F(_) => vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::KeyName;

    /// Helper: create a small 5-row x 20-col emulator.
    fn make_term() -> TerminalEmulator {
        TerminalEmulator::new(5, 20)
    }

    // -----------------------------------------------------------------------
    // 1. Plain ASCII text renders into the correct row of snapshot().screen.
    // -----------------------------------------------------------------------
    #[test]
    fn test_ascii_text_renders_to_row() {
        let mut t = make_term();
        // Move to row 0, col 0 (home) then write text.
        t.process(b"\x1b[H"); // CUP (1,1) = row 0, col 0
        t.process(b"Hello");
        let snap = t.snapshot();
        assert!(
            snap.screen[0].contains("Hello"),
            "row 0 should contain 'Hello', got: {:?}",
            snap.screen[0]
        );
    }

    // -----------------------------------------------------------------------
    // 2. Cursor position tracks after writing text.
    // -----------------------------------------------------------------------
    #[test]
    fn test_cursor_position_after_write() {
        let mut t = make_term();
        t.process(b"\x1b[H"); // cursor to (0,0)
        t.process(b"Hi"); // advance cursor by 2 columns
        let snap = t.snapshot();
        assert_eq!(snap.cursor_row, 0, "cursor should still be on row 0");
        assert_eq!(snap.cursor_col, 2, "cursor should be at col 2 after 'Hi'");
    }

    // -----------------------------------------------------------------------
    // 3. SGR inverse produces an AttrSpan{inverse:true}.
    // -----------------------------------------------------------------------
    #[test]
    fn test_sgr_inverse_produces_attr_span() {
        let mut t = TerminalEmulator::new(3, 40);
        // Move to row 0, col 0; set inverse; write 3 chars; reset.
        t.process(b"\x1b[H\x1b[7mABC\x1b[0m");
        let snap = t.snapshot();
        let inv_spans: Vec<&AttrSpan> = snap.attrs.iter().filter(|a| a.inverse).collect();
        assert!(
            !inv_spans.is_empty(),
            "expected at least one inverse AttrSpan"
        );
        let span = inv_spans[0];
        assert_eq!(span.row, 0, "inverse span should be on row 0");
        assert_eq!(span.col_start, 0, "span should start at col 0");
        assert_eq!(span.col_end, 3, "span should end at col 3 (exclusive)");
        assert!(span.inverse);
    }

    // -----------------------------------------------------------------------
    // 4. key_to_bytes produces the correct byte sequences.
    // -----------------------------------------------------------------------
    #[test]
    fn test_key_to_bytes_up() {
        assert_eq!(key_to_bytes(&KeyName::Up), b"\x1b[A".to_vec());
    }

    #[test]
    fn test_key_to_bytes_ctrl_c() {
        assert_eq!(key_to_bytes(&KeyName::CtrlC), vec![0x03]);
    }

    #[test]
    fn test_key_to_bytes_enter() {
        assert_eq!(key_to_bytes(&KeyName::Enter), b"\r".to_vec());
    }

    #[test]
    fn test_key_to_bytes_down() {
        assert_eq!(key_to_bytes(&KeyName::Down), b"\x1b[B".to_vec());
    }

    #[test]
    fn test_key_to_bytes_f1() {
        assert_eq!(key_to_bytes(&KeyName::F(1)), b"\x1bOP".to_vec());
    }

    #[test]
    fn test_key_to_bytes_f5() {
        assert_eq!(key_to_bytes(&KeyName::F(5)), b"\x1b[15~".to_vec());
    }

    // -----------------------------------------------------------------------
    // 5. process() increments seq.
    // -----------------------------------------------------------------------
    #[test]
    fn test_process_increments_seq() {
        let mut t = make_term();
        assert_eq!(t.seq(), 0);
        let s1 = t.process(b"a");
        assert_eq!(s1, 1);
        assert_eq!(t.seq(), 1);
        let s2 = t.process(b"b");
        assert_eq!(s2, 2);
        assert_eq!(t.seq(), 2);
        let snap = t.snapshot();
        assert_eq!(snap.seq, 2);
    }

    // -----------------------------------------------------------------------
    // 6. Switching to alt screen sets alt_screen=true.
    // -----------------------------------------------------------------------
    #[test]
    fn test_alt_screen_flag() {
        let mut t = make_term();
        assert!(!t.snapshot().alt_screen, "should start on normal screen");
        t.process(b"\x1b[?1049h"); // enter alternate screen
        assert!(
            t.snapshot().alt_screen,
            "alt_screen should be true after 1049h"
        );
        t.process(b"\x1b[?1049l"); // leave alternate screen
        assert!(
            !t.snapshot().alt_screen,
            "alt_screen should be false after 1049l"
        );
    }

    // -----------------------------------------------------------------------
    // Extra: cursor_visible reflects hide-cursor escape.
    // -----------------------------------------------------------------------
    #[test]
    fn test_cursor_visibility() {
        let mut t = make_term();
        assert!(
            t.snapshot().cursor_visible,
            "cursor should be visible by default"
        );
        t.process(b"\x1b[?25l"); // hide cursor
        assert!(
            !t.snapshot().cursor_visible,
            "cursor should be hidden after ?25l"
        );
        t.process(b"\x1b[?25h"); // show cursor
        assert!(
            t.snapshot().cursor_visible,
            "cursor should be visible after ?25h"
        );
    }

    // -----------------------------------------------------------------------
    // Extra: resize changes snapshot dimensions.
    // -----------------------------------------------------------------------
    #[test]
    fn test_resize() {
        let mut t = TerminalEmulator::new(24, 80);
        t.resize(30, 100);
        let snap = t.snapshot();
        assert_eq!(snap.rows, 30);
        assert_eq!(snap.cols, 100);
    }
}
