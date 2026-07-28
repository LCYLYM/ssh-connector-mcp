//! Persistent PTY sessions. Each session owns a russh channel with a PTY and a
//! background actor task that pumps remote bytes into a [`TerminalEmulator`] and
//! a raw byte ring (for Web-UI takeover), and forwards stdin to the remote.
//!
//! Sessions are addressed by id and survive across many AI tool calls; this is
//! what gives the AI a stateful interactive shell instead of one-shot execs.

use crate::error::{ConnectorError, ErrorCode, Result};
use crate::ssh::Connection;
use crate::term::{TerminalEmulator, key_to_bytes};
use crate::types::{KeyName, ReadResult, ScreenSnapshot};
use russh::ChannelMsg;
use russh::client;
use std::sync::Arc;
use tokio::sync::{Mutex, broadcast};
use tokio::time::Instant;

/// Commands sent to the PTY actor.
enum PtyCmd {
    /// Raw bytes to write to the remote stdin.
    Input(Vec<u8>),
    /// Resize the remote PTY and local emulator.
    Resize { rows: u16, cols: u16 },
}

/// Shared, lock-protected view of the terminal state the actor maintains.
struct PtyState {
    emulator: TerminalEmulator,
    /// Plain UTF-8 text appended since the session started (for line reads),
    /// capped to a recent window.
    text_tail: String,
    last_activity: Instant,
    closed: bool,
    /// Byte offset (in seq terms) consumed by the last incremental read.
    last_read_seq: u64,
}

/// Handle to a live PTY session, cloneable across tasks.
#[derive(Clone)]
pub struct PtyHandle {
    pub session_id: String,
    pub host_id: String,
    pub created_at: String,
    rows: Arc<Mutex<(u16, u16)>>,
    state: Arc<Mutex<PtyState>>,
    cmd_tx: tokio::sync::mpsc::Sender<PtyCmd>,
    /// Raw byte stream for Web-UI takeover (xterm.js).
    raw_tx: broadcast::Sender<Vec<u8>>,
}

const TEXT_TAIL_CAP: usize = 256 * 1024;

pub struct PtySession;

impl PtySession {
    /// Open a PTY on the connection and spawn its actor. Returns a handle.
    pub async fn open(
        conn: &Connection,
        session_id: String,
        host_id: String,
        rows: u16,
        cols: u16,
    ) -> Result<PtyHandle> {
        let channel = conn.open_channel().await?;
        channel
            .request_pty(true, "xterm-256color", cols as u32, rows as u32, 0, 0, &[])
            .await
            .map_err(|e| ConnectorError::internal(format!("request_pty: {e}")))?;
        channel
            .request_shell(true)
            .await
            .map_err(|e| ConnectorError::internal(format!("request_shell: {e}")))?;

        let created_at = now_rfc3339();
        let state = Arc::new(Mutex::new(PtyState {
            emulator: TerminalEmulator::new(rows, cols),
            text_tail: String::new(),
            last_activity: Instant::now(),
            closed: false,
            last_read_seq: 0,
        }));
        let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel::<PtyCmd>(64);
        let (raw_tx, _) = broadcast::channel::<Vec<u8>>(256);

        let handle = PtyHandle {
            session_id: session_id.clone(),
            host_id,
            created_at,
            rows: Arc::new(Mutex::new((rows, cols))),
            state: state.clone(),
            cmd_tx,
            raw_tx: raw_tx.clone(),
        };

        tokio::spawn(pty_actor(channel, state, cmd_rx, raw_tx));
        Ok(handle)
    }

    /// Map a semantic key to bytes and queue it as input.
    pub async fn send_key(handle: &PtyHandle, key: &KeyName) -> Result<()> {
        handle.input(key_to_bytes(key)).await
    }
}

impl PtyHandle {
    /// Queue raw input bytes to the remote.
    pub async fn input(&self, bytes: Vec<u8>) -> Result<()> {
        self.cmd_tx
            .send(PtyCmd::Input(bytes))
            .await
            .map_err(|_| ConnectorError::new(ErrorCode::Disconnected, "pty actor gone"))
    }

    /// Send text (UTF-8) as input.
    pub async fn send_text(&self, text: &str) -> Result<()> {
        self.input(text.as_bytes().to_vec()).await
    }

    /// Resize the PTY.
    pub async fn resize(&self, rows: u16, cols: u16) -> Result<()> {
        *self.rows.lock().await = (rows, cols);
        self.cmd_tx
            .send(PtyCmd::Resize { rows, cols })
            .await
            .map_err(|_| ConnectorError::new(ErrorCode::Disconnected, "pty actor gone"))
    }

    /// Current structured screen snapshot.
    pub async fn snapshot(&self) -> ScreenSnapshot {
        self.state.lock().await.emulator.snapshot()
    }

    /// Incremental text read since the last call: returns newly appended text.
    pub async fn read_new(&self) -> ReadResult {
        let mut st = self.state.lock().await;
        let seq = st.emulator.seq();
        // We approximate "new" as the full text tail when the caller hasn't read
        // since the last append; callers wanting precise diffs use snapshot.seq.
        let data = std::mem::take(&mut st.text_tail);
        let likely_waiting = guess_waiting(&data);
        st.last_read_seq = seq;
        ReadResult {
            data,
            seq,
            likely_waiting_input: likely_waiting,
            had_invalid_utf8: false,
        }
    }

    pub async fn is_closed(&self) -> bool {
        self.state.lock().await.closed
    }

    pub async fn idle_secs(&self) -> u64 {
        self.state.lock().await.last_activity.elapsed().as_secs()
    }

    pub async fn dims(&self) -> (u16, u16) {
        *self.rows.lock().await
    }

    /// Subscribe to the raw byte stream (Web-UI takeover).
    pub fn subscribe_raw(&self) -> broadcast::Receiver<Vec<u8>> {
        self.raw_tx.subscribe()
    }
}

/// Heuristic: output ends without a trailing newline and looks like a prompt.
fn guess_waiting(text: &str) -> bool {
    let t = text.trim_end_matches([' ', '\t']);
    let last = t.lines().last().unwrap_or("");
    last.ends_with("$ ")
        || last.ends_with("# ")
        || last.ends_with("> ")
        || last.ends_with('$')
        || last.ends_with('#')
        || last.to_lowercase().contains("password")
        || last.ends_with(": ")
}

async fn pty_actor(
    channel: russh::Channel<client::Msg>,
    state: Arc<Mutex<PtyState>>,
    mut cmd_rx: tokio::sync::mpsc::Receiver<PtyCmd>,
    raw_tx: broadcast::Sender<Vec<u8>>,
) {
    let mut channel = channel;
    loop {
        tokio::select! {
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(PtyCmd::Input(bytes)) => {
                        let _ = channel.data_bytes(bytes).await;
                        state.lock().await.last_activity = Instant::now();
                    }
                    Some(PtyCmd::Resize { rows, cols }) => {
                        let _ = channel.window_change(cols as u32, rows as u32, 0, 0).await;
                        state.lock().await.emulator.resize(rows, cols);
                    }
                    None => {
                        // All handles dropped; tear down.
                        let _ = channel.close().await;
                        break;
                    }
                }
            }
            msg = channel.wait() => {
                let Some(msg) = msg else {
                    state.lock().await.closed = true;
                    break;
                };
                match msg {
                    ChannelMsg::Data { ref data } => {
                        feed(&state, &raw_tx, data).await;
                    }
                    ChannelMsg::ExtendedData { ref data, .. } => {
                        feed(&state, &raw_tx, data).await;
                    }
                    ChannelMsg::Eof | ChannelMsg::Close => {
                        state.lock().await.closed = true;
                        break;
                    }
                    _ => {}
                }
            }
        }
    }
}

async fn feed(state: &Arc<Mutex<PtyState>>, raw_tx: &broadcast::Sender<Vec<u8>>, data: &[u8]) {
    let mut st = state.lock().await;
    st.emulator.process(data);
    let (chunk, _) = match std::str::from_utf8(data) {
        Ok(s) => (s.to_string(), false),
        Err(_) => (String::from_utf8_lossy(data).into_owned(), true),
    };
    st.text_tail.push_str(&chunk);
    trim_text_tail(&mut st.text_tail);
    st.last_activity = Instant::now();
    // Best-effort broadcast to any Web-UI subscribers.
    let _ = raw_tx.send(data.to_vec());
}

fn trim_text_tail(text: &mut String) {
    if text.len() <= TEXT_TAIL_CAP {
        return;
    }
    let mut cut = text.len() - TEXT_TAIL_CAP;
    while !text.is_char_boundary(cut) {
        cut += 1;
    }
    text.drain(..cut);
}

fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trims_multibyte_text_on_utf8_boundary() {
        let mut text = format!("prefix{}suffix", "中".repeat(TEXT_TAIL_CAP));
        trim_text_tail(&mut text);
        assert!(text.len() <= TEXT_TAIL_CAP);
        assert!(text.ends_with("suffix"));
        assert!(std::str::from_utf8(text.as_bytes()).is_ok());
    }
}
