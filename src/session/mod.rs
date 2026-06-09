//! Session manager: one-shot exec, persistent PTY sessions, and SFTP transfers.
//!
//! Quoting/encoding correctness (design doc §2) lives here:
//! - `ExecPayload::Argv` is escaped with POSIX single-quote rules so the AI
//!   never has to think about shell metacharacters.
//! - `ExecPayload::Script` is uploaded as a file via SFTP and run with the
//!   login shell, sidestepping quoting entirely for multi-line input.
//! - `ExecPayload::Raw` is the escape hatch; the caller owns all quoting.
//! - All byte streams are decoded as UTF-8 with lossy replacement and the
//!   `had_invalid_utf8` flag is surfaced so the AI knows when bytes were lost.

mod pty;

pub use pty::{PtyHandle, PtySession};

use crate::error::{ConnectorError, ErrorCode, Result};
use crate::ssh::{Connection, ConnectionPool};
use crate::types::{
    DirEntry, ExecPayload, ExecResult, ReadResult, ScreenSnapshot, SessionInfo, SessionKind,
};
use russh::ChannelMsg;
use russh_sftp::client::SftpSession;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

/// Escape one argument with POSIX single-quote rules: wrap in single quotes and
/// replace any embedded single quote with the `'\''` sequence.
pub fn posix_quote(arg: &str) -> String {
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('\'');
    for ch in arg.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

/// Join an argv vector into a single safely-quoted command line.
pub fn quote_argv(argv: &[String]) -> Result<String> {
    if argv.is_empty() {
        return Err(ConnectorError::bad_request("argv must not be empty"));
    }
    Ok(argv
        .iter()
        .map(|a| posix_quote(a))
        .collect::<Vec<_>>()
        .join(" "))
}

/// Decode bytes as UTF-8, replacing invalid sequences. Returns (string, had_invalid).
fn decode_utf8(bytes: &[u8]) -> (String, bool) {
    match std::str::from_utf8(bytes) {
        Ok(s) => (s.to_string(), false),
        Err(_) => (String::from_utf8_lossy(bytes).into_owned(), true),
    }
}

/// Configuration knobs passed from the daemon for exec behaviour.
#[derive(Clone, Copy)]
pub struct ExecLimits {
    pub timeout: Duration,
    pub output_cap_bytes: usize,
}

/// Run a one-shot command on a fresh channel and collect its result.
pub async fn exec(
    conn: &Connection,
    payload: &ExecPayload,
    limits: ExecLimits,
) -> Result<ExecResult> {
    let command = match payload {
        ExecPayload::Argv { argv } => quote_argv(argv)?,
        ExecPayload::Raw { raw } => raw.clone(),
        ExecPayload::Script { script } => {
            return exec_script(conn, script, limits).await;
        }
    };
    exec_command_line(conn, &command, limits).await
}

async fn exec_command_line(
    conn: &Connection,
    command: &str,
    limits: ExecLimits,
) -> Result<ExecResult> {
    let start = std::time::Instant::now();
    let channel = conn.open_channel().await?;
    channel
        .exec(true, command.as_bytes())
        .await
        .map_err(|e| ConnectorError::internal(format!("exec: {e}")))?;

    let mut stdout: Vec<u8> = Vec::new();
    let mut stderr: Vec<u8> = Vec::new();
    let mut exit_code: Option<i32> = None;
    let mut truncated = false;
    let mut timed_out = false;

    let mut channel = channel;
    let deadline = tokio::time::sleep(limits.timeout);
    tokio::pin!(deadline);

    loop {
        tokio::select! {
            _ = &mut deadline => {
                timed_out = true;
                let _ = channel.close().await;
                break;
            }
            msg = channel.wait() => {
                let Some(msg) = msg else { break };
                match msg {
                    ChannelMsg::Data { ref data } => {
                        if stdout.len() < limits.output_cap_bytes {
                            let room = limits.output_cap_bytes - stdout.len();
                            let take = room.min(data.len());
                            stdout.extend_from_slice(&data[..take]);
                            if take < data.len() { truncated = true; }
                        } else {
                            truncated = true;
                        }
                    }
                    ChannelMsg::ExtendedData { ref data, ext } => {
                        if ext == 1 {
                            if stderr.len() < limits.output_cap_bytes {
                                let room = limits.output_cap_bytes - stderr.len();
                                let take = room.min(data.len());
                                stderr.extend_from_slice(&data[..take]);
                                if take < data.len() { truncated = true; }
                            } else {
                                truncated = true;
                            }
                        }
                    }
                    ChannelMsg::ExitStatus { exit_status } => {
                        exit_code = Some(exit_status as i32);
                    }
                    ChannelMsg::Eof | ChannelMsg::Close => {
                        // Keep draining until wait() returns None for a clean close,
                        // but Close means we can stop.
                    }
                    _ => {}
                }
            }
        }
    }

    let (stdout_s, inv1) = decode_utf8(&stdout);
    let (stderr_s, inv2) = decode_utf8(&stderr);
    Ok(ExecResult {
        stdout: stdout_s,
        stderr: stderr_s,
        exit_code,
        duration_ms: start.elapsed().as_millis() as u64,
        truncated,
        timed_out,
        had_invalid_utf8: inv1 || inv2,
    })
}

/// Upload a script via SFTP to a temp path and execute it with `sh`.
async fn exec_script(conn: &Connection, script: &str, limits: ExecLimits) -> Result<ExecResult> {
    let sftp = open_sftp(conn).await?;
    let remote_path = format!("/tmp/.ssh-connector-{}.sh", gen_token());
    sftp_write_file(&sftp, &remote_path, script.as_bytes())
        .await
        .map_err(|e| ConnectorError::new(ErrorCode::SftpError, format!("upload script: {e}")))?;
    // Run then remove. Use sh explicitly; the path is single-quoted.
    let cmd = format!(
        "sh {0}; __rc=$?; rm -f {0}; exit $__rc",
        posix_quote(&remote_path)
    );
    let result = exec_command_line(conn, &cmd, limits).await;
    // Best-effort cleanup if exec failed before the inline rm.
    if result.is_err() {
        let _ = sftp.remove_file(remote_path.as_str()).await;
    }
    result
}

fn gen_token() -> String {
    let mut b = [0u8; 8];
    let _ = getrandom::fill(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Open an SFTP subsystem over a new channel on this connection.
pub async fn open_sftp(conn: &Connection) -> Result<SftpSession> {
    let channel = conn.open_channel().await?;
    channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(|e| ConnectorError::new(ErrorCode::SftpError, format!("request sftp: {e}")))?;
    SftpSession::new(channel.into_stream())
        .await
        .map_err(|e| ConnectorError::new(ErrorCode::SftpError, format!("sftp init: {e}")))
}

/// List a remote directory.
pub async fn sftp_list(conn: &Connection, path: &str) -> Result<Vec<DirEntry>> {
    let sftp = open_sftp(conn).await?;
    let rd = sftp
        .read_dir(path)
        .await
        .map_err(|e| ConnectorError::new(ErrorCode::SftpError, format!("read_dir: {e}")))?;
    let mut out = Vec::new();
    for entry in rd {
        let meta = entry.metadata();
        out.push(DirEntry {
            name: entry.file_name(),
            size: meta.size.unwrap_or(0),
            mode: meta.permissions.unwrap_or(0),
            mtime: meta.mtime.unwrap_or(0) as u64,
            is_dir: meta.is_dir(),
        });
    }
    Ok(out)
}

/// Read a remote file fully (capped).
pub async fn sftp_get(conn: &Connection, path: &str) -> Result<Vec<u8>> {
    let sftp = open_sftp(conn).await?;
    sftp.read(path)
        .await
        .map_err(|e| ConnectorError::new(ErrorCode::SftpError, format!("read: {e}")))
}

/// Write a remote file, creating or truncating it.
///
/// russh-sftp's `SftpSession::write` opens with `WRITE` only (no `CREATE`),
/// which fails with "No such file" on a new path. We open explicitly with
/// CREATE|TRUNCATE|WRITE and stream the bytes ourselves.
async fn sftp_write_file(sftp: &SftpSession, path: &str, data: &[u8]) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    let mut file = sftp
        .create(path)
        .await
        .map_err(|e| ConnectorError::new(ErrorCode::SftpError, format!("create: {e}")))?;
    file.write_all(data)
        .await
        .map_err(|e| ConnectorError::new(ErrorCode::SftpError, format!("write: {e}")))?;
    file.shutdown()
        .await
        .map_err(|e| ConnectorError::new(ErrorCode::SftpError, format!("flush: {e}")))?;
    Ok(())
}

/// Write a remote file (overwrites).
pub async fn sftp_put(conn: &Connection, path: &str, data: &[u8]) -> Result<()> {
    let sftp = open_sftp(conn).await?;
    sftp_write_file(&sftp, path, data).await
}

/// Owns live PTY sessions and bridges exec/sftp through the connection pool.
pub struct SessionManager {
    pool: Arc<ConnectionPool>,
    limits: ExecLimits,
    pty_idle_ttl: Duration,
    ptys: Mutex<HashMap<String, PtyHandle>>,
}

impl SessionManager {
    pub fn new(pool: Arc<ConnectionPool>, limits: ExecLimits, pty_idle_ttl: Duration) -> Arc<Self> {
        let mgr = Arc::new(Self {
            pool,
            limits,
            pty_idle_ttl,
            ptys: Mutex::new(HashMap::new()),
        });
        mgr.clone().spawn_reaper();
        mgr
    }

    /// Periodically drop closed or idle-expired PTY sessions.
    fn spawn_reaper(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(15));
            loop {
                tick.tick().await;
                let ttl = self.pty_idle_ttl.as_secs();
                let mut dead = Vec::new();
                {
                    let map = self.ptys.lock().await;
                    for (id, h) in map.iter() {
                        let expired = ttl > 0 && h.idle_secs().await >= ttl;
                        if h.is_closed().await || expired {
                            dead.push(id.clone());
                        }
                    }
                }
                if !dead.is_empty() {
                    let mut map = self.ptys.lock().await;
                    for id in dead {
                        map.remove(&id);
                    }
                }
            }
        });
    }

    fn gen_session_id() -> String {
        format!("s-{}", gen_token())
    }

    /// Run a one-shot command on a host (connecting on demand).
    pub async fn exec(&self, host_id: &str, payload: &ExecPayload) -> Result<ExecResult> {
        let conn = self.pool.get_or_connect(host_id).await?;
        exec(&conn, payload, self.limits).await
    }

    /// Open a new persistent PTY session on a host.
    pub async fn open_pty(&self, host_id: &str, rows: u16, cols: u16) -> Result<SessionInfo> {
        let conn = self.pool.get_or_connect(host_id).await?;
        let id = Self::gen_session_id();
        let handle = PtySession::open(&conn, id.clone(), host_id.to_string(), rows, cols).await?;
        let info = self.info_for(&handle).await;
        self.ptys.lock().await.insert(id, handle);
        Ok(info)
    }

    async fn get_pty(&self, session_id: &str) -> Result<PtyHandle> {
        self.ptys
            .lock()
            .await
            .get(session_id)
            .cloned()
            .ok_or_else(|| ConnectorError::session_not_found(session_id))
    }

    pub async fn pty_send_text(&self, session_id: &str, text: &str) -> Result<()> {
        self.get_pty(session_id).await?.send_text(text).await
    }

    pub async fn pty_send_key(&self, session_id: &str, key: &crate::types::KeyName) -> Result<()> {
        let h = self.get_pty(session_id).await?;
        PtySession::send_key(&h, key).await
    }

    pub async fn pty_snapshot(&self, session_id: &str) -> Result<ScreenSnapshot> {
        Ok(self.get_pty(session_id).await?.snapshot().await)
    }

    pub async fn pty_read(&self, session_id: &str) -> Result<ReadResult> {
        Ok(self.get_pty(session_id).await?.read_new().await)
    }

    pub async fn pty_resize(&self, session_id: &str, rows: u16, cols: u16) -> Result<()> {
        self.get_pty(session_id).await?.resize(rows, cols).await
    }

    /// Subscribe to a session's raw byte stream (Web-UI takeover).
    pub async fn pty_subscribe(
        &self,
        session_id: &str,
    ) -> Result<tokio::sync::broadcast::Receiver<Vec<u8>>> {
        Ok(self.get_pty(session_id).await?.subscribe_raw())
    }

    pub async fn pty_input(&self, session_id: &str, bytes: Vec<u8>) -> Result<()> {
        self.get_pty(session_id).await?.input(bytes).await
    }

    pub async fn close_pty(&self, session_id: &str) -> Result<()> {
        let removed = self.ptys.lock().await.remove(session_id);
        match removed {
            // Dropping the handle drops its cmd_tx; once all senders are gone the
            // actor closes the channel. We send a final close intent by dropping.
            Some(_) => Ok(()),
            None => Err(ConnectorError::session_not_found(session_id)),
        }
    }

    pub async fn list_sessions(&self) -> Vec<SessionInfo> {
        let map = self.ptys.lock().await;
        let mut out = Vec::with_capacity(map.len());
        for h in map.values() {
            out.push(self.info_for(h).await);
        }
        out
    }

    async fn info_for(&self, h: &PtyHandle) -> SessionInfo {
        let (rows, cols) = h.dims().await;
        let ttl = self.pty_idle_ttl.as_secs();
        let idle_left = if ttl > 0 {
            Some(ttl.saturating_sub(h.idle_secs().await))
        } else {
            None
        };
        SessionInfo {
            session_id: h.session_id.clone(),
            host_id: h.host_id.clone(),
            kind: SessionKind::Pty,
            created_at: h.created_at.clone(),
            idle_ttl_left_secs: idle_left,
            rows,
            cols,
        }
    }

    // --- SFTP passthrough ---

    pub async fn sftp_list(&self, host_id: &str, path: &str) -> Result<Vec<DirEntry>> {
        let conn = self.pool.get_or_connect(host_id).await?;
        sftp_list(&conn, path).await
    }

    pub async fn sftp_get(&self, host_id: &str, path: &str) -> Result<Vec<u8>> {
        let conn = self.pool.get_or_connect(host_id).await?;
        sftp_get(&conn, path).await
    }

    pub async fn sftp_put(&self, host_id: &str, path: &str, data: &[u8]) -> Result<()> {
        let conn = self.pool.get_or_connect(host_id).await?;
        sftp_put(&conn, path, data).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn posix_quote_plain() {
        assert_eq!(posix_quote("hello"), "'hello'");
    }

    #[test]
    fn posix_quote_with_single_quote() {
        // it's -> 'it'\''s'
        assert_eq!(posix_quote("it's"), "'it'\\''s'");
    }

    #[test]
    fn posix_quote_with_spaces_and_meta() {
        assert_eq!(posix_quote("a b; rm -rf /"), "'a b; rm -rf /'");
        assert_eq!(posix_quote("$(whoami)"), "'$(whoami)'");
        assert_eq!(posix_quote("`id`"), "'`id`'");
    }

    #[test]
    fn quote_argv_joins() {
        let argv = vec![
            "echo".to_string(),
            "hello world".to_string(),
            "a'b".to_string(),
        ];
        assert_eq!(quote_argv(&argv).unwrap(), "'echo' 'hello world' 'a'\\''b'");
    }

    #[test]
    fn quote_argv_empty_errs() {
        assert!(quote_argv(&[]).is_err());
    }

    #[test]
    fn decode_utf8_valid_and_invalid() {
        let (s, inv) = decode_utf8("héllo".as_bytes());
        assert_eq!(s, "héllo");
        assert!(!inv);
        let (s2, inv2) = decode_utf8(&[0xff, 0xfe, 0x41]);
        assert!(inv2);
        assert!(s2.contains('A'));
    }
}
