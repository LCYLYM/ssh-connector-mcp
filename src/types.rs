//! Shared domain types — the frozen contract every module builds against.

use serde::{Deserialize, Serialize};

/// How to authenticate to a host. Secrets are write-only toward AI: when a
/// config is serialized for an AI-facing response, secret-bearing variants are
/// redacted via [`AuthMethod::redacted`].
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuthMethod {
    Password {
        password: String,
    },
    /// PEM/OpenSSH private key material plus optional passphrase.
    PrivateKey {
        key_pem: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        passphrase: Option<String>,
    },
    /// Server-driven keyboard-interactive; answers are tried in order against
    /// successive prompts. Useful for simple OTP/2FA flows.
    KeyboardInteractive {
        answers: Vec<String>,
    },
}

impl AuthMethod {
    /// Produce an AI-safe copy with all secret material replaced by `***`.
    pub fn redacted(&self) -> AuthMethod {
        match self {
            AuthMethod::Password { .. } => AuthMethod::Password {
                password: "***".into(),
            },
            AuthMethod::PrivateKey { passphrase, .. } => AuthMethod::PrivateKey {
                key_pem: "***".into(),
                passphrase: passphrase.as_ref().map(|_| "***".into()),
            },
            AuthMethod::KeyboardInteractive { answers } => AuthMethod::KeyboardInteractive {
                answers: answers.iter().map(|_| "***".into()).collect(),
            },
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            AuthMethod::Password { .. } => "password",
            AuthMethod::PrivateKey { .. } => "private_key",
            AuthMethod::KeyboardInteractive { .. } => "keyboard_interactive",
        }
    }
}

/// One hop in a jump chain. Each hop authenticates independently.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct JumpHop {
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    pub user: String,
    pub auth: AuthMethod,
}

fn default_port() -> u16 {
    22
}

/// A managed host. `id` is assigned by the vault; everything except secrets is
/// AI-readable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostConfig {
    pub id: String,
    pub alias: String,
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    pub user: String,
    pub auth: AuthMethod,
    #[serde(default)]
    pub jump_hosts: Vec<JumpHop>,
    /// Extra environment to set on interactive sessions.
    #[serde(default)]
    pub env: std::collections::BTreeMap<String, String>,
}

impl HostConfig {
    /// AI-facing view: secrets redacted on the final auth and every hop.
    pub fn redacted(&self) -> HostConfig {
        let mut c = self.clone();
        c.auth = c.auth.redacted();
        for h in &mut c.jump_hosts {
            h.auth = h.auth.redacted();
        }
        c
    }
}

/// Input shape for creating/updating a host (no server-assigned id).
#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct HostSpec {
    pub alias: String,
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    pub user: String,
    pub auth: AuthMethod,
    #[serde(default)]
    pub jump_hosts: Vec<JumpHop>,
    #[serde(default)]
    pub env: std::collections::BTreeMap<String, String>,
}

/// Connection state of a host's transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HostStatus {
    Connected,
    Disconnected,
    Connecting,
}

/// AI-facing host summary (returned by host_list).
#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct HostSummary {
    pub host_id: String,
    pub alias: String,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub auth_kind: String,
    pub jump_count: usize,
    pub status: HostStatus,
}

impl HostSummary {
    pub fn from_config(c: &HostConfig, status: HostStatus) -> Self {
        Self {
            host_id: c.id.clone(),
            alias: c.alias.clone(),
            host: c.host.clone(),
            port: c.port,
            user: c.user.clone(),
            auth_kind: c.auth.kind().to_string(),
            jump_count: c.jump_hosts.len(),
            status,
        }
    }
}

/// Kind of live session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SessionKind {
    Pty,
}

/// Live PTY session metadata.
#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct SessionInfo {
    pub session_id: String,
    pub host_id: String,
    pub kind: SessionKind,
    pub created_at: String,
    pub idle_ttl_left_secs: Option<u64>,
    pub rows: u16,
    pub cols: u16,
}

/// How a one-shot command is delivered to the remote. Exactly one of the three
/// payload variants is chosen by the caller; this is what eliminates the whole
/// class of quoting bugs (see design doc §2.1).
#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecPayload {
    /// argv array; connector applies POSIX single-quote escaping internally.
    Argv { argv: Vec<String> },
    /// multi-line script uploaded via SFTP and executed as a file.
    Script { script: String },
    /// raw command string passed straight to the remote login shell (escape
    /// hatch; caller owns all quoting).
    Raw { raw: String },
}

/// Result of a one-shot exec.
#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct ExecResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<i32>,
    pub duration_ms: u64,
    /// True if either stream hit the byte cap and was truncated.
    pub truncated: bool,
    /// True if the deadline was hit and the channel was killed.
    pub timed_out: bool,
    /// True if invalid UTF-8 was seen and replaced with U+FFFD.
    pub had_invalid_utf8: bool,
}

/// A single cell attribute span on a screen row (for highlighting/inverse).
#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct AttrSpan {
    pub row: u16,
    pub col_start: u16,
    pub col_end: u16,
    pub inverse: bool,
    pub bold: bool,
}

/// Structured terminal screen snapshot handed to the AI instead of raw ANSI.
#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct ScreenSnapshot {
    pub rows: u16,
    pub cols: u16,
    pub cursor_row: u16,
    pub cursor_col: u16,
    pub cursor_visible: bool,
    /// One string per screen row, already rendered to plain text.
    pub screen: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub attrs: Vec<AttrSpan>,
    /// True when the remote is on the alternate screen (vim/htop/etc).
    pub alt_screen: bool,
    /// Monotonic sequence number, increments on every processed byte chunk.
    pub seq: u64,
}

/// Incremental line-oriented read from a PTY session.
#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct ReadResult {
    pub data: String,
    pub seq: u64,
    /// Heuristic: remote appears to be waiting for input (prompt detected /
    /// output stalled). Advisory only.
    pub likely_waiting_input: bool,
    pub had_invalid_utf8: bool,
}

/// Directory entry for sftp_list.
#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct DirEntry {
    pub name: String,
    pub size: u64,
    pub mode: u32,
    pub mtime: u64,
    pub is_dir: bool,
}

/// Semantic key names accepted by session_send_key, mapped to ANSI internally.
#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum KeyName {
    Enter,
    Tab,
    Escape,
    Backspace,
    Up,
    Down,
    Left,
    Right,
    Home,
    End,
    PageUp,
    PageDown,
    Delete,
    CtrlC,
    CtrlD,
    CtrlZ,
    CtrlL,
    CtrlA,
    CtrlE,
    CtrlU,
    CtrlK,
    F(u8),
}
