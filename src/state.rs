//! Shared application state: the single source of truth wired into both the MCP
//! server (AI-facing) and the Web UI (human-facing). Credential boundaries are
//! enforced here — AI paths only ever see redacted host data.

use crate::audit::AuditLog;
use crate::config::Config;
use crate::error::Result;
use crate::session::{ExecLimits, SessionManager};
use crate::ssh::ConnectionPool;
use crate::types::{
    DirEntry, ExecPayload, ExecResult, HostSpec, HostStatus, HostSummary, KeyName, ReadResult,
    ScreenSnapshot, SessionInfo,
};
use crate::vault::Vault;
use std::sync::Arc;
use std::time::Duration;

pub struct AppState {
    pub vault: Arc<Vault>,
    pub pool: Arc<ConnectionPool>,
    pub sessions: Arc<SessionManager>,
    pub audit: Arc<AuditLog>,
    pub config: Config,
    /// Loopback bearer token shared with the local MCP stdio shim.
    pub local_token: String,
}

impl AppState {
    pub fn new(
        vault: Arc<Vault>,
        audit: Arc<AuditLog>,
        config: Config,
        local_token: String,
    ) -> Arc<Self> {
        let pool = Arc::new(ConnectionPool::new(vault.clone(), config.keepalive_secs));
        let limits = ExecLimits {
            timeout: Duration::from_millis(config.exec_timeout_ms),
            output_cap_bytes: config.exec_output_cap_bytes,
        };
        let sessions = SessionManager::new(
            pool.clone(),
            limits,
            Duration::from_secs(config.pty_idle_ttl_secs),
        );
        Arc::new(Self {
            vault,
            pool,
            sessions,
            audit,
            config,
            local_token,
        })
    }

    // --- Host management (AI may create/update; reads are redacted) ---

    pub fn add_host(&self, spec: HostSpec) -> Result<String> {
        let id = self.vault.add_host(spec)?;
        self.audit
            .record(AuditLog::entry("host_add").with_host(&id));
        Ok(id)
    }

    pub fn update_host(&self, id: &str, spec: HostSpec) -> Result<()> {
        self.vault.update_host(id, spec)?;
        self.audit
            .record(AuditLog::entry("host_update").with_host(id));
        Ok(())
    }

    pub async fn remove_host(&self, id: &str) -> Result<()> {
        self.pool.disconnect(id).await;
        self.vault.remove_host(id)?;
        self.audit
            .record(AuditLog::entry("host_remove").with_host(id));
        Ok(())
    }

    /// AI-facing host list: summaries only, never secrets.
    pub async fn list_hosts(&self) -> Result<Vec<HostSummary>> {
        let configs = self.vault.list_host_configs()?;
        let mut out = Vec::with_capacity(configs.len());
        for c in &configs {
            let status = self.pool.status(&c.id).await;
            out.push(HostSummary::from_config(c, status));
        }
        Ok(out)
    }

    pub async fn host_status(&self, id: &str) -> HostStatus {
        self.pool.status(id).await
    }

    pub async fn connect_host(&self, id: &str) -> Result<()> {
        self.pool.connect(id).await?;
        self.audit
            .record(AuditLog::entry("host_connect").with_host(id));
        Ok(())
    }

    // --- Exec / PTY / SFTP (delegated to the session manager) ---

    pub async fn exec(&self, host_id: &str, payload: &ExecPayload) -> Result<ExecResult> {
        let r = self.sessions.exec(host_id, payload).await?;
        self.audit.record(
            AuditLog::entry("exec")
                .with_host(host_id)
                .with_exit(r.exit_code),
        );
        Ok(r)
    }

    pub async fn open_pty(&self, host_id: &str, rows: u16, cols: u16) -> Result<SessionInfo> {
        let info = self.sessions.open_pty(host_id, rows, cols).await?;
        self.audit.record(
            AuditLog::entry("pty_open")
                .with_host(host_id)
                .with_session(&info.session_id),
        );
        Ok(info)
    }

    pub async fn pty_send_text(&self, session_id: &str, text: &str) -> Result<()> {
        self.sessions.pty_send_text(session_id, text).await
    }

    pub async fn pty_send_key(&self, session_id: &str, key: &KeyName) -> Result<()> {
        self.sessions.pty_send_key(session_id, key).await
    }

    pub async fn pty_snapshot(&self, session_id: &str) -> Result<ScreenSnapshot> {
        self.sessions.pty_snapshot(session_id).await
    }

    pub async fn pty_read(&self, session_id: &str) -> Result<ReadResult> {
        self.sessions.pty_read(session_id).await
    }

    pub async fn pty_resize(&self, session_id: &str, rows: u16, cols: u16) -> Result<()> {
        self.sessions.pty_resize(session_id, rows, cols).await
    }

    pub async fn close_pty(&self, session_id: &str) -> Result<()> {
        self.sessions.close_pty(session_id).await?;
        self.audit
            .record(AuditLog::entry("pty_close").with_session(session_id));
        Ok(())
    }

    pub async fn list_sessions(&self) -> Vec<SessionInfo> {
        self.sessions.list_sessions().await
    }

    /// Raw stdin from a Web-UI terminal takeover (bypasses audit-per-keystroke).
    pub async fn pty_input_ws(&self, session_id: &str, bytes: Vec<u8>) -> Result<()> {
        self.sessions.pty_input(session_id, bytes).await
    }

    pub async fn sftp_list(&self, host_id: &str, path: &str) -> Result<Vec<DirEntry>> {
        self.sessions.sftp_list(host_id, path).await
    }

    pub async fn sftp_get(&self, host_id: &str, path: &str) -> Result<Vec<u8>> {
        let d = self.sessions.sftp_get(host_id, path).await?;
        self.audit
            .record(AuditLog::entry("sftp_get").with_host(host_id));
        Ok(d)
    }

    pub async fn sftp_put(&self, host_id: &str, path: &str, data: &[u8]) -> Result<()> {
        self.sessions.sftp_put(host_id, path, data).await?;
        self.audit
            .record(AuditLog::entry("sftp_put").with_host(host_id));
        Ok(())
    }
}
