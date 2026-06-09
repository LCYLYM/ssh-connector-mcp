//! MCP server: the AI-facing tool surface.
//!
//! Security invariant: tools here NEVER return credential plaintext. Host
//! creation/update accepts secrets (write-only), but every read path returns
//! redacted summaries. Credential reveal is exclusively a Web-UI (human) action
//! gated on the master password and is deliberately absent from this surface.
//!
//! Two transports share one tool router:
//! - `serve_http` mounts a Streamable-HTTP service into the daemon's axum app.
//! - `run_stdio_shim` is a thin stdio<->HTTP forwarder so editors that speak
//!   stdio MCP can reach a already-running daemon.

use crate::error::ConnectorError;
use crate::state::AppState;
use crate::types::{ExecPayload, HostSpec, KeyName};
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::{Json, Parameters};
use rmcp::model::{ServerCapabilities, ServerInfo};
use rmcp::{ErrorData, ServerHandler, tool, tool_handler, tool_router};
use schemars::JsonSchema;
use serde::Deserialize;
use std::sync::Arc;

fn err_to_mcp(e: ConnectorError) -> ErrorData {
    // Surface our structured error code + context as MCP error data so the AI
    // can branch on `code` (e.g. host_key_mismatch vs auth_failed).
    let data = serde_json::to_value(&e).ok();
    ErrorData::internal_error(e.message.clone(), data)
}

// --- Tool request types (AI-facing input schemas) ---

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AddHostRequest {
    #[serde(flatten)]
    pub spec: HostSpec,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct UpdateHostRequest {
    pub host_id: String,
    #[serde(flatten)]
    pub spec: HostSpec,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct HostIdRequest {
    pub host_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ExecRequest {
    pub host_id: String,
    /// Exactly one of argv / script / raw.
    #[serde(flatten)]
    pub payload: ExecPayload,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct OpenPtyRequest {
    pub host_id: String,
    #[serde(default = "default_rows")]
    pub rows: u16,
    #[serde(default = "default_cols")]
    pub cols: u16,
}

fn default_rows() -> u16 {
    24
}
fn default_cols() -> u16 {
    80
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SessionIdRequest {
    pub session_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SendTextRequest {
    pub session_id: String,
    pub text: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SendKeyRequest {
    pub session_id: String,
    pub key: KeyName,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ResizeRequest {
    pub session_id: String,
    pub rows: u16,
    pub cols: u16,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SftpListRequest {
    pub host_id: String,
    pub path: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SftpGetRequest {
    pub host_id: String,
    pub path: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SftpPutRequest {
    pub host_id: String,
    pub path: String,
    /// File content. Text is sent as-is (UTF-8).
    pub content: String,
}

/// The MCP tool server. Clones share one `Arc<AppState>`.
#[derive(Clone)]
pub struct McpServer {
    state: Arc<AppState>,
    tool_router: ToolRouter<Self>,
}

// --- Tool output types (need object-rooted JSON schemas for MCP) ---

use crate::types::{DirEntry, HostSummary, SessionInfo};

#[derive(Debug, serde::Serialize, JsonSchema)]
pub struct HostListResult {
    pub hosts: Vec<HostSummary>,
}

#[derive(Debug, serde::Serialize, JsonSchema)]
pub struct HostIdResult {
    pub host_id: String,
}

#[derive(Debug, serde::Serialize, JsonSchema)]
pub struct OkResult {
    pub ok: bool,
}

#[derive(Debug, serde::Serialize, JsonSchema)]
pub struct ConnectResult {
    pub status: String,
}

#[derive(Debug, serde::Serialize, JsonSchema)]
pub struct SessionListResult {
    pub sessions: Vec<SessionInfo>,
}

#[derive(Debug, serde::Serialize, JsonSchema)]
pub struct SftpListResult {
    pub entries: Vec<DirEntry>,
}

#[derive(Debug, serde::Serialize, JsonSchema)]
pub struct SftpGetResult {
    pub content: String,
    pub bytes: usize,
    pub had_invalid_utf8: bool,
}

impl McpServer {
    pub fn new(state: Arc<AppState>) -> Self {
        Self {
            state,
            tool_router: Self::tool_router(),
        }
    }
}

#[tool_router]
impl McpServer {
    #[tool(
        description = "List all configured hosts with connection status. Returns redacted summaries only — never credentials."
    )]
    async fn host_list(&self) -> Result<Json<HostListResult>, ErrorData> {
        let hosts = self.state.list_hosts().await.map_err(err_to_mcp)?;
        Ok(Json(HostListResult { hosts }))
    }

    #[tool(
        description = "Create a new host. Accepts credentials (password/private_key/keyboard_interactive) and optional jump hops; secrets are stored encrypted and are write-only to AI. Returns the new host_id."
    )]
    async fn host_add(
        &self,
        Parameters(req): Parameters<AddHostRequest>,
    ) -> Result<Json<HostIdResult>, ErrorData> {
        let host_id = self.state.add_host(req.spec).map_err(err_to_mcp)?;
        Ok(Json(HostIdResult { host_id }))
    }

    #[tool(description = "Update an existing host wholesale by host_id. Same shape as host_add.")]
    async fn host_update(
        &self,
        Parameters(req): Parameters<UpdateHostRequest>,
    ) -> Result<Json<OkResult>, ErrorData> {
        self.state
            .update_host(&req.host_id, req.spec)
            .map_err(err_to_mcp)?;
        Ok(Json(OkResult { ok: true }))
    }

    #[tool(description = "Delete a host and drop any live connection.")]
    async fn host_remove(
        &self,
        Parameters(req): Parameters<HostIdRequest>,
    ) -> Result<Json<OkResult>, ErrorData> {
        self.state
            .remove_host(&req.host_id)
            .await
            .map_err(err_to_mcp)?;
        Ok(Json(OkResult { ok: true }))
    }

    #[tool(
        description = "Open/establish the SSH transport to a host (runs the full jump chain and host-key TOFU). Idempotent."
    )]
    async fn host_connect(
        &self,
        Parameters(req): Parameters<HostIdRequest>,
    ) -> Result<Json<ConnectResult>, ErrorData> {
        self.state
            .connect_host(&req.host_id)
            .await
            .map_err(err_to_mcp)?;
        Ok(Json(ConnectResult {
            status: "connected".into(),
        }))
    }

    #[tool(
        description = "Run a one-shot command and wait for it to finish. Choose exactly one payload: `argv` (array, auto-quoted — preferred), `script` (multi-line, uploaded and run as a file), or `raw` (you own all quoting). Returns stdout/stderr/exit_code with truncation and timeout flags."
    )]
    async fn exec(
        &self,
        Parameters(req): Parameters<ExecRequest>,
    ) -> Result<Json<crate::types::ExecResult>, ErrorData> {
        let r = self
            .state
            .exec(&req.host_id, &req.payload)
            .await
            .map_err(err_to_mcp)?;
        Ok(Json(r))
    }

    #[tool(
        description = "Open a persistent interactive PTY session (stateful shell) on a host. Returns session metadata including session_id."
    )]
    async fn session_open(
        &self,
        Parameters(req): Parameters<OpenPtyRequest>,
    ) -> Result<Json<crate::types::SessionInfo>, ErrorData> {
        let info = self
            .state
            .open_pty(&req.host_id, req.rows, req.cols)
            .await
            .map_err(err_to_mcp)?;
        Ok(Json(info))
    }

    #[tool(description = "List all live PTY sessions with idle TTL remaining.")]
    async fn session_list(&self) -> Result<Json<SessionListResult>, ErrorData> {
        let sessions = self.state.list_sessions().await;
        Ok(Json(SessionListResult { sessions }))
    }

    #[tool(
        description = "Send literal text to a PTY session's stdin (no implicit newline — include \\n or use a key to submit)."
    )]
    async fn session_send_text(
        &self,
        Parameters(req): Parameters<SendTextRequest>,
    ) -> Result<Json<OkResult>, ErrorData> {
        self.state
            .pty_send_text(&req.session_id, &req.text)
            .await
            .map_err(err_to_mcp)?;
        Ok(Json(OkResult { ok: true }))
    }

    #[tool(
        description = "Send a semantic key (enter, tab, up, ctrl_c, f(n), etc.) to a PTY session."
    )]
    async fn session_send_key(
        &self,
        Parameters(req): Parameters<SendKeyRequest>,
    ) -> Result<Json<OkResult>, ErrorData> {
        self.state
            .pty_send_key(&req.session_id, &req.key)
            .await
            .map_err(err_to_mcp)?;
        Ok(Json(OkResult { ok: true }))
    }

    #[tool(
        description = "Get a structured snapshot of a PTY session's current screen (rows of text, cursor, attributes, alt-screen flag, seq)."
    )]
    async fn session_screen(
        &self,
        Parameters(req): Parameters<SessionIdRequest>,
    ) -> Result<Json<crate::types::ScreenSnapshot>, ErrorData> {
        let snap = self
            .state
            .pty_snapshot(&req.session_id)
            .await
            .map_err(err_to_mcp)?;
        Ok(Json(snap))
    }

    #[tool(
        description = "Read newly produced text from a PTY session since the last read. Includes a heuristic likely_waiting_input flag."
    )]
    async fn session_read(
        &self,
        Parameters(req): Parameters<SessionIdRequest>,
    ) -> Result<Json<crate::types::ReadResult>, ErrorData> {
        let r = self
            .state
            .pty_read(&req.session_id)
            .await
            .map_err(err_to_mcp)?;
        Ok(Json(r))
    }

    #[tool(description = "Resize a PTY session's terminal.")]
    async fn session_resize(
        &self,
        Parameters(req): Parameters<ResizeRequest>,
    ) -> Result<Json<OkResult>, ErrorData> {
        self.state
            .pty_resize(&req.session_id, req.rows, req.cols)
            .await
            .map_err(err_to_mcp)?;
        Ok(Json(OkResult { ok: true }))
    }

    #[tool(description = "Close a PTY session and free its channel.")]
    async fn session_close(
        &self,
        Parameters(req): Parameters<SessionIdRequest>,
    ) -> Result<Json<OkResult>, ErrorData> {
        self.state
            .close_pty(&req.session_id)
            .await
            .map_err(err_to_mcp)?;
        Ok(Json(OkResult { ok: true }))
    }

    #[tool(description = "List a remote directory over SFTP.")]
    async fn sftp_list(
        &self,
        Parameters(req): Parameters<SftpListRequest>,
    ) -> Result<Json<SftpListResult>, ErrorData> {
        let entries = self
            .state
            .sftp_list(&req.host_id, &req.path)
            .await
            .map_err(err_to_mcp)?;
        Ok(Json(SftpListResult { entries }))
    }

    #[tool(
        description = "Read a remote text file over SFTP. Returns content as a UTF-8 string (invalid bytes are flagged)."
    )]
    async fn sftp_get(
        &self,
        Parameters(req): Parameters<SftpGetRequest>,
    ) -> Result<Json<SftpGetResult>, ErrorData> {
        let bytes = self
            .state
            .sftp_get(&req.host_id, &req.path)
            .await
            .map_err(err_to_mcp)?;
        let (content, had_invalid_utf8) = match std::str::from_utf8(&bytes) {
            Ok(s) => (s.to_string(), false),
            Err(_) => (String::from_utf8_lossy(&bytes).into_owned(), true),
        };
        Ok(Json(SftpGetResult {
            content,
            bytes: bytes.len(),
            had_invalid_utf8,
        }))
    }

    #[tool(description = "Write a remote file over SFTP (overwrites).")]
    async fn sftp_put(
        &self,
        Parameters(req): Parameters<SftpPutRequest>,
    ) -> Result<Json<OkResult>, ErrorData> {
        self.state
            .sftp_put(&req.host_id, &req.path, req.content.as_bytes())
            .await
            .map_err(err_to_mcp)?;
        Ok(Json(OkResult { ok: true }))
    }
}

#[tool_handler]
impl ServerHandler for McpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build()).with_instructions(
            "SSH maintenance connector. When the user asks to operate SSH hosts, remote Linux \
             machines, VPS instances, or server-side files and commands that are available in this \
             connector, prefer these MCP tools over spawning local `ssh`, `scp`, or `sftp` shell \
             commands. Start with `host_list` to discover configured hosts and connection state; \
             use `host_connect` only when an explicit connection check is needed because `exec`, \
             PTY, and SFTP operations connect on demand. Hosts and credentials are managed by a \
             human via a separate Web UI; you can create/update hosts and reference them by \
             host_id, but you can never read stored credentials. Prefer `exec` with the `argv` \
             payload for one-shot commands because it is auto-quoted. Use `script` for multi-line \
             non-interactive work, `raw` only when you intentionally own shell quoting, \
             `session_open` for stateful interactive work (editors, REPLs, prompts), and SFTP tools \
             for remote file transfer.",
        )
    }
}

use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};

/// Build a Streamable-HTTP MCP service that the daemon mounts under `/mcp`.
/// Each connection gets a fresh `McpServer` sharing the same `AppState`.
pub fn build_http_service(
    state: Arc<AppState>,
) -> StreamableHttpService<McpServer, LocalSessionManager> {
    StreamableHttpService::new(
        move || Ok(McpServer::new(state.clone())),
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default(),
    )
}

/// Serve the MCP tool surface over stdio (for editors that speak stdio MCP).
/// Spins up its own full `AppState`; runs until the client disconnects.
pub async fn serve_stdio(state: Arc<AppState>) -> anyhow::Result<()> {
    use rmcp::ServiceExt;
    use rmcp::transport::stdio;
    let service = McpServer::new(state).serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
