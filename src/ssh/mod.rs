//! SSH connection layer: client handler, authentication (password / private key
//! / keyboard-interactive), multi-hop jump chains, host-key TOFU, and a
//! connection pool of one live transport per host.

#![allow(clippy::type_complexity)]

use crate::error::{ConnectorError, ErrorCode, Result};
use crate::types::{AuthMethod, HostConfig, HostStatus};
use crate::vault::Vault;
use russh::client::{self, Handle, KeyboardInteractiveAuthResponse};
use russh::keys::{HashAlg, PrivateKey, PrivateKeyWithHashAlg};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Per-connection client handler. Enforces host-key TOFU against the vault.
struct ClientHandler {
    vault: Arc<Vault>,
    /// host:port label this transport is connecting to (the final hop).
    host: String,
    port: u16,
}

impl client::Handler for ClientHandler {
    type Error = ConnectorError;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::ssh_key::PublicKey,
    ) -> std::result::Result<bool, Self::Error> {
        let fp = server_public_key.fingerprint(HashAlg::Sha256).to_string();
        match self.vault.get_host_key(&self.host, self.port)? {
            Some(known) => {
                if known == fp {
                    Ok(true)
                } else {
                    Err(ConnectorError::new(
                        ErrorCode::HostKeyMismatch,
                        format!(
                            "host key for {}:{} changed (known {known}, got {fp}); refusing to connect",
                            self.host, self.port
                        ),
                    ))
                }
            }
            None => {
                // TOFU: record on first sight and accept.
                self.vault.record_host_key(&self.host, self.port, &fp)?;
                Ok(true)
            }
        }
    }
}

fn client_config(keepalive_secs: u64) -> Arc<client::Config> {
    let mut cfg = client::Config::default();
    if keepalive_secs > 0 {
        cfg.keepalive_interval = Some(std::time::Duration::from_secs(keepalive_secs));
    }
    Arc::new(cfg)
}

/// Parse a private key from PEM, decrypting with the passphrase if needed.
fn load_private_key(key_pem: &str, passphrase: Option<&str>) -> Result<PrivateKey> {
    let key = PrivateKey::from_openssh(key_pem)
        .map_err(|e| ConnectorError::new(ErrorCode::AuthFailed, format!("bad private key: {e}")))?;
    if key.is_encrypted() {
        let pass = passphrase.ok_or_else(|| {
            ConnectorError::new(
                ErrorCode::AuthFailed,
                "private key is encrypted but no passphrase given",
            )
        })?;
        key.decrypt(pass).map_err(|e| {
            ConnectorError::new(ErrorCode::AuthFailed, format!("wrong passphrase: {e}"))
        })
    } else {
        Ok(key)
    }
}

/// Run the configured authentication method against an open handle.
async fn authenticate(
    handle: &mut Handle<ClientHandler>,
    user: &str,
    auth: &AuthMethod,
) -> Result<()> {
    let ok = match auth {
        AuthMethod::Password { password } => handle
            .authenticate_password(user, password)
            .await?
            .success(),
        AuthMethod::PrivateKey {
            key_pem,
            passphrase,
        } => {
            let key = load_private_key(key_pem, passphrase.as_deref())?;
            // Prefer SHA-256 for RSA; ignored for other key types.
            let kwh = PrivateKeyWithHashAlg::new(Arc::new(key), Some(HashAlg::Sha256));
            handle.authenticate_publickey(user, kwh).await?.success()
        }
        AuthMethod::KeyboardInteractive { answers } => {
            authenticate_keyboard_interactive(handle, user, answers).await?
        }
    };
    if ok {
        Ok(())
    } else {
        Err(ConnectorError::new(
            ErrorCode::AuthFailed,
            format!("authentication failed for user {user}"),
        ))
    }
}

async fn authenticate_keyboard_interactive(
    handle: &mut Handle<ClientHandler>,
    user: &str,
    answers: &[String],
) -> Result<bool> {
    let mut resp = handle
        .authenticate_keyboard_interactive_start(user, None)
        .await?;
    let mut idx = 0usize;
    loop {
        match resp {
            KeyboardInteractiveAuthResponse::Success => return Ok(true),
            KeyboardInteractiveAuthResponse::Failure { .. } => return Ok(false),
            KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
                // Answer each prompt from the configured answer list in order.
                let mut replies = Vec::with_capacity(prompts.len());
                for _ in &prompts {
                    let a = answers.get(idx).cloned().unwrap_or_default();
                    idx += 1;
                    replies.push(a);
                }
                resp = handle
                    .authenticate_keyboard_interactive_respond(replies)
                    .await?;
            }
        }
    }
}

/// A live transport to a host (final hop authenticated), plus its config snapshot.
pub struct Connection {
    pub handle: Handle<ClientHandler>,
    pub host_id: String,
}

impl Connection {
    /// Open a new session channel for exec/pty/sftp.
    pub async fn open_channel(&self) -> Result<russh::Channel<client::Msg>> {
        self.handle
            .channel_open_session()
            .await
            .map_err(|e| ConnectorError::new(ErrorCode::Disconnected, format!("open channel: {e}")))
    }
}

/// Establish a transport to the final target, tunnelling through any jump hops.
///
/// For each hop we open a direct-tcpip channel on the previous handle to the
/// next hop's address, then run a fresh SSH client over that channel's stream
/// (`connect_stream`). The last hop is the real target.
async fn establish(
    vault: &Arc<Vault>,
    cfg: &HostConfig,
    keepalive_secs: u64,
) -> Result<Handle<ClientHandler>> {
    // Build the ordered list of (host, port, user, auth) ending at the target.
    let mut chain: Vec<(&str, u16, &str, &AuthMethod)> = Vec::new();
    for hop in &cfg.jump_hosts {
        chain.push((&hop.host, hop.port, &hop.user, &hop.auth));
    }
    chain.push((&cfg.host, cfg.port, &cfg.user, &cfg.auth));

    // First hop: direct TCP connect.
    let (first_host, first_port, first_user, first_auth) = chain[0];
    let handler = ClientHandler {
        vault: vault.clone(),
        host: first_host.to_string(),
        port: first_port,
    };
    let mut handle = client::connect(
        client_config(keepalive_secs),
        (first_host, first_port),
        handler,
    )
    .await
    .map_err(|e| map_hop_error(0, first_host, e.into()))?;
    authenticate(&mut handle, first_user, first_auth)
        .await
        .map_err(|e| map_hop_error(0, first_host, e))?;

    // Subsequent hops: tunnel through the previous handle.
    for (i, &(host, port, user, auth)) in chain.iter().enumerate().skip(1) {
        let channel = handle
            .channel_open_direct_tcpip(host, port as u32, "127.0.0.1", 0)
            .await
            .map_err(|e| map_hop_error(i, host, e.into()))?;
        let handler = ClientHandler {
            vault: vault.clone(),
            host: host.to_string(),
            port,
        };
        let mut next = client::connect_stream(
            client_config(keepalive_secs),
            channel.into_stream(),
            handler,
        )
        .await
        .map_err(|e| map_hop_error(i, host, e))?;
        authenticate(&mut next, user, auth)
            .await
            .map_err(|e| map_hop_error(i, host, e))?;
        handle = next;
    }

    Ok(handle)
}

fn map_hop_error(hop_index: usize, host: &str, e: ConnectorError) -> ConnectorError {
    // Final hop keeps its native code (auth_failed/host_key_mismatch); intermediate
    // hops are wrapped as jump_failed_at_hop with the index.
    let ctx = serde_json::json!({ "hop_index": hop_index, "host": host });
    if hop_index == 0 {
        // Could be the only hop (no jumps) — keep specific code if it's auth/hostkey.
        match e.code {
            ErrorCode::AuthFailed | ErrorCode::HostKeyMismatch => e.with_context(ctx),
            _ => e.with_context(ctx),
        }
    } else {
        ConnectorError::new(
            ErrorCode::JumpFailedAtHop,
            format!("jump hop {hop_index} ({host}) failed: {e}"),
        )
        .with_context(ctx)
    }
}

/// Pool of live connections, one per host id.
pub struct ConnectionPool {
    vault: Arc<Vault>,
    keepalive_secs: u64,
    conns: Mutex<HashMap<String, Arc<Connection>>>,
}

impl ConnectionPool {
    pub fn new(vault: Arc<Vault>, keepalive_secs: u64) -> Self {
        Self {
            vault,
            keepalive_secs,
            conns: Mutex::new(HashMap::new()),
        }
    }

    /// Current status of a host's transport.
    pub async fn status(&self, host_id: &str) -> HostStatus {
        let guard = self.conns.lock().await;
        match guard.get(host_id) {
            Some(c) if !c.handle.is_closed() => HostStatus::Connected,
            _ => HostStatus::Disconnected,
        }
    }

    /// Connect (or reconnect) a host. Replaces any existing dead handle.
    pub async fn connect(&self, host_id: &str) -> Result<()> {
        let cfg = self.vault.get_host_config(host_id)?;
        let handle = establish(&self.vault, &cfg, self.keepalive_secs).await?;
        let conn = Arc::new(Connection {
            handle,
            host_id: host_id.to_string(),
        });
        self.conns.lock().await.insert(host_id.to_string(), conn);
        Ok(())
    }

    /// Get a live connection, erroring if not connected/dropped. Does NOT
    /// auto-reconnect (design doc §4.3): callers must reconnect explicitly so
    /// stale session state is never silently assumed.
    pub async fn get(&self, host_id: &str) -> Result<Arc<Connection>> {
        let guard = self.conns.lock().await;
        match guard.get(host_id) {
            Some(c) if !c.handle.is_closed() => Ok(c.clone()),
            _ => Err(ConnectorError::disconnected(host_id)),
        }
    }

    /// Ensure a live connection exists, connecting on demand if absent/dead.
    pub async fn get_or_connect(&self, host_id: &str) -> Result<Arc<Connection>> {
        if let Ok(c) = self.get(host_id).await {
            return Ok(c);
        }
        self.connect(host_id).await?;
        self.get(host_id).await
    }

    /// Drop a host's transport (e.g. on host removal).
    pub async fn disconnect(&self, host_id: &str) {
        if let Some(c) = self.conns.lock().await.remove(host_id) {
            let _ = c
                .handle
                .disconnect(russh::Disconnect::ByApplication, "", "")
                .await;
        }
    }
}
