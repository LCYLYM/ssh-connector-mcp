//! Structured local audit log. One JSON object per line, daily-rotated files
//! under `data_dir/audit/`. Never records credential plaintext; PTY stdin that
//! may carry passwords is recorded as a byte count, not content.

use serde::Serialize;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

#[derive(Debug, Serialize)]
pub struct AuditEntry<'a> {
    pub ts: String,
    pub action: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caller: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<serde_json::Value>,
}

impl<'a> AuditEntry<'a> {
    pub fn with_host(mut self, host_id: &'a str) -> Self {
        self.host_id = Some(host_id);
        self
    }
    pub fn with_session(mut self, session_id: &'a str) -> Self {
        self.session_id = Some(session_id);
        self
    }
    pub fn with_caller(mut self, caller: &'a str) -> Self {
        self.caller = Some(caller);
        self
    }
    pub fn with_exit(mut self, exit_code: Option<i32>) -> Self {
        self.exit_code = exit_code;
        self
    }
    pub fn with_detail(mut self, detail: serde_json::Value) -> Self {
        self.detail = Some(detail);
        self
    }
}

pub struct AuditLog {
    dir: PathBuf,
    lock: Mutex<()>,
}

impl AuditLog {
    pub fn new(audit_dir: PathBuf) -> Self {
        Self {
            dir: audit_dir,
            lock: Mutex::new(()),
        }
    }

    fn today_file(&self) -> PathBuf {
        let now = time::OffsetDateTime::now_utc();
        let day = format!(
            "{:04}-{:02}-{:02}",
            now.year(),
            now.month() as u8,
            now.day()
        );
        self.dir.join(format!("audit-{day}.jsonl"))
    }

    pub fn record(&self, entry: AuditEntry) {
        let line = match serde_json::to_string(&entry) {
            Ok(s) => s,
            Err(_) => return,
        };
        let _guard = self.lock.lock().unwrap_or_else(|p| p.into_inner());
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.today_file())
        {
            let _ = writeln!(f, "{line}");
        }
    }

    /// Convenience constructor for an entry with the current timestamp.
    pub fn entry(action: &str) -> AuditEntry<'_> {
        let now = time::OffsetDateTime::now_utc();
        AuditEntry {
            ts: now
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            action,
            host_id: None,
            session_id: None,
            caller: None,
            exit_code: None,
            detail: None,
        }
    }

    /// Read the most recent `limit` audit entries (newest first) as raw JSON
    /// values, scanning recent day-files. Used by the Web UI audit view.
    pub fn tail(&self, limit: usize) -> Vec<serde_json::Value> {
        let _guard = self.lock.lock().unwrap_or_else(|p| p.into_inner());
        let mut files: Vec<PathBuf> = match std::fs::read_dir(&self.dir) {
            Ok(rd) => rd
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .map(|n| n.starts_with("audit-") && n.ends_with(".jsonl"))
                        .unwrap_or(false)
                })
                .collect(),
            Err(_) => return Vec::new(),
        };
        files.sort();
        let mut lines: Vec<String> = Vec::new();
        // Read newest files first until we have enough lines.
        for path in files.iter().rev() {
            if let Ok(content) = std::fs::read_to_string(path) {
                let mut these: Vec<String> = content.lines().map(|l| l.to_string()).collect();
                these.reverse();
                lines.append(&mut these);
            }
            if lines.len() >= limit {
                break;
            }
        }
        lines
            .into_iter()
            .take(limit)
            .filter_map(|l| serde_json::from_str(&l).ok())
            .collect()
    }
}
