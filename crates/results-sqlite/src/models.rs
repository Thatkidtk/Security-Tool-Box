use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub type HostId = i64;
pub type PortId = i64;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunMeta {
    pub run_id: Uuid,
    pub started_at: i64,
    pub tool_version: String,
    pub args_json: String,
    pub git_sha: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortSpec {
    pub transport: String,
    pub port: u16,
    pub state: String,
    pub reason: Option<String>,
    pub service_name: Option<String>,
    pub confidence: f32,
    pub first_seen_ms: i64,
    pub last_seen_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpEndpoint {
    pub scheme: String,
    pub authority: String,
    pub path: String,
    pub status: Option<i32>,
    pub h2: bool,
    pub server_header: Option<String>,
    pub content_type: Option<String>,
    pub favicon_hash: Option<String>,
    pub tech_tags_json: Option<String>,
    pub tls_ja3: Option<String>,
    pub tls_ja3s: Option<String>,
    pub tls_chain_json: Option<String>,
    pub collected_ms: i64,
}

