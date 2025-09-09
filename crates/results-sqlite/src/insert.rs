use crate::{Db, HostId, PortId, RunMeta, PortSpec, HttpEndpoint};
use anyhow::Result;
use rusqlite::params;
use uuid::Uuid;

impl Db {
    pub fn begin_run(&self, meta: RunMeta) -> Result<Uuid> {
        self.conn.execute(
            "INSERT INTO runs(run_id, started_at, tool_version, args_json, git_sha) VALUES (?,?,?,?,?)",
            params![meta.run_id.to_string(), meta.started_at, meta.tool_version, meta.args_json, meta.git_sha],
        )?;
        Ok(meta.run_id)
    }

    pub fn finish_run(&self, run_id: &Uuid, finished_at: i64, host_count: i64, error_count: i64) -> Result<()> {
        self.conn.execute(
            "UPDATE runs SET finished_at=?, host_count=?, error_count=? WHERE run_id=?",
            params![finished_at, host_count, error_count, run_id.to_string()],
        )?;
        Ok(())
    }

    pub fn upsert_host(&self, run_id: &Uuid, addr: &str, hostname: Option<&str>) -> Result<HostId> {
        self.conn.execute(
            "INSERT INTO hosts(run_id,address,hostname) VALUES (?,?,?) ON CONFLICT(run_id,address) DO UPDATE SET hostname=COALESCE(excluded.hostname,hosts.hostname)",
            params![run_id.to_string(), addr, hostname],
        )?;
        let id: HostId = self.conn.query_row(
            "SELECT host_id FROM hosts WHERE run_id=? AND address=?",
            params![run_id.to_string(), addr],
            |r| r.get(0),
        )?;
        Ok(id)
    }

    pub fn upsert_port(&self, host_id: HostId, spec: &PortSpec) -> Result<PortId> {
        self.conn.execute(
            "INSERT INTO ports(host_id,transport,port,state,reason,service_name,confidence,first_seen_ms,last_seen_ms) VALUES (?,?,?,?,?,?,?,?,?)
             ON CONFLICT(host_id,transport,port) DO UPDATE SET state=excluded.state, reason=excluded.reason, service_name=excluded.service_name, confidence=excluded.confidence, last_seen_ms=excluded.last_seen_ms",
            params![host_id, spec.transport, spec.port as i64, spec.state, spec.reason, spec.service_name, spec.confidence as f64, spec.first_seen_ms, spec.last_seen_ms],
        )?;
        let id: PortId = self.conn.query_row(
            "SELECT port_id FROM ports WHERE host_id=? AND transport=? AND port=?",
            params![host_id, spec.transport, spec.port as i64],
            |r| r.get(0),
        )?;
        Ok(id)
    }

    pub fn add_http_endpoint(&self, port_id: PortId, http: &HttpEndpoint) -> Result<()> {
        self.conn.execute(
            "INSERT INTO http_endpoints(port_id,scheme,authority,path,status,h2,server_header,content_type,favicon_hash,tech_tags_json,tls_ja3,tls_ja3s,tls_chain_json,collected_ms)
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
             ON CONFLICT(port_id,scheme,authority,path) DO UPDATE SET status=excluded.status, server_header=excluded.server_header, content_type=excluded.content_type, favicon_hash=excluded.favicon_hash, tech_tags_json=excluded.tech_tags_json, tls_ja3=excluded.tls_ja3, tls_ja3s=excluded.tls_ja3s, tls_chain_json=excluded.tls_chain_json, collected_ms=excluded.collected_ms",
            params![port_id, http.scheme, http.authority, http.path, http.status, if http.h2 {1i64} else {0i64}, http.server_header, http.content_type, http.favicon_hash, http.tech_tags_json, http.tls_ja3, http.tls_ja3s, http.tls_chain_json, http.collected_ms],
        )?;
        Ok(())
    }

    pub fn add_error(&self, run_id: &Uuid, scope: &str, code: &str, message: &str, at_ms: i64) -> Result<()> {
        self.conn.execute(
            "INSERT INTO errors(run_id,scope,code,message,at_ms) VALUES (?,?,?,?,?)",
            params![run_id.to_string(), scope, code, message, at_ms],
        )?;
        Ok(())
    }
}

