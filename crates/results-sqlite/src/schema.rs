pub const MIG_0001_INIT: &str = r#"
BEGIN;

CREATE TABLE runs (
  run_id          TEXT PRIMARY KEY,
  started_at      INTEGER NOT NULL,
  finished_at     INTEGER,
  tool_version    TEXT NOT NULL,
  args_json       TEXT NOT NULL,
  git_sha         TEXT,
  host_count      INTEGER DEFAULT 0,
  error_count     INTEGER DEFAULT 0
);

CREATE TABLE hosts (
  host_id         INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id          TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  address         TEXT NOT NULL,
  hostname        TEXT,
  asn             INTEGER,
  org             TEXT,
  UNIQUE (run_id, address)
);

CREATE TABLE ports (
  port_id         INTEGER PRIMARY KEY AUTOINCREMENT,
  host_id         INTEGER NOT NULL REFERENCES hosts(host_id) ON DELETE CASCADE,
  transport       TEXT NOT NULL CHECK (transport IN ('tcp','udp')),
  port            INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
  state           TEXT NOT NULL CHECK (state IN ('open','closed','filtered','open|filtered')),
  reason          TEXT,
  service_name    TEXT,
  confidence      REAL DEFAULT 0.0,
  first_seen_ms   INTEGER NOT NULL,
  last_seen_ms    INTEGER NOT NULL,
  UNIQUE (host_id, transport, port)
);

CREATE TABLE banners (
  banner_id       INTEGER PRIMARY KEY AUTOINCREMENT,
  port_id         INTEGER NOT NULL REFERENCES ports(port_id) ON DELETE CASCADE,
  protocol        TEXT,
  banner          TEXT,
  collected_ms    INTEGER NOT NULL
);

CREATE TABLE http_endpoints (
  http_id         INTEGER PRIMARY KEY AUTOINCREMENT,
  port_id         INTEGER NOT NULL REFERENCES ports(port_id) ON DELETE CASCADE,
  scheme          TEXT NOT NULL CHECK (scheme IN ('http','https')),
  authority       TEXT NOT NULL,
  path            TEXT NOT NULL,
  status          INTEGER,
  h2              INTEGER NOT NULL CHECK (h2 IN (0,1)) DEFAULT 0,
  server_header   TEXT,
  content_type    TEXT,
  favicon_hash    TEXT,
  tech_tags_json  TEXT,
  tls_ja3         TEXT,
  tls_ja3s        TEXT,
  tls_chain_json  TEXT,
  collected_ms    INTEGER NOT NULL,
  UNIQUE (port_id, scheme, authority, path)
);

CREATE TABLE errors (
  error_id        INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id          TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  scope           TEXT NOT NULL,
  code            TEXT NOT NULL,
  message         TEXT NOT NULL,
  at_ms           INTEGER NOT NULL
);

CREATE INDEX idx_hosts_run ON hosts(run_id);
CREATE INDEX idx_ports_host ON ports(host_id);
CREATE INDEX idx_ports_lookup ON ports(transport, port, state);
CREATE INDEX idx_http_port ON http_endpoints(port_id);
CREATE INDEX idx_banners_port ON banners(port_id);
CREATE INDEX idx_errors_run ON errors(run_id);

COMMIT;
"#
;

