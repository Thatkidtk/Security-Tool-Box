# Results Storage and Analytics

## ER Diagram

```
runs ──< hosts ──< ports ──< banners
                      └────< http_endpoints
runs ──< errors
```

## Tables (V1)

- runs: run_id (uuidv7), started_at, finished_at, tool_version, args_json, git_sha, host_count, error_count
- hosts: host_id, run_id, address, hostname, asn?, org?
- ports: port_id, host_id, transport {tcp|udp}, port, state {open|closed|filtered|open|filtered}, reason?, service_name?, confidence (0..1), first_seen_ms, last_seen_ms
- banners: banner_id, port_id, protocol, banner, collected_ms
- http_endpoints: http_id, port_id, scheme {http|https}, authority, path, status, h2 {0|1}, server_header, content_type, favicon_hash, tech_tags_json, tls_ja3, tls_ja3s, tls_chain_json, collected_ms
- errors: error_id, run_id, scope, code, message, at_ms

## JSONL Event Examples

```
{"type":"scan.port","run_id":"018f...","addr":"192.0.2.10","transport":"tcp","port":443,"state":"open","reason":"syn-ack","t_first":1725900000101,"t_last":1725900000126}
{"type":"web.endpoint","run_id":"018f...","addr":"192.0.2.10","transport":"tcp","port":443,"scheme":"https","authority":"app.example.com","path":"/","status":200,"h2":1,"server_header":"nginx","content_type":"text/html","favicon_hash":"mmh3:0x1a2b3c","tech_tags":["nginx","react"],"tls":{"ja3":"...","ja3s":"...","chain":["...PEM..."]},"t":1725900000456}
{"type":"run.error","run_id":"018f...","scope":"port:192.0.2.10:tcp:443","code":"ECONNRESET","message":"connection reset by peer","t":1725900000501}
```

## DuckDB Recipes

```sql
-- Parquet
SELECT h.address, p.port, he.status, he.server_header
FROM 'hosts.parquet' h
JOIN 'ports.parquet' p USING(host_id)
LEFT JOIN 'http_endpoints.parquet' he USING(port_id)
WHERE p.state='open' AND p.port IN (80,443)
ORDER BY h.address, p.port;

-- Server header top 10
SELECT server_header, COUNT(*) AS n
FROM 'http_endpoints.parquet'
WHERE status BETWEEN 200 AND 399
GROUP BY server_header
ORDER BY n DESC
LIMIT 10;

-- SQLite
ATTACH 'results.db' AS r;
SELECT COUNT(*) FROM r.ports WHERE state='open';
DETACH r;
```

## Performance Tips

- Import with batch writers (1–5k rows per tx) for speed.
- Parquet export uses ZSTD and ~256k row groups by default.
- Timestamps are epoch ms; treat as UTC.

