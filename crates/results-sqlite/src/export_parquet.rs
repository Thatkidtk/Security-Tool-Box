use anyhow::Result;
use arrow::{array::{Int64Builder, Float64Builder, StringBuilder, ArrayRef}, record_batch::RecordBatch};
use parquet::arrow::arrow_writer::ArrowWriter;
use parquet::file::properties::WriterProperties;
use rusqlite::{Connection, Row};
use std::sync::Arc;

use crate::arrow_schemas;

const CHUNK: usize = 10_000;

pub fn export_table_to_parquet(conn: &Connection, table: &str, out: &std::path::Path) -> Result<()> {
    let sql = format!("SELECT * FROM {}", table);
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query([])?;
    let file = std::fs::File::create(out)?;
    let (schema, kind) = match table {
        "ports" => (arrow_schemas::ports_schema(), TableKind::Ports),
        "http_endpoints" => (arrow_schemas::http_endpoints_schema(), TableKind::Http),
        other => anyhow::bail!("unsupported table: {other}"),
    };

    let props = WriterProperties::builder()
        .set_compression(parquet::basic::Compression::ZSTD)
        .build();

    let mut writer = ArrowWriter::try_new(file, Arc::new(schema.clone()), Some(props))?;

    loop {
        let mut batch = RowBatch::new(&kind);
        let mut count = 0;
        while count < CHUNK {
            let Some(row) = rows.next()? else { break; };
            batch.push(row, &kind)?;
            count += 1;
        }
        if count == 0 { break; }
        let arrays = batch.finish(&kind)?;
        let rb = RecordBatch::try_new(Arc::new(schema.clone()), arrays)?;
        writer.write(&rb)?;
    }

    writer.close()?;
    Ok(())
}

enum TableKind { Ports, Http }

struct RowBatch {
    // Ports
    p_port_id: Int64Builder,
    p_host_id: Int64Builder,
    p_transport: StringBuilder,
    p_port: Int64Builder,
    p_state: StringBuilder,
    p_reason: StringBuilder,
    p_service_name: StringBuilder,
    p_confidence: Float64Builder,
    p_first: Int64Builder,
    p_last: Int64Builder,
    // Http
    h_http_id: Int64Builder,
    h_port_id: Int64Builder,
    h_scheme: StringBuilder,
    h_authority: StringBuilder,
    h_path: StringBuilder,
    h_status: Int64Builder,
    h_h2: Int64Builder,
    h_server: StringBuilder,
    h_ct: StringBuilder,
    h_fav: StringBuilder,
    h_tags: StringBuilder,
    h_ja3: StringBuilder,
    h_ja3s: StringBuilder,
    h_chain: StringBuilder,
    h_collected: Int64Builder,
}

impl RowBatch {
    fn new(kind: &TableKind) -> Self {
        match kind {
            TableKind::Ports => RowBatch {
                p_port_id: Int64Builder::new(), p_host_id: Int64Builder::new(), p_transport: StringBuilder::new(), p_port: Int64Builder::new(), p_state: StringBuilder::new(), p_reason: StringBuilder::new(), p_service_name: StringBuilder::new(), p_confidence: Float64Builder::new(), p_first: Int64Builder::new(), p_last: Int64Builder::new(),
                h_http_id: Int64Builder::new(), h_port_id: Int64Builder::new(), h_scheme: StringBuilder::new(), h_authority: StringBuilder::new(), h_path: StringBuilder::new(), h_status: Int64Builder::new(), h_h2: Int64Builder::new(), h_server: StringBuilder::new(), h_ct: StringBuilder::new(), h_fav: StringBuilder::new(), h_tags: StringBuilder::new(), h_ja3: StringBuilder::new(), h_ja3s: StringBuilder::new(), h_chain: StringBuilder::new(), h_collected: Int64Builder::new(),
            },
            TableKind::Http => RowBatch {
                p_port_id: Int64Builder::new(), p_host_id: Int64Builder::new(), p_transport: StringBuilder::new(), p_port: Int64Builder::new(), p_state: StringBuilder::new(), p_reason: StringBuilder::new(), p_service_name: StringBuilder::new(), p_confidence: Float64Builder::new(), p_first: Int64Builder::new(), p_last: Int64Builder::new(),
                h_http_id: Int64Builder::new(), h_port_id: Int64Builder::new(), h_scheme: StringBuilder::new(), h_authority: StringBuilder::new(), h_path: StringBuilder::new(), h_status: Int64Builder::new(), h_h2: Int64Builder::new(), h_server: StringBuilder::new(), h_ct: StringBuilder::new(), h_fav: StringBuilder::new(), h_tags: StringBuilder::new(), h_ja3: StringBuilder::new(), h_ja3s: StringBuilder::new(), h_chain: StringBuilder::new(), h_collected: Int64Builder::new(),
            },
        }
    }

    fn push(&mut self, row: &Row, kind: &TableKind) -> Result<()> {
        match kind {
            TableKind::Ports => {
                self.p_port_id.append_value(row.get::<_, i64>(0)?)?;
                self.p_host_id.append_value(row.get::<_, i64>(1)?)?;
                self.p_transport.append_value(row.get::<_, String>(2)?)?;
                self.p_port.append_value(row.get::<_, i64>(3)?)?;
                self.p_state.append_value(row.get::<_, String>(4)?)?;
                self.append_opt_str(&mut self.p_reason, row.get::<_, Option<String>>(5)?)?;
                self.append_opt_str(&mut self.p_service_name, row.get::<_, Option<String>>(6)?)?;
                self.p_confidence.append_value(row.get::<_, f64>(7)?)?;
                self.p_first.append_value(row.get::<_, i64>(8)?)?;
                self.p_last.append_value(row.get::<_, i64>(9)?)?;
            }
            TableKind::Http => {
                self.h_http_id.append_value(row.get::<_, i64>(0)?)?;
                self.h_port_id.append_value(row.get::<_, i64>(1)?)?;
                self.h_scheme.append_value(row.get::<_, String>(2)?)?;
                self.h_authority.append_value(row.get::<_, String>(3)?)?;
                self.h_path.append_value(row.get::<_, String>(4)?)?;
                self.append_opt_i64(&mut self.h_status, row.get::<_, Option<i64>>(5)?)?;
                self.h_h2.append_value(row.get::<_, i64>(6)?)?;
                self.append_opt_str(&mut self.h_server, row.get::<_, Option<String>>(7)?)?;
                self.append_opt_str(&mut self.h_ct, row.get::<_, Option<String>>(8)?)?;
                self.append_opt_str(&mut self.h_fav, row.get::<_, Option<String>>(9)?)?;
                self.append_opt_str(&mut self.h_tags, row.get::<_, Option<String>>(10)?)?;
                self.append_opt_str(&mut self.h_ja3, row.get::<_, Option<String>>(11)?)?;
                self.append_opt_str(&mut self.h_ja3s, row.get::<_, Option<String>>(12)?)?;
                self.append_opt_str(&mut self.h_chain, row.get::<_, Option<String>>(13)?)?;
                self.h_collected.append_value(row.get::<_, i64>(14)?)?;
            }
        }
        Ok(())
    }

    fn append_opt_str(&self, b: &mut StringBuilder, v: Option<String>) -> Result<()> { match v { Some(s) => b.append_value(s)?, None => b.append_null()? }; Ok(()) }
    fn append_opt_i64(&self, b: &mut Int64Builder, v: Option<i64>) -> Result<()> { match v { Some(x) => b.append_value(x)?, None => b.append_null()? }; Ok(()) }

    fn finish(self, kind: &TableKind) -> Result<Vec<Arc<dyn arrow::array::Array>>> {
        Ok(match kind {
            TableKind::Ports => vec![
                Arc::new(self.p_port_id.finish()),
                Arc::new(self.p_host_id.finish()),
                Arc::new(self.p_transport.finish()),
                Arc::new(self.p_port.finish()),
                Arc::new(self.p_state.finish()),
                Arc::new(self.p_reason.finish()),
                Arc::new(self.p_service_name.finish()),
                Arc::new(self.p_confidence.finish()),
                Arc::new(self.p_first.finish()),
                Arc::new(self.p_last.finish()),
            ],
            TableKind::Http => vec![
                Arc::new(self.h_http_id.finish()),
                Arc::new(self.h_port_id.finish()),
                Arc::new(self.h_scheme.finish()),
                Arc::new(self.h_authority.finish()),
                Arc::new(self.h_path.finish()),
                Arc::new(self.h_status.finish()),
                Arc::new(self.h_h2.finish()),
                Arc::new(self.h_server.finish()),
                Arc::new(self.h_ct.finish()),
                Arc::new(self.h_fav.finish()),
                Arc::new(self.h_tags.finish()),
                Arc::new(self.h_ja3.finish()),
                Arc::new(self.h_ja3s.finish()),
                Arc::new(self.h_chain.finish()),
                Arc::new(self.h_collected.finish()),
            ],
        })
    }
}

