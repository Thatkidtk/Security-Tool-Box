use crate::schema::MIG_0001_INIT;
use anyhow::Result;
use rusqlite::{Connection, params};

pub struct Db {
    pub conn: Connection,
}

impl Db {
    pub fn open_or_create(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let conn = Connection::open(path)?;
        apply_pragmas(&conn)?;
        migrate(&conn)?;
        Ok(Db { conn })
    }
}

fn apply_pragmas(conn: &Connection) -> Result<()> {
    conn.pragma_update(None, "journal_mode", &"WAL")?;
    conn.pragma_update(None, "synchronous", &"NORMAL")?;
    conn.pragma_update(None, "foreign_keys", &"ON")?;
    conn.pragma_update(None, "mmap_size", &268435456i64)?; // 256 MiB
    conn.pragma_update(None, "page_size", &4096i64)?;
    conn.pragma_update(None, "cache_size", &-262144i64)?; // 1 GiB target
    Ok(())
}

fn migrate(conn: &Connection) -> Result<()> {
    // naive: if runs table doesn't exist, apply 0001
    let exists: i64 = conn.query_row(
        "SELECT COUNT(1) FROM sqlite_master WHERE type='table' AND name='runs'",
        [],
        |r| r.get(0),
    )?;
    if exists == 0 {
        conn.execute_batch(MIG_0001_INIT)?;
    }
    Ok(())
}

