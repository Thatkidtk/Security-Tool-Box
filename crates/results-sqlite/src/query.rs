use crate::Db;
use anyhow::Result;

impl Db {
    pub fn table_exists(&self, name: &str) -> Result<bool> {
        let cnt: i64 = self.conn.query_row(
            "SELECT COUNT(1) FROM sqlite_master WHERE type='table' AND name=?",
            [name],
            |r| r.get(0),
        )?;
        Ok(cnt > 0)
    }
}

