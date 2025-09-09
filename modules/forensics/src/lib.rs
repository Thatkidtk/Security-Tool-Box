use anyhow::Result;
use sha2::{Sha256, Digest};
use std::fs::File;
use std::io::{Read, BufReader};

#[derive(Debug, Clone)]
pub struct FileInfo {
    pub path: String,
    pub size: u64,
    pub sha256: String,
    pub blake3: String,
    pub mime: Option<String>,
    pub ext: Option<String>,
}

pub fn hash_file(path: &str) -> Result<FileInfo> {
    let f = File::open(path)?;
    let metadata = f.metadata()?;
    let mut reader = BufReader::new(f);
    let mut sha = Sha256::new();
    let mut bl = blake3::Hasher::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 { break; }
        sha.update(&buf[..n]);
        bl.update(&buf[..n]);
    }
    let sha_hex = hex::encode(sha.finalize());
    let bl_hex = bl.finalize().to_hex().to_string();
    let tp = infer::get_from_path(path).ok().flatten();
    let mime = tp.as_ref().map(|t| t.mime_type().to_string());
    let ext = tp.as_ref().map(|t| t.extension().to_string());
    Ok(FileInfo { path: path.to_string(), size: metadata.len(), sha256: sha_hex, blake3: bl_hex, mime, ext })
}

