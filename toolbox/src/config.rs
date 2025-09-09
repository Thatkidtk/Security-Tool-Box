#![allow(dead_code)]
use serde::Deserialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Default, Deserialize, Clone)]
pub struct ScanConfig {
    pub ports: Option<String>,
    pub top: Option<usize>,
    pub timeout_ms: Option<u64>,
    pub concurrency: Option<usize>,
    pub host_concurrency: Option<usize>,
    pub qps: Option<u32>,
    pub retries: Option<u32>,
    pub retry_delay_ms: Option<u64>,
    pub format: Option<String>,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct DiscoverConfig {
    pub ports: Option<String>,
    pub timeout_ms: Option<u64>,
    pub concurrency: Option<usize>,
    pub qps: Option<u32>,
    pub format: Option<String>,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct Config {
    pub scan: Option<ScanConfig>,
    pub discover: Option<DiscoverConfig>,
}

pub fn load_config(path: Option<&Path>) -> Option<Config> {
    let path = match path {
        Some(p) => p.to_path_buf(),
        None => {
            let p = Path::new("toolbox.yaml");
            if p.exists() { p.to_path_buf() } else { return None; }
        }
    };
    let s = fs::read_to_string(path).ok()?;
    serde_yaml::from_str(&s).ok()
}
