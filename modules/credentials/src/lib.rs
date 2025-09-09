use regex::Regex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashKind {
    MD5,
    SHA1,
    SHA256,
    SHA512,
    NTLM,
    Bcrypt,
    Argon2,
    SSHA,
    Unknown,
}

pub fn detect_hash(s: &str) -> HashKind {
    let t = s.trim();
    if t.starts_with("$2a$") || t.starts_with("$2b$") || t.starts_with("$2y$") { return HashKind::Bcrypt; }
    if t.starts_with("$argon2i$") || t.starts_with("$argon2id$") || t.starts_with("$argon2d$") { return HashKind::Argon2; }
    if t.starts_with("{SSHA}") { return HashKind::SSHA; }
    // NTLM: 32 hex uppercase typically, allow lowercase
    let re_ntlm = Regex::new(r"^(?i)[a-f0-9]{32}$").unwrap();
    if re_ntlm.is_match(t) { return HashKind::NTLM; }
    // Hex digests
    let re_md5 = Regex::new(r"^(?i)[a-f0-9]{32}$").unwrap();
    let re_sha1 = Regex::new(r"^(?i)[a-f0-9]{40}$").unwrap();
    let re_sha256 = Regex::new(r"^(?i)[a-f0-9]{64}$").unwrap();
    let re_sha512 = Regex::new(r"^(?i)[a-f0-9]{128}$").unwrap();
    if re_md5.is_match(t) { return HashKind::MD5; }
    if re_sha1.is_match(t) { return HashKind::SHA1; }
    if re_sha256.is_match(t) { return HashKind::SHA256; }
    if re_sha512.is_match(t) { return HashKind::SHA512; }
    HashKind::Unknown
}

pub fn is_plausible_hash(s: &str) -> bool { detect_hash(s) != HashKind::Unknown }

pub fn wordlist_stats(content: &str) -> (usize, usize) {
    let mut total = 0usize;
    let mut set = std::collections::HashSet::new();
    for line in content.lines() {
        let w = line.trim();
        if w.is_empty() || w.starts_with('#') { continue; }
        total += 1;
        set.insert(w.to_string());
    }
    (total, set.len())
}

