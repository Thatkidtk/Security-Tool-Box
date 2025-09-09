//! Core utilities and shared types for the toolbox engine.

pub const fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Example shared type used across modules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target(pub String);

impl From<&str> for Target {
    fn from(s: &str) -> Self {
        Target(s.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_set() {
        assert!(!version().is_empty());
    }
}

