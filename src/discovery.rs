//! Discovering WLCG tokens from the environment
use std::{env, io::ErrorKind};

use thiserror::Error;

/// Token source
///
/// For use in discovery error reporting (only applicable to file sources)
#[derive(Clone, Copy, Debug)]
pub enum TokenFileSource {
    EnvBearerTokenFile,
    EnvXdgRuntimeDir,
    TmpDir,
}

impl std::fmt::Display for TokenFileSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenFileSource::EnvBearerTokenFile => {
                write!(f, "path specified in $BEARER_TOKEN_FILE")
            }
            TokenFileSource::EnvXdgRuntimeDir => {
                write!(f, "path specified in $XDG_RUNTIME_DIR/bt_u$ID")
            }
            TokenFileSource::TmpDir => write!(f, "/tmp/bt_u$ID"),
        }
    }
}

/// Token discovery error
#[derive(Clone, Debug, Error)]
pub enum TokenDiscoveryError {
    #[error("No token found in environment or default locations")]
    NoTokenFound,
    #[error("Failed to read token from {0}: {1}")]
    FileReadError(TokenFileSource, String),
}

/// Read to string from a file
///
/// Returnis None if the file does not exist or the contents are empty
///
/// Potential TODO: check the file permissions to ensure that the token is not
/// world-readable. Currently some debate as to whether this is mandatory.
fn read_to_string(
    token_path: &str,
    source: TokenFileSource,
) -> Result<Option<String>, TokenDiscoveryError> {
    match std::fs::read_to_string(token_path) {
        Ok(token) => {
            let token = token.trim();
            Ok((!token.is_empty()).then(|| token.to_string()))
        }
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(TokenDiscoveryError::FileReadError(source, e.to_string())),
    }
}

/// Load a raw WLCG token from the environment
///
/// No validation is performed on the token, it is simply returned as a string.
///
/// Procedure:
/// - If `BEARER_TOKEN` env is set, use it.
/// - If `BEARER_TOKEN_FILE` env is set, read the token from the file.
/// - If `XDG_RUNTIME_DIR` env is set then read the token from `$XDG_RUNTIME_DIR/bt_u$ID`.
/// - If `/tmp/bt_u$ID` exists, read the token from it.
///
/// Full specification at <https://github.com/WLCG-AuthZ-WG/bearer-token-discovery/blob/master/specification.md>
pub fn load_raw_token() -> Result<String, TokenDiscoveryError> {
    if let Ok(token) = env::var("BEARER_TOKEN") {
        let token = token.trim();
        if !token.is_empty() {
            return Ok(token.to_string());
        }
    }
    let uid = nix::unistd::Uid::current();
    let candidates = [
        env::var("BEARER_TOKEN_FILE")
            .ok()
            .map(|path| (path, TokenFileSource::EnvBearerTokenFile)),
        env::var("XDG_RUNTIME_DIR").ok().map(|dir| {
            (
                format!("{dir}/bt_u{uid}"),
                TokenFileSource::EnvXdgRuntimeDir,
            )
        }),
        Some((format!("/tmp/bt_u{uid}"), TokenFileSource::TmpDir)),
    ];
    for (path, source) in candidates.into_iter().flatten() {
        if let Some(token) = read_to_string(&path, source)? {
            return Ok(token);
        }
    }
    Err(TokenDiscoveryError::NoTokenFound)
}

#[cfg(test)]
mod tests {
    use std::{assert_matches, env};

    use super::load_raw_token;

    #[test]
    fn test_load_from_var() {
        unsafe {
            env::set_var("BEARER_TOKEN", "test_token");
        }

        let token = load_raw_token();
        assert_matches!(token, Ok(s) if s == "test_token");
    }
}
