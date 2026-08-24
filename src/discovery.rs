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
    #[error("Failed to read token from {location}: {kind}")]
    FileReadError {
        location: TokenFileSource,
        kind: ErrorKind,
    },
}

/// Read to string from a file
///
/// Returns None if the contents are empty (after trimming). Any I/O error,
/// including a missing file, is reported so the caller can decide whether to
/// continue with the next source.
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
        Err(e) => Err(TokenDiscoveryError::FileReadError {
            location: source,
            kind: e.kind(),
        }),
    }
}

/// Load a raw WLCG token from the environment
///
/// No validation is performed on the token, it is simply returned as a string.
///
/// Procedure:
/// - If `BEARER_TOKEN` env is set and non-empty, use it.
/// - If `BEARER_TOKEN_FILE` env is set, read the token from that file. Since
///   the location was configured explicitly, a missing or unreadable file is
///   an error rather than a reason to keep looking.
/// - Otherwise, if `XDG_RUNTIME_DIR` env is set, read `$XDG_RUNTIME_DIR/bt_u$ID`.
/// - Otherwise, read `/tmp/bt_u$ID`.
///
/// For the two default locations a missing file yields [`TokenDiscoveryError::NoTokenFound`];
/// any other I/O error (e.g. permission denied) is reported as-is.
///
/// Full specification at <https://github.com/WLCG-AuthZ-WG/bearer-token-discovery/blob/master/specification.md>
pub fn load_raw_token() -> Result<String, TokenDiscoveryError> {
    if let Ok(token) = env::var("BEARER_TOKEN") {
        let token = token.trim();
        if !token.is_empty() {
            return Ok(token.to_string());
        }
    }

    let (path, source) = if let Ok(path) = env::var("BEARER_TOKEN_FILE") {
        (path, TokenFileSource::EnvBearerTokenFile)
    } else {
        let uid = nix::unistd::Uid::current();
        match env::var("XDG_RUNTIME_DIR") {
            Ok(dir) => (
                format!("{dir}/bt_u{uid}"),
                TokenFileSource::EnvXdgRuntimeDir,
            ),
            Err(_) => (format!("/tmp/bt_u{uid}"), TokenFileSource::TmpDir),
        }
    };

    match read_to_string(&path, source) {
        Ok(Some(token)) => Ok(token),
        Ok(None) => Err(TokenDiscoveryError::NoTokenFound),
        // A missing default-location file just means there is no token yet;
        // a missing explicitly-configured file is a misconfiguration.
        Err(TokenDiscoveryError::FileReadError {
            location: TokenFileSource::EnvXdgRuntimeDir | TokenFileSource::TmpDir,
            kind: ErrorKind::NotFound,
        }) => Err(TokenDiscoveryError::NoTokenFound),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use std::io::ErrorKind;

    use temp_env::with_vars;

    use super::{TokenDiscoveryError, TokenFileSource, load_raw_token};

    const VARS: [&str; 3] = ["BEARER_TOKEN", "BEARER_TOKEN_FILE", "XDG_RUNTIME_DIR"];

    /// Run `f` with only the given discovery variables set
    fn with_env<R>(set: &[(&str, &str)], f: impl FnOnce() -> R) -> R {
        let vars: Vec<(&str, Option<&str>)> = VARS
            .iter()
            .map(|&k| (k, set.iter().find(|(sk, _)| *sk == k).map(|(_, v)| *v)))
            .collect();
        with_vars(vars, f)
    }

    #[test]
    fn test_load_from_var() {
        with_env(&[("BEARER_TOKEN", " test_token\n")], || {
            assert!(matches!(load_raw_token(), Ok(s) if s == "test_token"));
        });
    }

    #[test]
    fn test_load_from_file() {
        let dir = std::env::temp_dir().join(format!("wlcg-token-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("token");
        std::fs::write(&path, "file_token\n").unwrap();

        with_env(&[("BEARER_TOKEN_FILE", path.to_str().unwrap())], || {
            assert!(matches!(load_raw_token(), Ok(s) if s == "file_token"));
        });
        // An empty BEARER_TOKEN must not shadow the file
        with_env(
            &[
                ("BEARER_TOKEN", "  "),
                ("BEARER_TOKEN_FILE", path.to_str().unwrap()),
            ],
            || assert!(matches!(load_raw_token(), Ok(s) if s == "file_token")),
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_explicit_file_missing_is_error() {
        with_env(&[("BEARER_TOKEN_FILE", "/nonexistent/wlcg-token")], || {
            assert!(matches!(
                load_raw_token(),
                Err(TokenDiscoveryError::FileReadError {
                    location: TokenFileSource::EnvBearerTokenFile,
                    kind: ErrorKind::NotFound
                })
            ));
        });
    }

    #[test]
    fn test_xdg_missing_is_not_found() {
        with_env(&[("XDG_RUNTIME_DIR", "/nonexistent")], || {
            assert!(matches!(
                load_raw_token(),
                Err(TokenDiscoveryError::NoTokenFound)
            ));
        });
    }
}
