//! Token newtype and parsing / interpretation utilities

use std::time::SystemTime;

use base64::{Engine, alphabet, engine};
use thiserror::Error;

/// Parsing error for WLCG tokens
#[derive(Clone, Copy, Debug, Error)]
pub enum TokenParseError {
    #[error("Failed to decode JWT")]
    InvalidToken,
    #[error("Token does not contain a not-before claim")]
    MissingNotBeforeClaim,
    #[error("Token not-before claim is not a valid integer")]
    InvalidNotBeforeClaim,
    #[error("Token does not contain an expiry claim")]
    MissingExpiryClaim,
    #[error("Token expiry claim is not a valid integer")]
    InvalidExpiryClaim,
}

/// A WLCG token
///
/// Follows the WLCG common jwt profile, as described in
/// <https://github.com/WLCG-AuthZ-WG/common-jwt-profile/blob/master/v1.3/profile.md>
///
/// An instance of this struct is validated up to the point of:
/// - Parsing the string as a JWT structure
/// - Ensuring the `nbf` and `exp` claims are present and valid integers
#[derive(Debug, Clone)]
pub struct WLCGToken {
    /// The raw token string
    raw: String,
    /// Parsed not before time of the token
    nbf: SystemTime,
    /// Parsed expiry time of the token
    exp: SystemTime,
}

fn parse_raw(token: &str) -> Result<WLCGToken, TokenParseError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(TokenParseError::InvalidToken);
    }

    let payload = engine::GeneralPurpose::new(&alphabet::URL_SAFE, engine::general_purpose::NO_PAD)
        .decode(parts[1])
        .map_err(|_| TokenParseError::InvalidToken)?;

    let payload_json: serde_json::Value =
        serde_json::from_slice(&payload).map_err(|_| TokenParseError::InvalidToken)?;

    let Some(nbf) = payload_json.get("nbf") else {
        return Err(TokenParseError::MissingNotBeforeClaim);
    };
    let Some(nbf) = nbf.as_i64() else {
        return Err(TokenParseError::InvalidNotBeforeClaim);
    };
    let nbf = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(nbf as u64);

    let Some(exp) = payload_json.get("exp") else {
        return Err(TokenParseError::MissingExpiryClaim);
    };
    let Some(exp) = exp.as_i64() else {
        return Err(TokenParseError::InvalidExpiryClaim);
    };
    let exp = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(exp as u64);

    Ok(WLCGToken {
        raw: token.to_string(),
        nbf,
        exp,
    })
}

impl WLCGToken {
    /// Parse a raw token string
    pub fn parse(raw: &str) -> Result<Self, TokenParseError> {
        parse_raw(raw)
    }

    /// Get the raw token string
    pub fn raw(&self) -> &str {
        &self.raw
    }

    /// Get the not-before time of the token
    pub fn not_before(&self) -> SystemTime {
        self.nbf
    }

    /// Get the expiry time of the token
    pub fn expiry(&self) -> SystemTime {
        self.exp
    }

    /// Check if the token is valid at the current time
    pub fn is_valid(&self) -> bool {
        let now = SystemTime::now();
        now >= self.nbf && now <= self.exp
    }
}

impl From<WLCGToken> for String {
    fn from(token: WLCGToken) -> Self {
        token.raw
    }
}
