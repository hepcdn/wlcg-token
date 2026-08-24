//! Token newtype and parsing / interpretation utilities

use std::time::{Duration, SystemTime};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD_INDIFFERENT};
use thiserror::Error;

/// A JWT date claim (RFC 7519 `NumericDate`) recognised by the parser
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DateClaim {
    IssuedAt,
    NotBefore,
    Expiry,
}

impl DateClaim {
    /// The claim name as it appears in the JWT payload
    pub fn name(self) -> &'static str {
        match self {
            DateClaim::IssuedAt => "iat",
            DateClaim::NotBefore => "nbf",
            DateClaim::Expiry => "exp",
        }
    }
}

impl std::fmt::Display for DateClaim {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Parsing error for WLCG tokens
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum TokenParseError {
    #[error("Failed to decode JWT")]
    InvalidToken,
    #[error("Token does not contain a `{0}` claim")]
    MissingDateClaim(DateClaim),
    #[error("Token `{0}` claim is not a valid numeric date")]
    InvalidDateClaim(DateClaim),
}

/// A WLCG token
///
/// Follows the WLCG common jwt profile, as described in
/// <https://github.com/WLCG-AuthZ-WG/common-jwt-profile/blob/master/v1.3/profile.md>
///
/// An instance of this struct is validated up to the point of:
/// - Parsing the string as a JWT structure
/// - Ensuring the `nbf` and `exp` claims are present and valid integers
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WLCGToken {
    /// The raw token string
    raw: String,
    /// Parsed not before time of the token
    nbf: SystemTime,
    /// Parsed expiry time of the token
    exp: SystemTime,
}

fn parse_date_claim(
    payload_json: &serde_json::Value,
    claim: DateClaim,
) -> Result<SystemTime, TokenParseError> {
    let claim_value = payload_json
        .get(claim.name())
        .ok_or(TokenParseError::MissingDateClaim(claim))?
        .as_u64()
        .ok_or(TokenParseError::InvalidDateClaim(claim))?;
    // `SystemTime + Duration` panics on overflow; treat an unrepresentable
    // date as an invalid claim instead
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(claim_value))
        .ok_or(TokenParseError::InvalidDateClaim(claim))
}

impl WLCGToken {
    /// Parse a raw token string
    pub fn parse(raw: &str) -> Result<Self, TokenParseError> {
        let parts: Vec<&str> = raw.split('.').collect();
        if parts.len() != 3 {
            return Err(TokenParseError::InvalidToken);
        }

        let payload = URL_SAFE_NO_PAD_INDIFFERENT
            .decode(parts[1])
            .map_err(|_| TokenParseError::InvalidToken)?;

        let payload_json: serde_json::Value =
            serde_json::from_slice(&payload).map_err(|_| TokenParseError::InvalidToken)?;

        let nbf = parse_date_claim(&payload_json, DateClaim::NotBefore)?;
        let exp = parse_date_claim(&payload_json, DateClaim::Expiry)?;

        Ok(WLCGToken {
            raw: raw.to_string(),
            nbf,
            exp,
        })
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an unsigned JWT-shaped string from a JSON payload
    ///
    /// The parser never verifies the signature or header, so a fixed header
    /// and a dummy signature are sufficient.
    fn jwt(payload: &str) -> String {
        let header = URL_SAFE_NO_PAD_INDIFFERENT.encode(r#"{"alg":"none"}"#);
        let payload = URL_SAFE_NO_PAD_INDIFFERENT.encode(payload);
        format!("{header}.{payload}.sig")
    }

    fn epoch_secs(t: SystemTime) -> u64 {
        t.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs()
    }

    fn now_secs() -> u64 {
        epoch_secs(SystemTime::now())
    }

    #[test]
    fn parses_claims() {
        let (nbf, exp) = (now_secs() - 60, now_secs() + 3600);
        let raw = jwt(&format!(r#"{{"nbf":{nbf},"exp":{exp},"sub":"x"}}"#));
        let token = WLCGToken::parse(&raw).unwrap();
        assert_eq!(token.raw(), raw);
        assert_eq!(epoch_secs(token.not_before()), nbf);
        assert_eq!(epoch_secs(token.expiry()), exp);
        assert!(token.is_valid());
        assert_eq!(String::from(token), raw);
    }

    #[test]
    fn accepts_padded_payload() {
        let exp = now_secs() + 3600;
        // Pad the JSON with whitespace until the base64 form needs `=` padding
        let mut payload = format!(r#"{{"nbf":0,"exp":{exp}}}"#);
        while payload.len() % 3 == 0 {
            payload.push(' ');
        }
        let encoded = base64::engine::general_purpose::URL_SAFE.encode(&payload);
        assert!(
            encoded.ends_with('='),
            "test payload should require padding"
        );
        assert!(WLCGToken::parse(&format!("h.{encoded}.s")).is_ok());
    }

    #[test]
    fn rejects_expired_and_not_yet_valid() {
        let now = now_secs();
        let expired =
            WLCGToken::parse(&jwt(&format!(r#"{{"nbf":0,"exp":{}}}"#, now - 10))).unwrap();
        assert!(!expired.is_valid());
        let future = WLCGToken::parse(&jwt(&format!(
            r#"{{"nbf":{},"exp":{}}}"#,
            now + 60,
            now + 120
        )))
        .unwrap();
        assert!(!future.is_valid());
    }

    #[test]
    fn rejects_malformed_structure() {
        for raw in ["", "abc", "a.b", "a.b.c.d", &jwt("not json"), "h.!!!.s"] {
            assert_eq!(
                WLCGToken::parse(raw),
                Err(TokenParseError::InvalidToken),
                "{raw:?}"
            );
        }
    }

    #[test]
    fn rejects_missing_claims() {
        assert_eq!(
            WLCGToken::parse(&jwt(r#"{"exp":1}"#)),
            Err(TokenParseError::MissingDateClaim(DateClaim::NotBefore))
        );
        assert_eq!(
            WLCGToken::parse(&jwt(r#"{"nbf":1}"#)),
            Err(TokenParseError::MissingDateClaim(DateClaim::Expiry))
        );
    }

    #[test]
    fn rejects_invalid_claims() {
        for (payload, claim) in [
            (r#"{"nbf":"1","exp":1}"#, DateClaim::NotBefore),
            (r#"{"nbf":-5,"exp":1}"#, DateClaim::NotBefore),
            (r#"{"nbf":1.5,"exp":1}"#, DateClaim::NotBefore),
            (r#"{"nbf":1,"exp":null}"#, DateClaim::Expiry),
            (r#"{"nbf":1,"exp":18446744073709551615}"#, DateClaim::Expiry),
        ] {
            assert_eq!(
                WLCGToken::parse(&jwt(payload)),
                Err(TokenParseError::InvalidDateClaim(claim)),
                "{payload}"
            );
        }
    }

    #[test]
    fn error_messages_name_the_claim() {
        assert_eq!(
            TokenParseError::MissingDateClaim(DateClaim::NotBefore).to_string(),
            "Token does not contain a `nbf` claim"
        );
    }
}
