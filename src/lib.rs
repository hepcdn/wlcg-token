//! WLCG Token library
//!
//! This library provides functionality for discovering and using JWT tokens
//! for authentication in distributed computing environments according to the
//! [Worldwide LHC Computing Grid](https://wlcg.web.cern.ch/) token usage
//! [protocol](https://github.com/WLCG-AuthZ-WG/common-jwt-profile/tree/master).
//! It includes modules for token discovery, a runtime cache with automated
//! reload when the token nears expiry, and a user-friendly authorization
//! provider middleware for use with the `reqwest` HTTP client.

mod discovery;
mod provider;
#[cfg(feature = "reqwest")]
pub mod reqwest;
mod token;

pub use discovery::{TokenDiscoveryError, TokenFileSource, load_raw_token};
pub use provider::{TokenProviderError, load_token};
pub use token::{DateClaim, TokenParseError, WLCGToken};
