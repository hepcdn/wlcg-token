use std::{
    sync::LazyLock,
    thread,
    time::{Duration, SystemTime},
};

use arc_swap::ArcSwap;
use thiserror::Error;

use crate::{
    WLCGToken,
    discovery::{TokenDiscoveryError, load_raw_token},
    token::TokenParseError,
};

/// Token provider error
#[derive(Clone, Debug, Error)]
pub enum TokenProviderError {
    #[error("Failed to discover token: {0}")]
    DiscoveryError(#[from] TokenDiscoveryError),
    #[error("Failed to parse token: {0}")]
    ParseError(#[from] TokenParseError),
}

/// Global token cache
static TOKEN_CACHE: LazyLock<ArcSwap<Result<WLCGToken, TokenProviderError>>> =
    LazyLock::new(|| {
        ArcSwap::from_pointee(Err(TokenProviderError::DiscoveryError(
            TokenDiscoveryError::NoTokenFound,
        )))
    });

/// Global token refresh thread handle
static TOKEN_REFRESH_THREAD: LazyLock<thread::JoinHandle<()>> = LazyLock::new(|| {
    // How often to retry token discovery if the token is dead (or not yet discovered).
    let token_poll_interval = std::env::var("WLCG_TOKEN_POLL_INTERVAL")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or_else(|| Duration::from_secs(60));
    // Start-up: block until we have a token, then spawn the refresh thread
    TOKEN_CACHE.store(refresh_token().into());
    thread::spawn(move || {
        loop {
            let exp_in = match TOKEN_CACHE.load().as_ref() {
                Ok(token) => token
                    .expiry()
                    .duration_since(SystemTime::now())
                    .unwrap_or_default(),
                Err(_) => Default::default(),
            };
            let sleep_time = (exp_in / 2).max(token_poll_interval);
            thread::sleep(sleep_time);
            TOKEN_CACHE.store(refresh_token().into());
        }
    })
});

fn refresh_token() -> Result<WLCGToken, TokenProviderError> {
    let raw_token = load_raw_token()?;
    let token = WLCGToken::parse(&raw_token)?;
    Ok(token)
}

/// Load the current token
///
/// Fetches the current token from the global cache, which is automatically
/// refreshed when the token nears expiry via an internal background thread.
/// The cache is populated following the token discovery protocol, as
/// described in [`crate::discovery::load_raw_token`].
///
/// When a token is not available, the environment is polled for a new token
/// every 60 seconds or the interval specified by the `WLCG_TOKEN_POLL_INTERVAL`
/// environment variable.
pub fn load_token() -> Result<WLCGToken, TokenProviderError> {
    // Ensure the refresh thread is started
    let _ = TOKEN_REFRESH_THREAD;
    TOKEN_CACHE.load().as_ref().clone()
}
