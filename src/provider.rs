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

/// Refresh the token once it has less than this long left to live.
///
/// WLCG tokens typically live for ~1 hour and are renewed by an external agent
/// (e.g. `htgettoken`) well before expiry, so 5 minutes leaves plenty of
/// room while still polling at `token_poll_interval` near the end.
const REFRESH_MARGIN: Duration = Duration::from_secs(5 * 60);

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
            // Sleep until the token enters its refresh margin; once inside the
            // margin (or with no token at all) fall back to plain polling.
            let sleep_time = match TOKEN_CACHE.load().as_ref() {
                Ok(token) => token
                    .expiry()
                    .duration_since(SystemTime::now())
                    .unwrap_or_default()
                    .saturating_sub(REFRESH_MARGIN)
                    .max(token_poll_interval),
                Err(_) => token_poll_interval,
            };
            thread::sleep(sleep_time);

            let token = refresh_token();
            let change_token = match (TOKEN_CACHE.load().as_ref(), &token) {
                // Only trade a live token for one that outlives it
                (Ok(old), Ok(new)) if old.is_valid() => {
                    new.is_valid() && new.expiry() > old.expiry()
                }
                // A dead token is worth replacing with anything, even an error,
                // so callers learn why no token is available
                (Ok(_), _) => true,
                (Err(_), Ok(_)) => true,
                // A new error may be more informative than the old one
                (Err(_), Err(_)) => true,
            };
            if change_token {
                TOKEN_CACHE.store(token.into());
            }
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
/// described in [`load_raw_token`](crate::load_raw_token).
///
/// When a token is not available, the environment is polled for a new token
/// every 60 seconds or the interval specified by the `WLCG_TOKEN_POLL_INTERVAL`
/// environment variable. A live token is re-read from the environment once it
/// is within 5 minutes of expiry, and replaced only by a token that outlives it.
///
/// When the token cannot be discovered or is invalid, an error is returned. The
/// error may change over time as the environment is polled for a new token.
/// Callers should handle the error and retry the call to [`load_token()`] if
/// appropriate.
pub fn load_token() -> Result<WLCGToken, TokenProviderError> {
    // Ensure the refresh thread is started
    LazyLock::force(&TOKEN_REFRESH_THREAD);
    TOKEN_CACHE.load().as_ref().clone()
}
