//! Middleware for use with reqwest to inject the authorization token
//!
//! Provides [`WLCGTokenAuthMiddleware`] which can be used with
//! [`reqwest_middleware`] to inject the authorization token into requests.
//!
//! # Example
//! ```
//! use reqwest_middleware::ClientBuilder;
//! use wlcg_token::reqwest::WLCGTokenAuthMiddleware;
//!
//! let client = ClientBuilder::new(reqwest::Client::new())
//!     .with(WLCGTokenAuthMiddleware::try_new().expect("Failed to create WLCGTokenAuthMiddleware"))
//!     .build();
//!
//! let response = client.get("https://example.com").send().await.expect("Request failed");
//! ```
use anyhow::anyhow;
use async_trait::async_trait;
use reqwest::{Request, Response, header::AUTHORIZATION};
use reqwest_middleware::{Middleware, Next};

use crate::{TokenProviderError, load_token};

pub struct WLCGTokenAuthMiddleware {}

impl WLCGTokenAuthMiddleware {
    /// Create a new instance of the middleware
    ///
    /// Will return an error if a token cannot be discovered in the environment or default locations
    /// at the time of creation. The middleware will continue to poll for a token in the background
    /// if one is not available.
    pub fn try_new() -> Result<Self, TokenProviderError> {
        // Attempt to load the token to ensure it is available
        let _ = load_token()?;
        Ok(WLCGTokenAuthMiddleware {})
    }
}

#[async_trait]
impl Middleware for WLCGTokenAuthMiddleware {
    async fn handle(
        &self,
        mut req: Request,
        extensions: &mut http::Extensions,
        next: Next<'_>,
    ) -> reqwest_middleware::Result<Response> {
        let token = load_token().map_err(|e| anyhow!("Failed to load WLCG token: {}", e))?;
        let mut auth_value =
            reqwest::header::HeaderValue::from_str(format!("Bearer {}", token.raw()).as_str())
                .expect("token became malformed in runtime");
        auth_value.set_sensitive(true);
        req.headers_mut().insert(AUTHORIZATION, auth_value);

        next.run(req, extensions).await
    }
}
