//! Middleware for use with reqwest to inject the authorization token
//!
//! Provides [`WLCGTokenAuthMiddleware`] which can be used with
//! [`reqwest_middleware`] to inject the authorization token into requests.
use anyhow::anyhow;
use async_trait::async_trait;
use reqwest::{Request, Response, header::AUTHORIZATION};
use reqwest_middleware::{Middleware, Next};

use crate::{TokenProviderError, load_token};

pub struct WLCGTokenAuthMiddleware {}

impl WLCGTokenAuthMiddleware {
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
