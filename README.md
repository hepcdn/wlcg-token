WLCG Token library
------------------

This Rust library provides functionality for discovering and using JWT tokens
for authentication in distributed computing environments according to the
[Worldwide LHC Computing Grid](https://wlcg.web.cern.ch/) token usage
[protocol](https://github.com/WLCG-AuthZ-WG/common-jwt-profile/tree/master).  It
includes modules for token discovery, a runtime cache with automated reload when
the token nears expiry, and a user-friendly authorization provider middleware
for use with the [`reqwest`](https://crates.io/crates/reqwest) HTTP client.

## Example usage

The main entry point for this library is the `load_token()` function, which
returns a `WLCGToken` struct containing the raw token string and parsed claims
related to the token's validity (`nbf` and `exp`).  The token is automatically
discovered and cached, and will be refreshed when it nears expiry.

```rust
use wlcg_token::{load_token, WLCGToken};

let token: WLCGToken = load_token().expect("Failed to load WLCG token");
```

## Example usage with reqwest

Add the following to your `Cargo.toml`:

```toml
[dependencies]
wlcg-token = { version = "0.1", features = ["reqwest"] }
reqwest = "0.13"
reqwest-middleware = "0.5"
tokio = { version = "1", features = ["rt", "net"] }
anyhow = "1"
```

Then use the library as follows:

```rust
use reqwest_middleware::ClientBuilder;
use wlcg_token::reqwest::WLCGTokenAuthMiddleware;

async fn example() -> anyhow::Result<()> {
    let client = ClientBuilder::new(reqwest::Client::new())
        .with(WLCGTokenAuthMiddleware::try_new()?)
        .build();

    let _response = client.get("https://example.com").send().await?;
    Ok(())
}

fn main() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Failed to create Tokio runtime");
    rt.block_on(example()).unwrap();
}
```

## Related crates

The [`scitokens`](https://crates.io/crates/scitokens) crate provides a more
server-oriented implementation of the WLCG token protocol, including token
generation, signing, and verification.  This crate is focused on the client-side
usage of WLCG tokens, including discovery and caching.