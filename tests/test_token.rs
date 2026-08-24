use wlcg_token::{WLCGToken, load_token};

/// Test token generated from json:
/// ```json
/// {
///    "wlcg.ver": "1.0",
///    "sub": "73f16d93-2441-4a50-88ff-85360d78c6b5",
///    "iss": "https://wlcg.cloud.cern.ch/",
///    "aud": "https://wlcg.cern.ch/jwt/v1/any",
///    "client_id": "b47eb46a-f2dc-4a7e-b0c8-2f1e81dd5d4a",
///    "exp": 2782655200,
///    "nbf": 1782651600,
///    "iat": 1782651600,
///    "jti": "2500cda3-9ea7-46c5-a393-20e4031319f3",
///    "scope": "openid profile storage.read:/ storage.modify:/"
/// }
/// ```
/// with https://www.jwt.io/ generator using the secret
/// `old-mcdonald-had-a-farm-eieio-and-on-that-farm-he-had-some-cows`
const TEST_TOKEN_RAW: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ3bGNnLnZlciI6IjEuMCIsInN1YiI6IjczZjE2ZDkzLTI0NDEtNGE1MC04OGZmLTg1MzYwZDc4YzZiNSIsImlzcyI6Imh0dHBzOi8vd2xjZy5jbG91ZC5jZXJuLmNoLyIsImF1ZCI6Imh0dHBzOi8vd2xjZy5jZXJuLmNoL2p3dC92MS9hbnkiLCJjbGllbnRfaWQiOiJiNDdlYjQ2YS1mMmRjLTRhN2UtYjBjOC0yZjFlODFkZDVkNGEiLCJleHAiOjI3ODI2NTUyMDAsIm5iZiI6MTc4MjY1MTYwMCwiaWF0IjoxNzgyNjUxNjAwLCJqdGkiOiIyNTAwY2RhMy05ZWE3LTQ2YzUtYTM5My0yMGU0MDMxMzE5ZjMiLCJzY29wZSI6Im9wZW5pZCBwcm9maWxlIHN0b3JhZ2UucmVhZDovIHN0b3JhZ2UubW9kaWZ5Oi8ifQ.NOgFcphX6SsPeLfP0tB43dxkeu9PjYLnKlIXyD5YwLg";

#[test]
fn test_token_is_valid() {
    let token = WLCGToken::parse(TEST_TOKEN_RAW).expect("Failed to parse test token");

    assert!(
        token.is_valid(),
        "Test token should be valid unless this is run after 2058"
    );
}

#[test]
fn test_token_load_env() {
    // The cache is populated on first call and held in a global, so the
    // variable only needs to be set while the provider initialises.
    temp_env::with_var("BEARER_TOKEN", Some(TEST_TOKEN_RAW), || {
        let token = load_token().expect("Failed to load token from environment");
        assert_eq!(token.raw(), TEST_TOKEN_RAW);
    });
}
