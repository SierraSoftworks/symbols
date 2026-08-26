use std::borrow::Cow;
use std::time::{Duration, Instant};

use filt_rs::{Filter, FilterValue, Filterable};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk::JwkSet};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::RwLock;

use crate::errors::Error;

/// The claims a validated token carried, kept verbatim (rather than parsed
/// into a fixed struct) so that the management ACL can match on whatever the
/// issuer chose to assert — groups, email, custom claims and all.
pub type Claims = serde_json::Map<String, Value>;

const JWKS_REFRESH_INTERVAL: Duration = Duration::from_secs(3600);

/// Validates JWTs from a single OIDC issuer via its published JWKS. Used both
/// for GitHub Actions id-tokens (uploads) and for the management-plane OIDC
/// client; keys are cached and refreshed lazily (including once on an unknown
/// `kid`, so key rotations don't require a restart).
pub struct Validator {
    http: reqwest::Client,
    issuer: String,
    audience: String,
    keys: RwLock<Option<CachedKeys>>,
}

struct CachedKeys {
    set: JwkSet,
    fetched_at: Instant,
}

#[derive(Deserialize)]
struct OidcDiscovery {
    jwks_uri: String,
}

impl Validator {
    pub fn new(http: reqwest::Client, issuer: &str, audience: &str) -> Self {
        Self {
            http,
            issuer: issuer.trim_end_matches('/').to_string(),
            audience: audience.to_string(),
            keys: RwLock::new(None),
        }
    }

    async fn fetch_keys(&self) -> Result<JwkSet, Error> {
        let discovery_url = format!("{}/.well-known/openid-configuration", self.issuer);
        let discovery: OidcDiscovery = self
            .http
            .get(&discovery_url)
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .map_err(|e| Error::Unauthenticated(format!("OIDC discovery failed: {e}")))?
            .json()
            .await
            .map_err(|e| Error::Unauthenticated(format!("OIDC discovery malformed: {e}")))?;

        self.http
            .get(&discovery.jwks_uri)
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .map_err(|e| Error::Unauthenticated(format!("JWKS fetch failed: {e}")))?
            .json()
            .await
            .map_err(|e| Error::Unauthenticated(format!("JWKS malformed: {e}")))
    }

    async fn key_for(&self, kid: &str, allow_refresh: bool) -> Result<Option<DecodingKey>, Error> {
        {
            let cached = self.keys.read().await;
            if let Some(cached) = cached.as_ref() {
                if cached.fetched_at.elapsed() < JWKS_REFRESH_INTERVAL {
                    if let Some(jwk) = cached.set.find(kid) {
                        return Ok(Some(DecodingKey::from_jwk(jwk).map_err(|e| {
                            Error::Unauthenticated(format!("unusable JWK: {e}"))
                        })?));
                    }
                    if !allow_refresh {
                        return Ok(None);
                    }
                }
            }
        }

        let set = self.fetch_keys().await?;
        let key = set
            .find(kid)
            .map(DecodingKey::from_jwk)
            .transpose()
            .map_err(|e| Error::Unauthenticated(format!("unusable JWK: {e}")))?;
        *self.keys.write().await = Some(CachedKeys {
            set,
            fetched_at: Instant::now(),
        });
        Ok(key)
    }

    /// Validates the token's signature, issuer, audience and expiry, returning
    /// its claims.
    pub async fn validate<C: serde::de::DeserializeOwned>(&self, token: &str) -> Result<C, Error> {
        let header = decode_header(token)
            .map_err(|e| Error::Unauthenticated(format!("malformed token: {e}")))?;
        let kid = header
            .kid
            .ok_or_else(|| Error::Unauthenticated("token missing key id".to_string()))?;

        let key = match self.key_for(&kid, true).await? {
            Some(key) => key,
            None => {
                return Err(Error::Unauthenticated(format!(
                    "unknown signing key '{kid}'"
                )));
            }
        };

        let mut validation = Validation::new(header.alg);
        // GitHub signs with RS256; tsidp with RS256/ES256. Restrict to
        // asymmetric algorithms so an HS256 token can never be validated
        // against public key material.
        if matches!(header.alg, Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512) {
            return Err(Error::Unauthenticated("symmetric algorithms are not accepted".to_string()));
        }
        validation.set_audience(&[&self.audience]);
        validation.set_issuer(&[&self.issuer]);

        let data = decode::<C>(token, &key, &validation)
            .map_err(|e| Error::Unauthenticated(format!("token rejected: {e}")))?;
        Ok(data.claims)
    }
}

/// The GitHub Actions OIDC claims the server acts on.
/// See https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect
#[derive(Debug, Clone, Deserialize)]
pub struct GithubClaims {
    /// "org/repo" — becomes the project name.
    pub repository: String,
    /// The org (or user) owning the repository; checked against trusted_orgs.
    pub repository_owner: String,
    /// "public", "private" or "internal" — seeds the project's visibility.
    #[serde(default)]
    pub repository_visibility: Option<String>,
    /// e.g. "refs/tags/v1.2.3".
    #[serde(rename = "ref", default)]
    pub git_ref: Option<String>,
}

/// Pulls a bearer token out of an Authorization header.
pub fn bearer_token(req: &actix_web::HttpRequest) -> Result<String, Error> {
    let header = req
        .headers()
        .get(actix_web::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| Error::Unauthenticated("missing Authorization header".to_string()))?;
    header
        .strip_prefix("Bearer ")
        .or_else(|| header.strip_prefix("bearer "))
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .ok_or_else(|| Error::Unauthenticated("expected a bearer token".to_string()))
}

/// The authenticated management-plane user, whichever way they authenticated
/// (bearer token from the management issuer, or a browser session cookie
/// minted by the OIDC sign-in flow). Either way the identity is just the
/// claims the issuer asserted, which is what the ACL is written against.
#[derive(Debug, Clone, Default)]
pub struct Identity {
    pub claims: Claims,
}

impl Identity {
    pub fn new(claims: Claims) -> Self {
        Self { claims }
    }

    fn claim(&self, name: &str) -> Option<&str> {
        self.claims.get(name).and_then(Value::as_str)
    }

    /// The issuer's stable identifier for the user, used in audit logs.
    pub fn subject(&self) -> &str {
        self.claim("sub").unwrap_or("<unknown>")
    }

    pub fn email(&self) -> Option<&str> {
        self.claim("email")
    }

    /// The friendliest name the token offers, if any.
    pub fn name(&self) -> Option<&str> {
        self.claim("name").or_else(|| self.claim("preferred_username"))
    }

    /// Applies the management ACL to this request. A filter that fails to
    /// evaluate (say it compares a claim the token didn't carry with an
    /// operator that can't cope) denies the request: an ACL that can't be
    /// decided is not an ACL that passed.
    pub fn check_acl(&self, acl: &Filter, method: &str, path: &str) -> Result<(), Error> {
        let request = AccessRequest {
            method,
            path,
            claims: &self.claims,
        };
        match acl.matches(&request) {
            Ok(true) => Ok(()),
            Ok(false) => Err(Error::Forbidden(format!(
                "'{}' is not permitted to use this server's management plane",
                self.subject()
            ))),
            Err(e) => {
                tracing::error!(acl = %acl.raw(), "Management ACL failed to evaluate: {e}");
                Err(Error::Forbidden(
                    "this server's management ACL could not be evaluated".to_string(),
                ))
            }
        }
    }
}

/// Exposes a management request to the ACL expression: the HTTP `method` and
/// `path`, plus every validated token claim under the `claims.` prefix (e.g.
/// `claims.email`). Unknown keys resolve to null, matching `filt-rs`'s own
/// convention.
struct AccessRequest<'a> {
    method: &'a str,
    path: &'a str,
    claims: &'a Claims,
}

impl Filterable for AccessRequest<'_> {
    fn get(&self, key: &str) -> FilterValue<'_> {
        match key {
            "method" => FilterValue::String(Cow::Borrowed(self.method)),
            "path" => FilterValue::String(Cow::Borrowed(self.path)),
            key => match key.strip_prefix("claims.") {
                Some(claim) => self
                    .claims
                    .get(claim)
                    .map(json_to_filter_value)
                    .unwrap_or(FilterValue::Null),
                None => FilterValue::Null,
            },
        }
    }
}

fn json_to_filter_value(value: &Value) -> FilterValue<'_> {
    match value {
        Value::Null => FilterValue::Null,
        Value::Bool(b) => FilterValue::Bool(*b),
        Value::Number(n) => FilterValue::Number(n.as_f64().unwrap_or(0.0)),
        Value::String(s) => FilterValue::String(Cow::Borrowed(s)),
        Value::Array(items) => FilterValue::Tuple(items.iter().map(json_to_filter_value).collect()),
        // Object-valued claims have no scalar filter representation; treat
        // them as absent.
        Value::Object(_) => FilterValue::Null,
    }
}

/// The name of the browser session cookie.
pub const SESSION_COOKIE: &str = "symbols_session";
/// The name of the short-lived cookie carrying OIDC login-flow state.
pub const LOGIN_COOKIE: &str = "symbols_login";

/// `aud` values distinguishing the two kinds of locally minted tokens, so a
/// login-state token can never be replayed as a session (and vice versa).
const SESSION_AUDIENCE: &str = "symbols/session";
const LOGIN_AUDIENCE: &str = "symbols/login";

/// A browser session. The identity's claims are carried inside (nested, not
/// flattened, so the provider's own `aud`/`exp` can never shadow ours) rather
/// than reduced to a subject: the ACL is evaluated on every request, so it
/// needs the same claims a bearer token would have supplied — and a tightened
/// ACL then applies to sessions already in flight.
#[derive(Debug, Serialize, Deserialize)]
struct SessionClaims {
    aud: String,
    exp: i64,
    claims: Claims,
}

/// The state we need to survive the round-trip to the OIDC provider. Signed
/// into a short-lived cookie rather than stored server-side, so the flow is
/// stateless and restart-tolerant (unless the session secret is per-boot).
#[derive(Debug, Serialize, Deserialize)]
pub struct LoginState {
    aud: String,
    exp: i64,
    /// CSRF token echoed back by the provider via the `state` parameter.
    pub state: String,
    /// PKCE code verifier for the token exchange.
    pub pkce_verifier: String,
    /// Nonce expected inside the resulting id-token.
    pub nonce: String,
    /// Local path to return the user to after sign-in.
    pub next: String,
}

/// Mints and verifies the HS256 tokens this server issues to browsers
/// (session cookies and login-flow state). This is deliberately separate from
/// [`Validator`]: that type verifies *other issuers'* asymmetric tokens and
/// rejects HMAC algorithms outright; these tokens are ours, signed with a
/// local secret that never leaves the process.
pub struct Sessions {
    encoding: jsonwebtoken::EncodingKey,
    decoding: jsonwebtoken::DecodingKey,
    session_duration: Duration,
}

const LOGIN_STATE_DURATION: Duration = Duration::from_secs(10 * 60);

impl Sessions {
    pub fn new(secret: &[u8], session_duration: Duration) -> Self {
        Self {
            encoding: jsonwebtoken::EncodingKey::from_secret(secret),
            decoding: jsonwebtoken::DecodingKey::from_secret(secret),
            session_duration,
        }
    }

    /// A `Sessions` with a random per-boot secret (the default when no
    /// `session_secret` is configured).
    pub fn ephemeral(session_duration: Duration) -> Self {
        let secret: [u8; 32] = rand::random();
        Self::new(&secret, session_duration)
    }

    fn mint<C: serde::Serialize>(&self, claims: &C) -> Result<String, Error> {
        jsonwebtoken::encode(
            &jsonwebtoken::Header::new(Algorithm::HS256),
            claims,
            &self.encoding,
        )
        .map_err(|e| Error::Internal(format!("signing session token: {e}")))
    }

    fn verify<C: serde::de::DeserializeOwned>(
        &self,
        token: &str,
        audience: &str,
    ) -> Result<C, Error> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_audience(&[audience]);
        validation.set_required_spec_claims(&["exp", "aud"]);
        decode::<C>(token, &self.decoding, &validation)
            .map(|data| data.claims)
            .map_err(|e| Error::Unauthenticated(format!("invalid session: {e}")))
    }

    pub fn issue_session(&self, identity: &Identity) -> Result<String, Error> {
        self.mint(&SessionClaims {
            aud: SESSION_AUDIENCE.to_string(),
            exp: (chrono::Utc::now()
                + chrono::Duration::from_std(self.session_duration)
                    .unwrap_or_else(|_| chrono::Duration::hours(8)))
            .timestamp(),
            claims: identity.claims.clone(),
        })
    }

    pub fn verify_session(&self, token: &str) -> Result<Identity, Error> {
        let session: SessionClaims = self.verify(token, SESSION_AUDIENCE)?;
        Ok(Identity::new(session.claims))
    }

    pub fn session_duration(&self) -> Duration {
        self.session_duration
    }

    pub fn issue_login_state(
        &self,
        state: &str,
        pkce_verifier: &str,
        nonce: &str,
        next: &str,
    ) -> Result<String, Error> {
        self.mint(&LoginState {
            aud: LOGIN_AUDIENCE.to_string(),
            exp: (chrono::Utc::now() + chrono::Duration::seconds(LOGIN_STATE_DURATION.as_secs() as i64))
                .timestamp(),
            state: state.to_string(),
            pkce_verifier: pkce_verifier.to_string(),
            nonce: nonce.to_string(),
            next: next.to_string(),
        })
    }

    pub fn verify_login_state(&self, token: &str) -> Result<LoginState, Error> {
        self.verify(token, LOGIN_AUDIENCE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> Identity {
        Identity::new(
            serde_json::json!({
                "sub": "user-1",
                "email": "Benjamin@example.com",
                "name": "Benjamin",
                "groups": ["symbols-admins", "everyone"],
            })
            .as_object()
            .unwrap()
            .clone(),
        )
    }

    fn acl(expression: &str) -> Filter {
        Filter::new(expression).unwrap()
    }

    #[test]
    fn session_roundtrip() {
        let sessions = Sessions::new(b"secret", Duration::from_secs(3600));
        let token = sessions.issue_session(&identity()).unwrap();
        let restored = sessions.verify_session(&token).unwrap();
        assert_eq!(restored.subject(), "user-1");
        assert_eq!(restored.email(), Some("Benjamin@example.com"));
        // Every claim survives the round-trip, so the ACL sees the same thing
        // it would have seen on a bearer token.
        assert_eq!(restored.claims, identity().claims);
    }

    #[test]
    fn sessions_from_other_secrets_are_rejected() {
        let ours = Sessions::new(b"secret", Duration::from_secs(3600));
        let theirs = Sessions::new(b"other", Duration::from_secs(3600));
        let token = theirs.issue_session(&identity()).unwrap();
        assert!(ours.verify_session(&token).is_err());
    }

    #[test]
    fn login_state_is_not_a_session() {
        // A login-state token presented as a session cookie must fail (and
        // vice versa) — the audiences differ.
        let sessions = Sessions::new(b"secret", Duration::from_secs(3600));
        let login = sessions
            .issue_login_state("state", "verifier", "nonce", "/")
            .unwrap();
        assert!(sessions.verify_session(&login).is_err());
        let session = sessions.issue_session(&identity()).unwrap();
        assert!(sessions.verify_login_state(&session).is_err());
    }

    #[test]
    fn acl_matches_on_claims() {
        let id = identity();
        assert!(id.check_acl(&acl("true"), "GET", "/").is_ok());
        assert!(id.check_acl(&acl("false"), "GET", "/").is_err());
        assert!(id.check_acl(&acl(r#"claims.sub == "user-1""#), "GET", "/").is_ok());
        // Strings compare case-insensitively, as everywhere in filt-rs.
        assert!(
            id.check_acl(&acl(r#"claims.email == "benjamin@example.com""#), "GET", "/")
                .is_ok()
        );
        assert!(
            id.check_acl(&acl(r#"claims.email endswith "@elsewhere.com""#), "GET", "/")
                .is_err()
        );
        // List-valued claims (groups being the useful one) become tuples.
        assert!(
            id.check_acl(&acl(r#"claims.groups contains "symbols-admins""#), "GET", "/")
                .is_ok()
        );
        // A claim the token didn't carry is null, which matches nothing.
        assert!(id.check_acl(&acl(r#"claims.nope == "x""#), "GET", "/").is_err());
    }

    #[test]
    fn acl_matches_on_method_and_path() {
        // A read-only viewer: anything but a GET is denied.
        let read_only = acl(r#"method == "GET" || claims.groups contains "owners""#);
        let id = identity();
        assert!(id.check_acl(&read_only, "GET", "/api/v1/projects").is_ok());
        assert!(id.check_acl(&read_only, "DELETE", "/api/v1/projects").is_err());
        assert!(
            id.check_acl(&acl(r#"path startswith "/api/""#), "GET", "/api/v1/stats")
                .is_ok()
        );
    }

    #[test]
    fn acl_denial_is_forbidden_not_unauthenticated() {
        // The distinction matters to the UI: a 401 bounces the browser into
        // the sign-in flow, which would loop forever for a signed-in user the
        // ACL rejects.
        assert!(matches!(
            identity().check_acl(&acl("false"), "GET", "/"),
            Err(Error::Forbidden(_))
        ));
    }
}
