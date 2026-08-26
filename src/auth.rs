use std::time::{Duration, Instant};

use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk::JwkSet};
use serde::Deserialize;
use tokio::sync::RwLock;

use crate::errors::Error;

const JWKS_REFRESH_INTERVAL: Duration = Duration::from_secs(3600);

/// Validates JWTs from a single OIDC issuer via its published JWKS. Used both
/// for GitHub Actions id-tokens (uploads) and for the management-plane OIDC
/// issuer; keys are cached and refreshed lazily (including once on an unknown
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

/// Management-plane claims: identity only, used for audit logging.
#[derive(Debug, Clone, Deserialize)]
pub struct ManagementClaims {
    #[serde(default)]
    pub sub: String,
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
