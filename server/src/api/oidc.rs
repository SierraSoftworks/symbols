//! Browser sign-in for the management UI: the OIDC authorization-code flow
//! with PKCE, run entirely server-side (the UI is SSR-only, so there is no
//! client to run a popup flow the way grey's SPA does).
//!
//! `GET /auth/login` redirects to the provider with `state`, `nonce` and a
//! PKCE challenge, remembering all three in a short-lived signed cookie.
//! `GET /auth/callback` verifies that cookie, exchanges the code (with the
//! client secret, which never reaches the browser), validates the id-token
//! against the issuer's JWKS, and mints the session cookie. CSRF on the
//! session is covered by SameSite=Lax: cross-site POSTs never carry it.

use std::sync::Arc;
use std::time::{Duration, Instant};

use actix_web::cookie::{Cookie, SameSite};
use actix_web::{HttpRequest, HttpResponse, web};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;

use super::{AppState, pages};
use crate::auth::{Claims, Identity, LOGIN_COOKIE, SESSION_COOKIE};
use crate::errors::Error;

const ENDPOINT_CACHE_TTL: Duration = Duration::from_secs(3600);

#[derive(Debug, Clone, Deserialize)]
pub struct Endpoints {
    pub authorization_endpoint: String,
    pub token_endpoint: String,
}

/// Caches the issuer's discovery document (we need the authorization and
/// token endpoints; JWKS caching lives in [`crate::auth::Validator`]).
pub struct EndpointCache {
    http: reqwest::Client,
    issuer: String,
    cached: RwLock<Option<(Endpoints, Instant)>>,
}

impl EndpointCache {
    pub fn new(http: reqwest::Client, issuer: &str) -> Self {
        Self {
            http,
            issuer: issuer.trim_end_matches('/').to_string(),
            cached: RwLock::new(None),
        }
    }

    pub async fn get(&self) -> Result<Endpoints, Error> {
        {
            let cached = self.cached.read().await;
            if let Some((endpoints, fetched_at)) = cached.as_ref() {
                if fetched_at.elapsed() < ENDPOINT_CACHE_TTL {
                    return Ok(endpoints.clone());
                }
            }
        }

        let url = format!("{}/.well-known/openid-configuration", self.issuer);
        let endpoints: Endpoints = self
            .http
            .get(&url)
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .map_err(|e| Error::Upstream(format!("OIDC discovery failed: {e}")))?
            .json()
            .await
            .map_err(|e| Error::Upstream(format!("OIDC discovery malformed: {e}")))?;

        *self.cached.write().await = Some((endpoints.clone(), Instant::now()));
        Ok(endpoints)
    }
}

/// The base URL the user's browser reached us on, trusting the reverse
/// proxy's Forwarded/X-Forwarded-* headers. Deriving the redirect URI from it
/// is safe because the provider only accepts pre-registered redirect URIs.
fn base_url(req: &HttpRequest) -> (String, bool) {
    let info = req.connection_info();
    let https = info.scheme() == "https";
    (format!("{}://{}", info.scheme(), info.host()), https)
}

fn random_token() -> String {
    let bytes: [u8; 32] = rand::random();
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Only ever redirect back to a local path — anything else (absolute URLs,
/// scheme-relative "//host") would make `?next=` an open redirect.
fn sanitize_next(next: Option<&str>) -> String {
    match next {
        Some(next)
            if next.starts_with('/')
                && !next.starts_with("//")
                && !next.contains('\\')
                && !next.contains("://")
                && !next.chars().any(|c| c.is_control()) =>
        {
            next.to_string()
        }
        _ => "/".to_string(),
    }
}

#[derive(Debug, Deserialize)]
pub struct LoginQuery {
    #[serde(default)]
    pub next: Option<String>,
}

pub async fn login(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    query: web::Query<LoginQuery>,
) -> Result<HttpResponse, Error> {
    let oidc_config = &state.config.management.oidc;
    let endpoints = state.oidc_endpoints.get().await?;

    let csrf_state = random_token();
    let nonce = random_token();
    let pkce_verifier = random_token();
    let pkce_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(pkce_verifier.as_bytes()));
    let next = sanitize_next(query.next.as_deref());

    let (base, https) = base_url(&req);
    let redirect_uri = format!("{base}/auth/callback");

    let mut authorize_url = url::Url::parse(&endpoints.authorization_endpoint)
        .map_err(|e| Error::Upstream(format!("invalid authorization endpoint: {e}")))?;
    authorize_url
        .query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &oidc_config.client_id)
        .append_pair("redirect_uri", &redirect_uri)
        .append_pair("scope", &oidc_config.scopes.join(" "))
        .append_pair("state", &csrf_state)
        .append_pair("nonce", &nonce)
        .append_pair("code_challenge", &pkce_challenge)
        .append_pair("code_challenge_method", "S256");

    let login_state = state
        .sessions
        .issue_login_state(&csrf_state, &pkce_verifier, &nonce, &next)?;
    let cookie = Cookie::build(LOGIN_COOKIE, login_state)
        .path("/auth")
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(https)
        .max_age(actix_web::cookie::time::Duration::minutes(10))
        .finish();

    Ok(HttpResponse::Found()
        .cookie(cookie)
        .insert_header((actix_web::http::header::LOCATION, authorize_url.to_string()))
        .finish())
}

#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub error_description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    id_token: Option<String>,
}

pub async fn callback(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    query: web::Query<CallbackQuery>,
) -> Result<HttpResponse, Error> {
    let oidc_config = &state.config.management.oidc;

    if let Some(error) = &query.error {
        let detail = query.error_description.as_deref().unwrap_or(error);
        return Ok(pages::error_page(400, &format!("Sign-in failed: {detail}")).await);
    }

    let login_state = match req
        .cookie(LOGIN_COOKIE)
        .and_then(|c| state.sessions.verify_login_state(c.value()).ok())
    {
        Some(login_state) => login_state,
        None => {
            return Ok(pages::error_page(
                400,
                "Sign-in session expired or missing — please try signing in again.",
            )
            .await);
        }
    };

    let (Some(code), Some(returned_state)) = (query.code.as_deref(), query.state.as_deref())
    else {
        return Ok(pages::error_page(400, "Malformed sign-in callback.").await);
    };
    if returned_state != login_state.state {
        return Ok(pages::error_page(400, "Sign-in state mismatch — please try again.").await);
    }

    let (base, https) = base_url(&req);
    let redirect_uri = format!("{base}/auth/callback");
    let endpoints = state.oidc_endpoints.get().await?;

    let token_response: TokenResponse = state
        .http
        .post(&endpoints.token_endpoint)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", &redirect_uri),
            ("client_id", &oidc_config.client_id),
            ("client_secret", &oidc_config.client_secret),
            ("code_verifier", &login_state.pkce_verifier),
        ])
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|e| Error::Upstream(format!("OIDC code exchange failed: {e}")))?
        .json()
        .await
        .map_err(|e| Error::Upstream(format!("OIDC token response malformed: {e}")))?;

    let Some(id_token) = token_response.id_token else {
        return Err(Error::Upstream(
            "OIDC token response carried no id_token".to_string(),
        ));
    };

    // Signature, issuer, audience (our client id) and expiry are enforced by
    // the validator; the nonce ties the token to this browser's login.
    let claims: Claims = state.management_auth.validate(&id_token).await?;
    if claims.get("nonce").and_then(|n| n.as_str()) != Some(login_state.nonce.as_str()) {
        return Ok(pages::error_page(400, "Sign-in nonce mismatch — please try again.").await);
    }

    // The ACL is deliberately not applied here: it can discriminate on the
    // request's method and path, and the only path in scope at this point is
    // /auth/callback. Every management request re-evaluates it against what
    // is actually being asked for, so a rejected user signs in and then meets
    // a 403 on the page itself.
    let identity = Identity::new(claims);
    let session = state.sessions.issue_session(&identity)?;
    // The session carries the provider's claims so the ACL can be re-checked
    // on every request. A provider that asserts a great many of them (a long
    // group list, say) could push the cookie past the ~4KB browsers accept,
    // at which point it is dropped silently and sign-in appears to do
    // nothing — so say so rather than leaving it to be puzzled out.
    if session.len() > 3500 {
        tracing::warn!(
            bytes = session.len(),
            subject = %identity.subject(),
            "Session cookie is close to the browser size limit; consider narrowing management.oidc.scopes"
        );
    }
    let session_cookie = Cookie::build(SESSION_COOKIE, session)
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(https)
        .max_age(
            actix_web::cookie::time::Duration::try_from(state.sessions.session_duration())
                .unwrap_or(actix_web::cookie::time::Duration::hours(8)),
        )
        .finish();
    let mut clear_login = Cookie::build(LOGIN_COOKIE, "").path("/auth").finish();
    clear_login.make_removal();

    tracing::info!(subject = %identity.subject(), "Management UI sign-in");
    Ok(HttpResponse::Found()
        .cookie(session_cookie)
        .cookie(clear_login)
        .insert_header((actix_web::http::header::LOCATION, login_state.next))
        .finish())
}

pub async fn logout(req: HttpRequest) -> HttpResponse {
    let (_, https) = base_url(&req);
    let mut clear = Cookie::build(SESSION_COOKIE, "")
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(https)
        .finish();
    clear.make_removal();
    HttpResponse::Found()
        .cookie(clear)
        .insert_header((actix_web::http::header::LOCATION, "/"))
        .finish()
}
