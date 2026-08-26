use std::sync::Arc;

use actix_web::web;

use crate::auth::{Sessions, Validator};
use crate::config::Config;
use crate::storage::Store;

pub mod assets;
pub mod debuginfod;
pub mod forms;
pub mod management;
pub mod oidc;
pub mod pages;
pub mod upload;

/// Which listener a request arrived on. The internal plane serves every
/// project; the public plane serves only `public` projects (and hides the
/// existence of the rest).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Plane {
    Public,
    Internal,
}

pub struct AppState {
    pub config: Config,
    pub store: Store,
    pub github_auth: Validator,
    pub management_auth: Validator,
    /// Signs/verifies the browser session and login-state cookies.
    pub sessions: Sessions,
    /// Present when browser sign-in (`management.oidc`) is configured.
    pub oidc: Option<OidcRuntime>,
    pub http: reqwest::Client,
}

/// Everything the browser sign-in flow needs beyond static config.
pub struct OidcRuntime {
    /// Validates the id-tokens produced by the code exchange. Distinct from
    /// `management_auth`: id-tokens carry the OAuth client id as audience,
    /// while bearer API tokens carry `management.audience`.
    pub id_tokens: Validator,
    pub endpoints: oidc::EndpointCache,
}

impl AppState {
    pub fn new(config: Config, store: Store, http: reqwest::Client) -> Self {
        let sessions = match &config.management.session_secret {
            Some(secret) => {
                Sessions::new(secret.as_bytes(), config.management.session_duration)
            }
            None => Sessions::ephemeral(config.management.session_duration),
        };
        let oidc = config.management.oidc.as_ref().map(|oidc_config| OidcRuntime {
            id_tokens: Validator::new(
                http.clone(),
                &config.management.issuer,
                &oidc_config.client_id,
            ),
            endpoints: oidc::EndpointCache::new(http.clone(), &config.management.issuer),
        });

        Self {
            github_auth: Validator::new(http.clone(), &config.github.issuer, &config.github.audience),
            management_auth: Validator::new(
                http.clone(),
                &config.management.issuer,
                &config.management.audience,
            ),
            sessions,
            oidc,
            store,
            http,
            config,
        }
    }
}

/// Routes served on both planes: health, the debuginfod read protocol, and
/// symbol uploads (GitHub's OIDC-authenticated CI runners live on the public
/// internet).
fn configure_core(cfg: &mut web::ServiceConfig) {
    cfg.route("/health", web::get().to(health))
        .route(
            "/buildid/{id}/debuginfo",
            web::get().to(debuginfod::get_debuginfo),
        )
        .route(
            "/buildid/{id}/{section}",
            web::get().to(debuginfod::unsupported),
        )
        .route("/api/v1/symbols", web::post().to(upload::upload_symbol));
}

pub fn configure_public(cfg: &mut web::ServiceConfig) {
    configure_core(cfg);
}

/// The internal plane additionally carries the management API and the
/// management UI (pages, form actions, sign-in flow, static assets). Keeping
/// these off the public listener means a management-plane bug is never
/// internet-reachable.
pub fn configure_internal(cfg: &mut web::ServiceConfig) {
    configure_core(cfg);
    cfg
        // Management API (bearer token or browser session).
        .route("/api/v1/projects", web::get().to(management::list_projects))
        .route(
            "/api/v1/projects/{org}/{repo}",
            web::get().to(management::get_project),
        )
        .route(
            "/api/v1/projects/{org}/{repo}",
            web::patch().to(management::update_project),
        )
        .route(
            "/api/v1/projects/{org}/{repo}/symbols",
            web::get().to(management::list_symbols),
        )
        .route(
            "/api/v1/projects/{org}/{repo}/symbols/{id}",
            web::delete().to(management::delete_symbol),
        )
        .route(
            "/api/v1/projects/{org}/{repo}/versions/{version}",
            web::delete().to(management::purge_version),
        )
        .route("/api/v1/stats", web::get().to(management::get_stats))
        .route("/api/v1/sweep", web::post().to(management::run_sweep))
        // Server-rendered management UI.
        .route("/", web::get().to(pages::dashboard))
        .route("/projects/{org}/{repo}", web::get().to(pages::project))
        .route("/setup", web::get().to(pages::setup))
        // Form actions (POST → redirect → GET).
        .route(
            "/projects/{org}/{repo}/settings",
            web::post().to(forms::update_settings),
        )
        .route(
            "/projects/{org}/{repo}/purge",
            web::post().to(forms::purge),
        )
        .route("/admin/sweep", web::post().to(forms::sweep))
        // Browser sign-in.
        .route("/auth/login", web::get().to(oidc::login))
        .route("/auth/callback", web::get().to(oidc::callback))
        .route("/auth/logout", web::get().to(oidc::logout))
        // Static assets, embedded in the binary.
        .route("/static/styles.css", web::get().to(assets::stylesheet))
        .route("/static/app.js", web::get().to(assets::script));
}

async fn health(state: web::Data<Arc<AppState>>) -> actix_web::HttpResponse {
    // Storage reachability is deliberately not probed here: the health check
    // gates task liveness, and a transient S3 blip shouldn't restart-loop the
    // service (reads degrade to errors on their own).
    let _ = state;
    actix_web::HttpResponse::Ok().json(serde_json::json!({ "ok": true }))
}
