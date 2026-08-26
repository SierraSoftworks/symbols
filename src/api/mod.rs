use std::sync::Arc;

use actix_web::web;

use crate::auth::Validator;
use crate::config::Config;
use crate::storage::Store;

pub mod debuginfod;
pub mod management;
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
    pub http: reqwest::Client,
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route("/health", web::get().to(health))
        .route(
            "/buildid/{id}/debuginfo",
            web::get().to(debuginfod::get_debuginfo),
        )
        .route(
            "/buildid/{id}/{section}",
            web::get().to(debuginfod::unsupported),
        )
        .route("/api/v1/symbols", web::post().to(upload::upload_symbol))
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
        );
}

async fn health(state: web::Data<Arc<AppState>>) -> actix_web::HttpResponse {
    // Storage reachability is deliberately not probed here: the health check
    // gates task liveness, and a transient S3 blip shouldn't restart-loop the
    // service (reads degrade to errors on their own).
    let _ = state;
    actix_web::HttpResponse::Ok().json(serde_json::json!({ "ok": true }))
}
