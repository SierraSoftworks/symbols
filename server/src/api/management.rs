use std::sync::Arc;

use actix_web::{HttpRequest, HttpResponse, web};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::AppState;
use crate::auth::{Claims, Identity, SESSION_COOKIE, bearer_token};
use crate::errors::Error;
use crate::formats::{SymbolFormat, sanitize_id};
use crate::storage::{SymbolMeta, UpstreamStats, Visibility};

/// Authenticates a management-plane request either way it can arrive: a
/// bearer token from the management issuer (automation), or the browser
/// session cookie minted by the sign-in flow. Both paths then pass through
/// the configured ACL, which sees the same claims either way.
///
/// Note that an *invalid* Authorization header is a hard 401 even if a valid
/// session cookie is also present — silently falling back would make token
/// expiry indistinguishable from success.
pub async fn authorize(req: &HttpRequest, state: &AppState) -> Result<Identity, Error> {
    let identity = if req
        .headers()
        .contains_key(actix_web::http::header::AUTHORIZATION)
    {
        let token = bearer_token(req)?;
        let claims: Claims = state.management_auth.validate(&token).await?;
        Identity::new(claims)
    } else if let Some(cookie) = req.cookie(SESSION_COOKIE) {
        state.sessions.verify_session(cookie.value())?
    } else {
        return Err(Error::Unauthenticated(
            "sign in, or provide a bearer token".to_string(),
        ));
    };

    // Evaluated per request rather than once at sign-in, so the ACL can key
    // off what is being asked for (`method`, `path`) and so tightening it
    // takes effect on sessions that are already open.
    if let Err(e) = identity.check_acl(
        &state.config.management.acl,
        req.method().as_str(),
        req.path(),
    ) {
        tracing::warn!(
            subject = %identity.subject(),
            method = %req.method(),
            path = %req.path(),
            "Management request rejected by the ACL"
        );
        return Err(e);
    }
    Ok(identity)
}

fn project_name(path: &(String, String)) -> String {
    format!("{}/{}", path.0, path.1)
}

pub async fn list_projects(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
) -> Result<HttpResponse, Error> {
    authorize(&req, &state).await?;
    let projects = state.store.list_projects().await?;
    Ok(HttpResponse::Ok().json(projects))
}

pub async fn get_project(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, Error> {
    authorize(&req, &state).await?;
    let name = project_name(&path);
    let project = state.store.get_project(&name).await?.ok_or(Error::NotFound)?;
    Ok(HttpResponse::Ok().json(project))
}

#[derive(Debug, Deserialize)]
pub struct ProjectUpdate {
    #[serde(default)]
    pub visibility: Option<Visibility>,
    #[serde(default)]
    pub keep_versions: Option<usize>,
}

pub async fn update_project(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    path: web::Path<(String, String)>,
    update: web::Json<ProjectUpdate>,
) -> Result<HttpResponse, Error> {
    let identity = authorize(&req, &state).await?;
    let name = project_name(&path);
    let mut project = state.store.get_project(&name).await?.ok_or(Error::NotFound)?;

    if let Some(visibility) = update.visibility {
        project.visibility = visibility;
    }
    if let Some(keep) = update.keep_versions {
        project.keep_versions = Some(keep.max(1));
    }

    state.store.put_project(&project).await?;
    tracing::info!(
        project = %project.name,
        by = %identity.subject(),
        visibility = ?project.visibility,
        keep_versions = ?project.keep_versions,
        "Updated project"
    );
    Ok(HttpResponse::Ok().json(project))
}

pub async fn list_symbols(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, Error> {
    authorize(&req, &state).await?;
    let name = project_name(&path);
    state.store.get_project(&name).await?.ok_or(Error::NotFound)?;
    let symbols = state.store.list_symbols(&name).await?;
    Ok(HttpResponse::Ok().json(symbols))
}

pub async fn delete_symbol(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    path: web::Path<(String, String, String)>,
) -> Result<HttpResponse, Error> {
    let identity = authorize(&req, &state).await?;
    let name = format!("{}/{}", path.0, path.1);
    let id = sanitize_id(&path.2)?;
    state.store.get_project(&name).await?.ok_or(Error::NotFound)?;
    state.store.delete_symbol(&name, &id).await?;
    tracing::info!(project = %name, build_id = %id, by = %identity.subject(), "Deleted symbols");
    Ok(HttpResponse::NoContent().finish())
}

// --- Purging --------------------------------------------------------------

/// Which stored symbols a purge applies to: one file by build id, or every
/// file of a release version — optionally narrowed to one OS/architecture
/// target.
#[derive(Debug)]
pub enum PurgeFilter {
    BuildId(String),
    Release {
        version: String,
        os: Option<String>,
        arch: Option<String>,
    },
}

/// The OS a stored symbol targets: the uploader's tag when present, else what
/// the format implies. Must agree with the UI's `Os::infer` so purging "what
/// the row shows" deletes what the row shows.
fn symbol_os(meta: &SymbolMeta) -> String {
    meta.os.clone().unwrap_or_else(|| {
        match meta.format {
            SymbolFormat::Elf => "linux",
            SymbolFormat::MachO => "macos",
            SymbolFormat::Pdb => "windows",
        }
        .to_string()
    })
}

/// Deletes every symbol in the project matching the filter; returns how many
/// were deleted. Shared by the DELETE API route and the UI's purge forms.
pub async fn purge_symbols(
    state: &AppState,
    identity: &Identity,
    project: &str,
    filter: &PurgeFilter,
) -> Result<usize, Error> {
    state.store.get_project(project).await?.ok_or(Error::NotFound)?;

    let symbols = state.store.list_symbols(project).await?;
    let mut deleted = 0;
    for meta in symbols {
        let matches = match filter {
            PurgeFilter::BuildId(id) => meta.id == *id,
            PurgeFilter::Release { version, os, arch } => {
                meta.version == *version
                    && os
                        .as_deref()
                        .is_none_or(|os| symbol_os(&meta).eq_ignore_ascii_case(os))
                    && arch.as_deref().is_none_or(|arch| {
                        meta.arch.as_deref().is_some_and(|meta_arch| {
                            symbols_ui::arch_label(meta_arch) == symbols_ui::arch_label(arch)
                        })
                    })
            }
        };
        if matches {
            state.store.delete_symbol(project, &meta.id).await?;
            deleted += 1;
        }
    }

    tracing::info!(
        project = %project,
        by = %identity.subject(),
        filter = ?filter,
        deleted,
        "Purged symbols"
    );
    Ok(deleted)
}

#[derive(Debug, Deserialize)]
pub struct PurgeQuery {
    #[serde(default)]
    pub os: Option<String>,
    #[serde(default)]
    pub arch: Option<String>,
}

/// `DELETE /api/v1/projects/{org}/{repo}/versions/{version}` — purge a
/// release, optionally narrowed with `?os=` / `?arch=`.
pub async fn purge_version(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    path: web::Path<(String, String, String)>,
    query: web::Query<PurgeQuery>,
) -> Result<HttpResponse, Error> {
    let identity = authorize(&req, &state).await?;
    let name = format!("{}/{}", path.0, path.1);
    let filter = PurgeFilter::Release {
        version: path.2.clone(),
        os: query.os.clone(),
        arch: query.arch.clone(),
    };
    let deleted = purge_symbols(&state, &identity, &name, &filter).await?;
    Ok(HttpResponse::Ok().json(serde_json::json!({ "deleted": deleted })))
}

// --- Statistics -----------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct ProjectStats {
    pub name: String,
    pub visibility: Visibility,
    pub symbol_count: usize,
    pub version_count: usize,
    pub total_size: u64,
    pub last_upload: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
pub struct ServerStats {
    pub projects: Vec<ProjectStats>,
    pub upstream: UpstreamStats,
    pub symbol_count: usize,
    pub total_size: u64,
    /// What those symbols occupy in the bucket, compressed. Symbols stored
    /// before the server compressed at rest count at their own size.
    pub stored_size: u64,
    pub last_upload: Option<DateTime<Utc>>,
}

/// Walks every project's symbol listing to aggregate sizes and recency. This
/// is a full metadata scan — fine at the scale of a per-org symbol server,
/// and only reachable from authenticated management surfaces.
pub async fn collect_stats(state: &AppState) -> Result<ServerStats, Error> {
    let mut projects = Vec::new();
    let mut symbol_count = 0;
    let mut total_size = 0;
    let mut stored_size = 0;
    let mut last_upload: Option<DateTime<Utc>> = None;

    for project in state.store.list_projects().await? {
        let symbols = state.store.list_symbols(&project.name).await?;
        let versions: std::collections::HashSet<&str> =
            symbols.iter().map(|s| s.version.as_str()).collect();
        let size: u64 = symbols.iter().map(|s| s.size).sum();
        let stored: u64 = symbols.iter().map(|s| s.stored_size.unwrap_or(s.size)).sum();
        let newest = symbols.iter().map(|s| s.uploaded_at).max();

        symbol_count += symbols.len();
        total_size += size;
        stored_size += stored;
        last_upload = last_upload.max(newest);

        projects.push(ProjectStats {
            name: project.name,
            visibility: project.visibility,
            symbol_count: symbols.len(),
            version_count: versions.len(),
            total_size: size,
            last_upload: newest,
        });
    }

    let upstream = state.store.upstream_stats().await?;
    Ok(ServerStats {
        projects,
        upstream,
        symbol_count,
        total_size,
        stored_size,
        last_upload,
    })
}

/// `GET /api/v1/stats` — storage broken down by project plus the upstream
/// cache, for dashboards and monitoring.
pub async fn get_stats(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
) -> Result<HttpResponse, Error> {
    authorize(&req, &state).await?;
    let stats = collect_stats(&state).await?;
    Ok(HttpResponse::Ok().json(stats))
}

/// `POST /api/v1/sweep` — run the retention sweep immediately.
pub async fn run_sweep(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
) -> Result<HttpResponse, Error> {
    let identity = authorize(&req, &state).await?;
    let summary = crate::retention::sweep(&state).await?;
    tracing::info!(
        by = %identity.subject(),
        symbols_pruned = summary.symbols_pruned,
        upstream_dropped = summary.upstream_dropped,
        "Manual retention sweep"
    );
    Ok(HttpResponse::Ok().json(summary))
}
