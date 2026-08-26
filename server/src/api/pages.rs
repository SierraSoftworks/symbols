//! Server-rendered management UI pages. Each handler authenticates, gathers
//! everything the page needs from storage, maps it into the UI crate's view
//! models, and renders the Yew component tree to HTML — there is no client
//! runtime, so pages must arrive complete.

use std::sync::Arc;

use actix_web::{HttpRequest, HttpResponse, http::StatusCode, web};
use serde::Deserialize;
use symbols_ui::{AppProps, PageBody};

use super::{AppState, management};
use crate::auth::Identity;
use crate::errors::Error;
use crate::storage::{SymbolMeta, Visibility};

/// Wraps a rendered page body in the document shell. This plays the role of
/// grey's Trunk-built index.html template; with no asset pipeline the shell
/// is just written out here.
fn shell(title: &str, body: &str) -> String {
    format!(
        concat!(
            "<!DOCTYPE html>",
            "<html lang=\"en\">",
            "<head>",
            "<meta charset=\"utf-8\">",
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
            "<meta name=\"robots\" content=\"noindex\">",
            "<title>{title}</title>",
            "<link rel=\"stylesheet\" href=\"/static/styles.css\">",
            "</head>",
            "<body>{body}<script src=\"/static/app.js\" defer></script></body>",
            "</html>"
        ),
        title = escape_html(title),
        body = body,
    )
}

/// Titles include project names; those come from GitHub OIDC claims (safe
/// charset in practice) but escaping costs nothing.
fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

async fn render(
    status: StatusCode,
    identity: Option<&Identity>,
    body: PageBody,
) -> HttpResponse {
    let title = body.title();
    let user = identity.map(|identity| symbols_ui::SessionUser {
        subject: identity.subject.clone(),
        name: identity.name.clone(),
        email: identity.email.clone(),
    });
    let html = symbols_ui::render(AppProps { user, body }).await;
    HttpResponse::build(status)
        .content_type("text/html; charset=utf-8")
        .body(shell(&title, &html))
}

/// A standalone HTML error page (no session context) — used by the sign-in
/// flow, where errors happen before or instead of a session existing.
pub async fn error_page(status: u16, message: &str) -> HttpResponse {
    render(
        StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        None,
        PageBody::Error {
            status,
            message: message.to_string(),
        },
    )
    .await
}

/// Authenticates a page request. Unauthenticated browsers are redirected into
/// the sign-in flow (with a `next` back to this page) rather than shown a
/// bare 401; disallowed users get a rendered 403. (The response is boxed only
/// to keep the error variant small — clippy::result_large_err.)
async fn page_auth(req: &HttpRequest, state: &AppState) -> Result<Identity, Box<HttpResponse>> {
    match management::authorize(req, state).await {
        Ok(identity) => Ok(identity),
        Err(Error::Unauthenticated(_)) => {
            let next: String = url::form_urlencoded::byte_serialize(
                req.uri()
                    .path_and_query()
                    .map(|pq| pq.as_str())
                    .unwrap_or("/")
                    .as_bytes(),
            )
            .collect();
            Err(Box::new(
                HttpResponse::Found()
                    .insert_header((
                        actix_web::http::header::LOCATION,
                        format!("{}?next={next}", symbols_ui::routes::login()),
                    ))
                    .finish(),
            ))
        }
        Err(Error::Forbidden(message)) => Err(Box::new(error_page(403, &message).await)),
        Err(e) => Err(Box::new(error_page(500, &e.to_string()).await)),
    }
}

#[derive(Debug, Deserialize)]
pub struct FlashQuery {
    #[serde(default)]
    pub flash: Option<String>,
    #[serde(default)]
    pub error: Option<u8>,
}

impl FlashQuery {
    fn flash(&self) -> Option<symbols_ui::Flash> {
        self.flash.as_ref().map(|message| symbols_ui::Flash {
            message: message.clone(),
            error: self.error.unwrap_or(0) != 0,
        })
    }
}

fn visibility(v: Visibility) -> symbols_ui::Visibility {
    match v {
        Visibility::Public => symbols_ui::Visibility::Public,
        Visibility::Internal => symbols_ui::Visibility::Internal,
    }
}

/// `GET /` — stats tiles plus the project table.
pub async fn dashboard(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    query: web::Query<FlashQuery>,
) -> Result<HttpResponse, Error> {
    let identity = match page_auth(&req, &state).await {
        Ok(identity) => identity,
        Err(response) => return Ok(*response),
    };

    let stats = management::collect_stats(&state).await?;
    let projects = stats
        .projects
        .iter()
        .map(|p| symbols_ui::ProjectRow {
            name: p.name.clone(),
            visibility: visibility(p.visibility),
            version_count: p.version_count,
            symbol_count: p.symbol_count,
            total_size: p.total_size,
            last_upload: p.last_upload,
        })
        .collect();
    let summary = symbols_ui::StatsSummary {
        project_count: stats.projects.len(),
        symbol_count: stats.symbol_count,
        total_size: stats.total_size,
        upstream_entries: stats.upstream.entries,
        upstream_size: stats.upstream.total_size,
        last_upload: stats.last_upload,
    };

    Ok(render(
        StatusCode::OK,
        Some(&identity),
        PageBody::Dashboard {
            stats: summary,
            projects,
            flash: query.flash(),
        },
    )
    .await)
}

/// Groups a project's symbols into releases (one per version tag, newest
/// first), each holding its per-target rows sorted by OS then architecture.
fn release_rows(symbols: &[SymbolMeta]) -> Vec<symbols_ui::ReleaseRow> {
    let mut releases: Vec<symbols_ui::ReleaseRow> = Vec::new();
    for meta in symbols {
        let os = symbols_ui::Os::infer(
            meta.os.as_deref(),
            match meta.format {
                crate::formats::SymbolFormat::Elf => "elf",
                crate::formats::SymbolFormat::MachO => "macho",
                crate::formats::SymbolFormat::Pdb => "pdb",
            },
        );
        let target = symbols_ui::TargetRow {
            build_id: meta.id.clone(),
            os,
            arch: meta.arch.clone(),
            format: match meta.format {
                crate::formats::SymbolFormat::Elf => "elf",
                crate::formats::SymbolFormat::MachO => "macho",
                crate::formats::SymbolFormat::Pdb => "pdb",
            }
            .to_string(),
            size: meta.size,
            uploaded_at: meta.uploaded_at,
            commit: meta.commit.clone(),
            build_url: meta.build_url.clone(),
            uploaded_from: meta.uploaded_from.clone(),
        };

        match releases.iter_mut().find(|r| r.version == meta.version) {
            Some(release) => {
                release.total_size += meta.size;
                release.updated_at = release.updated_at.max(meta.uploaded_at);
                release.targets.push(target);
            }
            None => releases.push(symbols_ui::ReleaseRow {
                version: meta.version.clone(),
                updated_at: meta.uploaded_at,
                total_size: meta.size,
                targets: vec![target],
            }),
        }
    }

    for release in &mut releases {
        release
            .targets
            .sort_by(|a, b| (a.os.label(), &a.arch).cmp(&(b.os.label(), &b.arch)));
    }
    releases.sort_by_key(|r| std::cmp::Reverse(r.updated_at));
    releases
}

/// `GET /projects/{org}/{repo}` — settings plus the release/target breakdown.
pub async fn project(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    path: web::Path<(String, String)>,
    query: web::Query<FlashQuery>,
) -> Result<HttpResponse, Error> {
    let identity = match page_auth(&req, &state).await {
        Ok(identity) => identity,
        Err(response) => return Ok(*response),
    };

    let name = format!("{}/{}", path.0, path.1);
    let Some(project) = state.store.get_project(&name).await? else {
        return Ok(error_page(404, &format!("No project named '{name}' exists.")).await);
    };
    let symbols = state.store.list_symbols(&name).await?;
    let releases = release_rows(&symbols);

    let detail = symbols_ui::ProjectDetail {
        name: project.name.clone(),
        visibility: visibility(project.visibility),
        keep_versions: project.keep_versions,
        default_keep_versions: state.config.retention.default_keep_versions,
        created_at: project.created_at,
        total_size: symbols.iter().map(|s| s.size).sum(),
        releases,
    };

    Ok(render(
        StatusCode::OK,
        Some(&identity),
        PageBody::Project {
            detail,
            flash: query.flash(),
        },
    )
    .await)
}

/// `GET /setup` — configuration snippets. Deliberately viewable without
/// signing in: it contains only the server's own URLs (this route exists on
/// the internal plane alone), and it's the page people need *before* they
/// have everything wired up.
pub async fn setup(req: HttpRequest, state: web::Data<Arc<AppState>>) -> HttpResponse {
    // Best-effort session resolution so the header reflects sign-in state.
    let identity = management::authorize(&req, &state).await.ok();

    let public_url = state
        .config
        .server
        .public_url
        .clone()
        .unwrap_or_else(|| format!("https://{}", state.config.github.audience));
    // Scoped: ConnectionInfo is a RefCell guard and must not live across the
    // render await.
    let internal_url = {
        let info = req.connection_info();
        format!("{}://{}", info.scheme(), info.host())
    };

    let body = PageBody::Setup {
        info: symbols_ui::SetupInfo {
            public_url: public_url.trim_end_matches('/').to_string(),
            internal_url: internal_url.trim_end_matches('/').to_string(),
            github_audience: state.config.github.audience.clone(),
        },
    };
    render(StatusCode::OK, identity.as_ref(), body).await
}
