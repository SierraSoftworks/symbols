//! HTML form actions for the SSR-only UI: every mutation is a plain POST
//! followed by a redirect back to the page, with the outcome carried in a
//! `?flash=` query parameter. CSRF is covered by the session cookie's
//! SameSite=Lax attribute — cross-site form POSTs never carry it.

use std::sync::Arc;

use actix_web::{HttpRequest, HttpResponse, web};
use serde::Deserialize;

use super::{AppState, management, pages};
use crate::auth::Identity;
use crate::errors::Error;
use crate::formats::sanitize_id;
use crate::storage::Visibility;

/// POST-form authentication mirrors page authentication: browsers without a
/// session are bounced to sign-in (landing back on the *referring page*, not
/// the POST target, after signing in — hence redirecting to `next`).
async fn form_auth(
    req: &HttpRequest,
    state: &AppState,
    next: &str,
) -> Result<Identity, Box<HttpResponse>> {
    match management::authorize(req, state).await {
        Ok(identity) => Ok(identity),
        Err(Error::Unauthenticated(_)) => {
            let next: String = url::form_urlencoded::byte_serialize(next.as_bytes()).collect();
            Err(Box::new(
                HttpResponse::SeeOther()
                    .insert_header((
                        actix_web::http::header::LOCATION,
                        format!("{}?next={next}", symbols_ui::routes::login()),
                    ))
                    .finish(),
            ))
        }
        Err(Error::Forbidden(message)) => Err(Box::new(pages::error_page(403, &message).await)),
        Err(e) => Err(Box::new(pages::error_page(500, &e.to_string()).await)),
    }
}

/// 303 back to `path` with a flash message; the follow-up GET renders it.
fn redirect_with_flash(path: &str, message: &str, error: bool) -> HttpResponse {
    let encoded: String = url::form_urlencoded::byte_serialize(message.as_bytes()).collect();
    let mut location = format!("{path}?flash={encoded}");
    if error {
        location.push_str("&error=1");
    }
    HttpResponse::SeeOther()
        .insert_header((actix_web::http::header::LOCATION, location))
        .finish()
}

#[derive(Debug, Deserialize)]
pub struct SettingsForm {
    pub visibility: String,
    /// Empty string clears the override back to the server default.
    #[serde(default)]
    pub keep_versions: String,
}

/// `POST /projects/{org}/{repo}/settings`.
pub async fn update_settings(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    path: web::Path<(String, String)>,
    form: web::Form<SettingsForm>,
) -> Result<HttpResponse, Error> {
    let name = format!("{}/{}", path.0, path.1);
    let page = symbols_ui::routes::project(&name);
    let identity = match form_auth(&req, &state, &page).await {
        Ok(identity) => identity,
        Err(response) => return Ok(*response),
    };

    let visibility = match form.visibility.as_str() {
        "public" => Visibility::Public,
        "internal" => Visibility::Internal,
        other => {
            return Ok(redirect_with_flash(
                &page,
                &format!("Unknown visibility '{other}'"),
                true,
            ));
        }
    };
    let keep_versions = match form.keep_versions.trim() {
        "" => None,
        raw => match raw.parse::<usize>() {
            Ok(keep) => Some(keep.max(1)),
            Err(_) => {
                return Ok(redirect_with_flash(
                    &page,
                    "Keep versions must be a number (or empty for the default)",
                    true,
                ));
            }
        },
    };

    let Some(mut project) = state.store.get_project(&name).await? else {
        return Ok(pages::error_page(404, &format!("No project named '{name}' exists.")).await);
    };
    project.visibility = visibility;
    project.keep_versions = keep_versions;
    state.store.put_project(&project).await?;

    tracing::info!(
        project = %project.name,
        by = %identity.subject(),
        visibility = ?project.visibility,
        keep_versions = ?project.keep_versions,
        "Updated project settings via UI"
    );
    Ok(redirect_with_flash(&page, "Settings saved", false))
}

#[derive(Debug, Deserialize)]
pub struct PurgeForm {
    /// Purge a single stored symbol file...
    #[serde(default)]
    pub build_id: Option<String>,
    /// ...or a whole release version (the empty string is the untagged
    /// pseudo-version, so this stays `Option` to tell "absent" from "untagged").
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub os: Option<String>,
    #[serde(default)]
    pub arch: Option<String>,
}

/// `POST /projects/{org}/{repo}/purge`.
pub async fn purge(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    path: web::Path<(String, String)>,
    form: web::Form<PurgeForm>,
) -> Result<HttpResponse, Error> {
    let name = format!("{}/{}", path.0, path.1);
    let page = symbols_ui::routes::project(&name);
    let identity = match form_auth(&req, &state, &page).await {
        Ok(identity) => identity,
        Err(response) => return Ok(*response),
    };

    let filter = match (&form.build_id, &form.version) {
        (Some(build_id), _) => management::PurgeFilter::BuildId(sanitize_id(build_id)?),
        (None, Some(version)) => management::PurgeFilter::Release {
            version: version.clone(),
            os: form.os.clone(),
            arch: form.arch.clone(),
        },
        (None, None) => {
            return Ok(redirect_with_flash(&page, "Nothing selected to purge", true));
        }
    };

    let deleted = management::purge_symbols(&state, &identity, &name, &filter).await?;
    let message = match deleted {
        0 => "No matching symbols to purge".to_string(),
        1 => "Purged 1 symbol file".to_string(),
        n => format!("Purged {n} symbol files"),
    };
    Ok(redirect_with_flash(&page, &message, deleted == 0))
}

/// `POST /admin/sweep` — run the retention sweep right now.
pub async fn sweep(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
) -> Result<HttpResponse, Error> {
    let identity = match form_auth(&req, &state, symbols_ui::routes::dashboard()).await {
        Ok(identity) => identity,
        Err(response) => return Ok(*response),
    };

    let summary = crate::retention::sweep(&state).await?;
    tracing::info!(
        by = %identity.subject(),
        symbols_pruned = summary.symbols_pruned,
        upstream_dropped = summary.upstream_dropped,
        "Manual retention sweep via UI"
    );
    Ok(redirect_with_flash(
        symbols_ui::routes::dashboard(),
        &format!(
            "Sweep complete: pruned {} symbol file(s), dropped {} upstream cache entr{}",
            summary.symbols_pruned,
            summary.upstream_dropped,
            if summary.upstream_dropped == 1 { "y" } else { "ies" },
        ),
        false,
    ))
}
