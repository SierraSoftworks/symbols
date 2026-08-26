use std::sync::Arc;

use actix_web::{HttpRequest, HttpResponse, web};
use serde::Deserialize;

use super::AppState;
use crate::auth::{GithubClaims, bearer_token};
use crate::errors::Error;
use crate::formats::identify;
use crate::storage::{Project, SymbolMeta, Visibility};

#[derive(Debug, Deserialize)]
pub struct UploadQuery {
    /// Release/version tag the symbols belong to; groups uploads for
    /// retention. Optional but strongly recommended.
    #[serde(default)]
    pub version: String,
    /// OS tag ("linux", "macos", "windows"), normally the runner's OS.
    #[serde(default)]
    pub os: Option<String>,
    /// Architecture tag; only used when the symbol file itself doesn't carry
    /// one (PDBs), since the file is the authority on what it contains.
    #[serde(default)]
    pub arch: Option<String>,
    /// Commit SHA the symbols were built from.
    #[serde(default)]
    pub commit: Option<String>,
    /// Link to the CI run that produced the upload.
    #[serde(default)]
    pub build_url: Option<String>,
}

/// Uploader-supplied metadata ends up rendered in the management UI (labels
/// and hrefs), so each field is held to a tight shape rather than stored
/// verbatim. Empty values are treated as absent first (the publish action
/// sends `os=`/`arch=` with empty values when it can't classify the runner).
fn normalize_metadata(query: &mut UploadQuery) {
    for field in [
        &mut query.os,
        &mut query.arch,
        &mut query.commit,
        &mut query.build_url,
    ] {
        if field.as_deref().is_some_and(|v| v.is_empty()) {
            *field = None;
        }
    }
}

fn validate_metadata(query: &UploadQuery) -> Result<(), Error> {
    for (name, value, max) in [
        ("version", Some(&query.version), 128usize),
        ("os", query.os.as_ref(), 32),
        ("arch", query.arch.as_ref(), 32),
    ] {
        if let Some(value) = value {
            let ok = value.len() <= max
                && value
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '+' | '/'));
            if !ok {
                return Err(Error::BadRequest(format!("invalid {name} tag")));
            }
        }
    }

    if let Some(commit) = &query.commit {
        if commit.len() > 64 || !commit.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(Error::BadRequest("invalid commit sha".to_string()));
        }
    }

    if let Some(build_url) = &query.build_url {
        let parsed = url::Url::parse(build_url)
            .map_err(|e| Error::BadRequest(format!("invalid build_url: {e}")))?;
        if build_url.len() > 512 || !matches!(parsed.scheme(), "http" | "https") {
            return Err(Error::BadRequest("invalid build_url".to_string()));
        }
    }

    Ok(())
}

/// `POST /api/v1/symbols` — authenticated by a GitHub Actions OIDC id-token.
///
/// The project is derived from the token's `repository` claim ("org/repo"),
/// never from the request, and the build identifier is derived from the
/// uploaded file itself — an uploader can neither publish into another
/// project nor poison a foreign build ID's lookup with mislabelled content
/// (a build ID collision would require colliding the actual note/UUID/GUID).
///
/// Uploads from repositories in a trusted org auto-create the project on
/// first use, seeded with the repository's own visibility.
pub async fn upload_symbol(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    query: web::Query<UploadQuery>,
    body: web::Bytes,
) -> Result<HttpResponse, Error> {
    let token = bearer_token(&req)?;
    let claims: GithubClaims = state.github_auth.validate(&token).await?;

    let trusted = state
        .config
        .github
        .trusted_orgs
        .iter()
        .any(|org| org.eq_ignore_ascii_case(&claims.repository_owner));
    if !trusted {
        return Err(Error::Forbidden(format!(
            "organization '{}' is not trusted by this server",
            claims.repository_owner
        )));
    }

    let ref_prefixes = &state.config.github.ref_prefixes;
    if !ref_prefixes.is_empty() {
        let git_ref = claims.git_ref.as_deref().unwrap_or("");
        if !ref_prefixes.iter().any(|p| git_ref.starts_with(p.as_str())) {
            return Err(Error::Forbidden(format!(
                "uploads are only accepted from refs matching {ref_prefixes:?} (got '{git_ref}')"
            )));
        }
    }

    let mut query = query.into_inner();
    normalize_metadata(&mut query);
    validate_metadata(&query)?;

    if body.is_empty() {
        return Err(Error::BadRequest("empty upload".to_string()));
    }

    let info = identify(&body)?;

    let project_name = claims.repository.clone();
    let project = match state.store.get_project(&project_name).await? {
        Some(existing) => existing,
        None => {
            let visibility = match claims.repository_visibility.as_deref() {
                Some("public") => Visibility::Public,
                // Private/internal repositories — and anything unexpected —
                // default to internal-plane-only symbols; widen via the API.
                _ => Visibility::Internal,
            };
            let project = Project {
                name: project_name.clone(),
                visibility,
                keep_versions: None,
                created_at: chrono::Utc::now(),
                created_by: "auto".to_string(),
            };
            state.store.put_project(&project).await?;
            tracing::info!(
                project = %project.name,
                visibility = ?project.visibility,
                "Auto-created project for trusted organization"
            );
            project
        }
    };

    let meta = SymbolMeta {
        id: info.id.clone(),
        format: info.format,
        // The file's own architecture wins; the uploader's tag only fills the
        // gap for formats that don't declare one (PDBs).
        arch: info.arch.clone().or_else(|| query.arch.clone()),
        version: query.version.clone(),
        size: body.len() as u64,
        uploaded_at: chrono::Utc::now(),
        uploaded_from: claims.git_ref.clone(),
        os: query.os.as_deref().map(|os| os.to_ascii_lowercase()),
        commit: query.commit.as_deref().map(|c| c.to_ascii_lowercase()),
        build_url: query.build_url.clone(),
    };

    let size = body.len();
    state.store.put_symbol(&project.name, &info, &meta, body).await?;

    tracing::info!(
        project = %project.name,
        build_id = %info.id,
        format = ?info.format,
        arch = ?info.arch,
        version = %meta.version,
        size,
        "Stored symbols"
    );

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "build_id": info.id,
        "project": project.name,
        "format": info.format,
        "arch": info.arch,
        "version": meta.version,
        "size": size,
    })))
}
