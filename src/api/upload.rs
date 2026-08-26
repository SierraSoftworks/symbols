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
        arch: info.arch.clone(),
        version: query.version.clone(),
        size: body.len() as u64,
        uploaded_at: chrono::Utc::now(),
        uploaded_from: claims.git_ref.clone(),
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
