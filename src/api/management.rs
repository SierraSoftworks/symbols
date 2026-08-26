use std::sync::Arc;

use actix_web::{HttpRequest, HttpResponse, web};
use serde::Deserialize;

use super::AppState;
use crate::auth::{ManagementClaims, bearer_token};
use crate::errors::Error;
use crate::formats::sanitize_id;
use crate::storage::Visibility;

/// All management routes require a token from the management OIDC issuer.
async fn authorize(req: &HttpRequest, state: &AppState) -> Result<ManagementClaims, Error> {
    let token = bearer_token(req)?;
    state.management_auth.validate(&token).await
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
    let claims = authorize(&req, &state).await?;
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
        by = %claims.sub,
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
    let claims = authorize(&req, &state).await?;
    let name = format!("{}/{}", path.0, path.1);
    let id = sanitize_id(&path.2)?;
    state.store.get_project(&name).await?.ok_or(Error::NotFound)?;
    state.store.delete_symbol(&name, &id).await?;
    tracing::info!(project = %name, build_id = %id, by = %claims.sub, "Deleted symbols");
    Ok(HttpResponse::NoContent().finish())
}
