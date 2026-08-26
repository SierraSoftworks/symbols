use std::sync::Arc;

use actix_web::{HttpResponse, web};
use futures::{StreamExt, TryStreamExt};

use super::{AppState, Plane};
use crate::errors::Error;
use crate::formats::sanitize_id;
use crate::storage::Visibility;

/// `GET /buildid/{id}/debuginfo` — the debuginfod lookup protocol, as spoken
/// by Pyroscope's symbolizer, elfutils tooling (`DEBUGINFOD_URLS`), gdb, etc.
pub async fn get_debuginfo(
    state: web::Data<Arc<AppState>>,
    plane: web::Data<Plane>,
    path: web::Path<String>,
) -> Result<HttpResponse, Error> {
    let id = sanitize_id(&path.into_inner())?;

    if let Some(index) = state.store.get_index(&id).await? {
        let project = state.store.get_project(&index.project).await?;
        let visible = match (project.as_ref().map(|p| p.visibility), **plane) {
            (Some(_), Plane::Internal) => true,
            (Some(Visibility::Public), Plane::Public) => true,
            // Not visible on this plane — indistinguishable from absent, so
            // the public plane can't be used to enumerate internal symbols.
            _ => false,
        };
        if visible {
            if let Some((size, result)) = state.store.get_symbol(&index.project, &id).await? {
                tracing::debug!(build_id = %id, project = %index.project, "Serving stored symbol");
                return Ok(stream_response(size, result));
            }
            // A dangling index entry (interrupted delete); fall through to
            // federation just like a plain miss.
            tracing::warn!(build_id = %id, project = %index.project, "Dangling build-id index entry");
        }
    }

    federated_lookup(&state, &id).await
}

/// Any other debuginfod route (`/buildid/{id}/executable`, `/section/...`) is
/// deliberately unimplemented; consumers treat 404 as "not available".
pub async fn unsupported() -> HttpResponse {
    HttpResponse::NotFound().finish()
}

fn stream_response(size: u64, result: object_store::GetResult) -> HttpResponse {
    let stream = result
        .into_stream()
        .map_err(|e| std::io::Error::other(format!("storage stream: {e}")));
    let mut response = HttpResponse::Ok();
    response.content_type("application/octet-stream");
    response.insert_header((actix_web::http::header::CONTENT_LENGTH, size));
    response.streaming(stream)
}

/// On a local miss, consult the upstream debuginfod server (distro symbols:
/// glibc, openssl, ...). Responses within the cache limit are persisted to
/// object storage so each build ID is fetched from upstream at most once;
/// larger responses stream straight through.
async fn federated_lookup(state: &AppState, id: &str) -> Result<HttpResponse, Error> {
    let Some(upstream) = state.config.federation.upstream.as_deref().filter(|u| !u.is_empty()) else {
        return Err(Error::NotFound);
    };

    if let Some((size, result)) = state.store.get_upstream(id).await? {
        tracing::debug!(build_id = %id, "Serving upstream symbol from cache");
        return Ok(stream_response(size, result));
    }

    let url = format!("{}/buildid/{id}/debuginfo", upstream.trim_end_matches('/'));
    let response = state
        .http
        .get(&url)
        .send()
        .await
        .map_err(|e| Error::Upstream(format!("querying {url}: {e}")))?;

    match response.status() {
        reqwest::StatusCode::OK => {}
        reqwest::StatusCode::NOT_FOUND => return Err(Error::NotFound),
        status => {
            return Err(Error::Upstream(format!("{url} responded {status}")));
        }
    }

    let cache_limit = state.config.federation.cache_limit_bytes as usize;
    let mut buffer: Vec<u8> = Vec::new();
    let mut body = response.bytes_stream();

    while let Some(chunk) = body.next().await {
        let chunk = chunk.map_err(|e| Error::Upstream(format!("reading {url}: {e}")))?;
        if buffer.len() + chunk.len() > cache_limit {
            // Too large to cache: forward what we have plus the rest of the
            // upstream stream without persisting.
            tracing::info!(build_id = %id, "Upstream symbol exceeds cache limit; streaming through");
            let prefix = futures::stream::once(async move {
                Ok::<bytes::Bytes, std::io::Error>(bytes::Bytes::from(buffer))
            });
            let first = futures::stream::once(async move { Ok(chunk) });
            let rest = body.map_err(|e| std::io::Error::other(format!("upstream stream: {e}")));
            let combined = prefix.chain(first.chain(rest));
            return Ok(HttpResponse::Ok()
                .content_type("application/octet-stream")
                .streaming(combined));
        }
        buffer.extend_from_slice(&chunk);
    }

    let data = bytes::Bytes::from(buffer);
    if let Err(e) = state.store.put_upstream(id, data.clone()).await {
        // Cache writes are best-effort: the caller still gets their symbols
        // during a storage outage.
        tracing::warn!(build_id = %id, error = %e, "Failed to cache upstream symbol");
    } else {
        tracing::info!(build_id = %id, size = data.len(), "Cached upstream symbol");
    }

    Ok(HttpResponse::Ok()
        .content_type("application/octet-stream")
        .insert_header((actix_web::http::header::CONTENT_LENGTH, data.len() as u64))
        .body(data))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use actix_web::{App, test, web};

    use crate::api::{AppState, Plane, configure};
    use crate::auth::Validator;
    use crate::config::Config;
    use crate::formats::{SymbolFormat, SymbolInfo};
    use crate::storage::{Project, Store, SymbolMeta, Visibility};

    async fn seeded_state() -> Arc<AppState> {
        let config = Config::test();
        let http = reqwest::Client::new();
        let store = Store::in_memory();

        for (name, visibility) in [
            ("SierraSoftworks/grey", Visibility::Public),
            ("SierraSoftworks/mail-backup", Visibility::Internal),
        ] {
            store
                .put_project(&Project {
                    name: name.to_string(),
                    visibility,
                    keep_versions: None,
                    created_at: chrono::Utc::now(),
                    created_by: "test".to_string(),
                })
                .await
                .unwrap();
        }

        for (project, id, data) in [
            ("SierraSoftworks/grey", "aabbccdd", &b"public symbols"[..]),
            ("SierraSoftworks/mail-backup", "11223344", &b"internal symbols"[..]),
        ] {
            let info = SymbolInfo {
                id: id.to_string(),
                format: SymbolFormat::Elf,
                arch: Some("aarch64".to_string()),
            };
            let meta = SymbolMeta {
                id: id.to_string(),
                format: SymbolFormat::Elf,
                arch: None,
                version: "v1".to_string(),
                size: data.len() as u64,
                uploaded_at: chrono::Utc::now(),
                uploaded_from: None,
            };
            store
                .put_symbol(project, &info, &meta, bytes::Bytes::from_static(data))
                .await
                .unwrap();
        }

        Arc::new(AppState {
            github_auth: Validator::new(http.clone(), &config.github.issuer, &config.github.audience),
            management_auth: Validator::new(
                http.clone(),
                &config.management.issuer,
                &config.management.audience,
            ),
            store,
            http,
            config,
        })
    }

    async fn get(state: &Arc<AppState>, plane: Plane, path: &str) -> (u16, Vec<u8>) {
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(state.clone()))
                .app_data(web::Data::new(plane))
                .configure(configure),
        )
        .await;
        let response = test::call_service(&app, test::TestRequest::get().uri(path).to_request()).await;
        let status = response.status().as_u16();
        let body = test::read_body(response).await.to_vec();
        (status, body)
    }

    #[actix_web::test]
    async fn serves_public_symbols_on_both_planes() {
        let state = seeded_state().await;
        for plane in [Plane::Public, Plane::Internal] {
            let (status, body) = get(&state, plane, "/buildid/aabbccdd/debuginfo").await;
            assert_eq!(status, 200);
            assert_eq!(body, b"public symbols");
        }
    }

    #[actix_web::test]
    async fn internal_symbols_hidden_from_the_public_plane() {
        let state = seeded_state().await;
        let (status, _) = get(&state, Plane::Public, "/buildid/11223344/debuginfo").await;
        assert_eq!(status, 404, "internal project must look absent publicly");
        let (status, body) = get(&state, Plane::Internal, "/buildid/11223344/debuginfo").await;
        assert_eq!(status, 200);
        assert_eq!(body, b"internal symbols");
    }

    #[actix_web::test]
    async fn lookup_normalises_case_and_rejects_invalid_ids() {
        let state = seeded_state().await;
        let (status, body) = get(&state, Plane::Public, "/buildid/AABBCCDD/debuginfo").await;
        assert_eq!(status, 200);
        assert_eq!(body, b"public symbols");
        let (status, _) = get(&state, Plane::Public, "/buildid/zz!/debuginfo").await;
        assert_eq!(status, 400);
    }

    #[actix_web::test]
    async fn unknown_ids_and_other_sections_return_404() {
        let state = seeded_state().await;
        // Federation is disabled in the test config, so a miss is a plain 404.
        let (status, _) = get(&state, Plane::Internal, "/buildid/deadbeef/debuginfo").await;
        assert_eq!(status, 404);
        let (status, _) = get(&state, Plane::Internal, "/buildid/aabbccdd/executable").await;
        assert_eq!(status, 404);
    }
}
