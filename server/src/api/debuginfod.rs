use std::sync::Arc;

use actix_web::{HttpRequest, HttpResponse, http::header, web};
use futures::{StreamExt, TryStreamExt};

use super::{AppState, Plane};
use crate::compression::{self, Compression};
use crate::errors::Error;
use crate::formats::sanitize_id;
use crate::storage::{StoredObject, Visibility};

/// `GET /buildid/{id}/debuginfo` — the debuginfod lookup protocol, as spoken
/// by Pyroscope's symbolizer, elfutils tooling (`DEBUGINFOD_URLS`), gdb, etc.
pub async fn get_debuginfo(
    req: HttpRequest,
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
            if let Some(stored) = state.store.get_symbol(&index.project, &id).await? {
                tracing::debug!(build_id = %id, project = %index.project, "Serving stored symbol");
                return Ok(stream_response(&req, stored));
            }
            // A dangling index entry (interrupted delete); fall through to
            // federation just like a plain miss.
            tracing::warn!(build_id = %id, project = %index.project, "Dangling build-id index entry");
        }
    }

    federated_lookup(&req, &state, &id).await
}

/// Any other debuginfod route (`/buildid/{id}/executable`, `/section/...`) is
/// deliberately unimplemented; consumers treat 404 as "not available".
pub async fn unsupported() -> HttpResponse {
    HttpResponse::NotFound().finish()
}

/// Streams a stored object out. Symbols are held gzipped, so a client that
/// advertises gzip gets those bytes untouched — no inflation here, no
/// re-compression at the edge, and a fraction of the bytes on the wire.
/// Anyone else gets the same stream inflated on the way past.
fn stream_response(req: &HttpRequest, stored: StoredObject) -> HttpResponse {
    let stream = Box::pin(
        stored
            .result
            .into_stream()
            .map_err(|e| std::io::Error::other(format!("storage stream: {e}"))),
    );

    let mut response = HttpResponse::Ok();
    response.content_type("application/octet-stream");
    // What comes back depends on what the client accepts, and there are caches
    // (a CDN, at least) between us and it.
    response.insert_header((header::VARY, "accept-encoding"));

    match stored.compression {
        Compression::None => {
            response.insert_header((header::CONTENT_LENGTH, stored.stored_size));
            response.streaming(stream)
        }
        Compression::Gzip if accepts_gzip(req) => {
            response.insert_header((header::CONTENT_ENCODING, "gzip"));
            response.insert_header((header::CONTENT_LENGTH, stored.stored_size));
            response.streaming(stream)
        }
        // The inflated length isn't known without reading the whole object, so
        // this response goes out chunked.
        Compression::Gzip => response.streaming(compression::decode_stream(stream)),
    }
}

/// Whether the client asked for gzip. Absence means no: the debuginfod clients
/// in the wild (elfutils' libcurl client, gdb, Pyroscope's symbolizer) don't
/// all negotiate content encodings, and handing gzip to one that didn't ask
/// would hand it garbage.
fn accepts_gzip(req: &HttpRequest) -> bool {
    let Some(accepted) = req
        .headers()
        .get(header::ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };

    accepted.split(',').any(|entry| {
        let mut parts = entry.split(';').map(str::trim);
        let coding = parts.next().unwrap_or_default();
        if !coding.eq_ignore_ascii_case("gzip") && coding != "*" {
            return false;
        }
        // "gzip;q=0" is an explicit refusal.
        parts
            .find_map(|param| param.strip_prefix("q="))
            .and_then(|q| q.trim().parse::<f32>().ok())
            .map(|q| q > 0.0)
            .unwrap_or(true)
    })
}

/// On a local miss, consult the upstream debuginfod server (distro symbols:
/// glibc, openssl, ...). Responses within the cache limit are persisted to
/// object storage so each build ID is fetched from upstream at most once;
/// larger responses stream straight through.
async fn federated_lookup(
    req: &HttpRequest,
    state: &AppState,
    id: &str,
) -> Result<HttpResponse, Error> {
    let Some(upstream) = state.config.federation.upstream.as_deref().filter(|u| !u.is_empty()) else {
        return Err(Error::NotFound);
    };

    if let Some(stored) = state.store.get_upstream(id).await? {
        tracing::debug!(build_id = %id, "Serving upstream symbol from cache");
        return Ok(stream_response(req, stored));
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

    // Cached entries are compressed like our own symbols, so the cache costs a
    // fraction of the storage and re-serves without re-encoding.
    let cacheable = data.clone();
    match web::block(move || compression::compress(&cacheable)).await {
        Ok(Ok(compressed)) => {
            let stored_size = compressed.len();
            // Cache writes are best-effort: the caller still gets their symbols
            // during a storage outage.
            if let Err(e) = state.store.put_upstream(id, compressed).await {
                tracing::warn!(build_id = %id, error = %e, "Failed to cache upstream symbol");
            } else {
                let size = data.len();
                tracing::info!(build_id = %id, size, stored_size, "Cached upstream symbol");
            }
        }
        Ok(Err(e)) => {
            tracing::warn!(build_id = %id, error = %e, "Failed to compress upstream symbol")
        }
        Err(e) => tracing::warn!(build_id = %id, error = %e, "Compression task failed"),
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

    use crate::api::{AppState, Plane, configure_internal, configure_public};
    use crate::compression::{Compression, compress};
    use crate::config::Config;
    use crate::formats::{SymbolFormat, SymbolInfo};
    use crate::storage::{Project, Store, SymbolMeta, Visibility};

    async fn seeded_state() -> Arc<AppState> {
        seeded_state_with(|_| {}).await
    }

    async fn seeded_state_with(configure: impl FnOnce(&mut Config)) -> Arc<AppState> {
        let mut config = Config::test();
        configure(&mut config);
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

        for (project, id, data, compression) in [
            (
                "SierraSoftworks/grey",
                "aabbccdd",
                &b"public symbols"[..],
                Compression::Gzip,
            ),
            (
                "SierraSoftworks/mail-backup",
                "11223344",
                &b"internal symbols"[..],
                Compression::Gzip,
            ),
            // Stored before the server compressed at rest.
            (
                "SierraSoftworks/grey",
                "99887766",
                &b"legacy symbols"[..],
                Compression::None,
            ),
        ] {
            let info = SymbolInfo {
                id: id.to_string(),
                format: SymbolFormat::Elf,
                arch: Some("aarch64".to_string()),
            };
            let stored = match compression {
                Compression::Gzip => compress(data).unwrap(),
                Compression::None => bytes::Bytes::copy_from_slice(data),
            };
            let meta = SymbolMeta {
                id: id.to_string(),
                format: SymbolFormat::Elf,
                arch: None,
                version: "v1".to_string(),
                size: data.len() as u64,
                compression,
                stored_size: Some(stored.len() as u64),
                uploaded_at: chrono::Utc::now(),
                uploaded_from: None,
                os: None,
                commit: None,
                build_url: None,
            };
            store.put_symbol(project, &info, &meta, stored).await.unwrap();
        }

        Arc::new(AppState::new(config, store, reqwest::Client::new()))
    }

    async fn get(state: &Arc<AppState>, plane: Plane, path: &str) -> (u16, Vec<u8>) {
        let (status, body, _, _) = request(state, plane, path, None).await;
        (status, body)
    }

    /// Returns the status, the raw body (undecoded) and the response's
    /// `Content-Encoding` and `Vary` headers.
    async fn request(
        state: &Arc<AppState>,
        plane: Plane,
        path: &str,
        accept_encoding: Option<&str>,
    ) -> (u16, Vec<u8>, Option<String>, Option<String>) {
        let configure = match plane {
            Plane::Public => configure_public,
            Plane::Internal => configure_internal,
        };
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(state.clone()))
                .app_data(web::Data::new(plane))
                .configure(configure),
        )
        .await;

        let mut request = test::TestRequest::get().uri(path);
        if let Some(encoding) = accept_encoding {
            request = request.insert_header(("accept-encoding", encoding));
        }

        let response = test::call_service(&app, request.to_request()).await;
        let status = response.status().as_u16();
        let header = |name: &str| {
            response
                .headers()
                .get(name)
                .map(|v| v.to_str().unwrap().to_string())
        };
        let (encoding, vary) = (header("content-encoding"), header("vary"));
        let body = test::read_body(response).await.to_vec();
        (status, body, encoding, vary)
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
    async fn compressed_symbols_pass_through_to_clients_that_accept_gzip() {
        let state = seeded_state().await;
        let (status, body, encoding, vary) =
            request(&state, Plane::Public, "/buildid/aabbccdd/debuginfo", Some("gzip")).await;

        assert_eq!(status, 200);
        assert_eq!(encoding.as_deref(), Some("gzip"));
        assert_eq!(vary.as_deref(), Some("accept-encoding"));
        assert_eq!(
            crate::compression::decompress(&body, 1 << 20).unwrap(),
            &b"public symbols"[..],
            "the client should receive the stored bytes verbatim"
        );
    }

    #[actix_web::test]
    async fn compressed_symbols_are_inflated_for_clients_that_do_not() {
        let state = seeded_state().await;
        for accept in [None, Some("br"), Some("gzip;q=0"), Some("deflate, gzip;q=0.0")] {
            let (status, body, encoding, _) =
                request(&state, Plane::Public, "/buildid/aabbccdd/debuginfo", accept).await;
            assert_eq!(status, 200, "accept-encoding: {accept:?}");
            assert_eq!(encoding, None, "accept-encoding: {accept:?}");
            assert_eq!(body, b"public symbols", "accept-encoding: {accept:?}");
        }
    }

    #[actix_web::test]
    async fn symbols_stored_before_compression_are_served_as_they_are() {
        let state = seeded_state().await;
        for accept in [None, Some("gzip")] {
            let (status, body, encoding, _) =
                request(&state, Plane::Public, "/buildid/99887766/debuginfo", accept).await;
            assert_eq!(status, 200);
            assert_eq!(encoding, None, "nothing to advertise for a plain object");
            assert_eq!(body, b"legacy symbols");
        }
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

    #[actix_web::test]
    async fn management_surfaces_do_not_exist_on_the_public_plane() {
        let state = seeded_state().await;
        // The management API, the UI, and the sign-in flow are internal-plane
        // only; the public listener must not even route them.
        for path in ["/api/v1/projects", "/", "/setup", "/auth/login", "/static/styles.css"] {
            let (status, _) = get(&state, Plane::Public, path).await;
            assert_eq!(status, 404, "{path} should not be routed publicly");
        }
    }

    #[actix_web::test]
    async fn ui_pages_redirect_unauthenticated_browsers_to_sign_in() {
        let state = seeded_state().await;
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(state.clone()))
                .app_data(web::Data::new(Plane::Internal))
                .configure(configure_internal),
        )
        .await;
        let response = test::call_service(
            &app,
            test::TestRequest::get().uri("/projects/SierraSoftworks/grey").to_request(),
        )
        .await;
        assert_eq!(response.status().as_u16(), 302);
        let location = response
            .headers()
            .get(actix_web::http::header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(
            location.starts_with("/auth/login?next=%2Fprojects%2FSierraSoftworks%2Fgrey"),
            "unexpected redirect target: {location}"
        );
    }

    /// A session cookie for a signed-in user, as the sign-in flow would mint
    /// it: the claims the issuer asserted, verbatim.
    fn session_for(state: &Arc<AppState>) -> String {
        state
            .sessions
            .issue_session(&crate::auth::Identity::new(
                serde_json::json!({
                    "sub": "user-1",
                    "email": "benjamin@example.com",
                    "name": "Benjamin",
                    "groups": ["readers"],
                })
                .as_object()
                .unwrap()
                .clone(),
            ))
            .unwrap()
    }

    #[actix_web::test]
    async fn session_cookie_grants_access_to_ui_and_api() {
        let state = seeded_state().await;
        let session = session_for(&state);

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(state.clone()))
                .app_data(web::Data::new(Plane::Internal))
                .configure(configure_internal),
        )
        .await;

        for uri in ["/", "/projects/SierraSoftworks/grey", "/api/v1/projects", "/api/v1/stats"] {
            let response = test::call_service(
                &app,
                test::TestRequest::get()
                    .uri(uri)
                    .cookie(actix_web::cookie::Cookie::new(
                        crate::auth::SESSION_COOKIE,
                        session.clone(),
                    ))
                    .to_request(),
            )
            .await;
            assert_eq!(response.status().as_u16(), 200, "{uri} should be accessible");
        }

        // And the rendered dashboard should carry the signed-in user.
        let response = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/")
                .cookie(actix_web::cookie::Cookie::new(
                    crate::auth::SESSION_COOKIE,
                    session.clone(),
                ))
                .to_request(),
        )
        .await;
        let body = String::from_utf8(test::read_body(response).await.to_vec()).unwrap();
        assert!(body.contains("Benjamin"));
        assert!(body.contains("SierraSoftworks/grey"));
    }

    #[actix_web::test]
    async fn the_acl_gates_an_authenticated_session() {
        // A read-only ACL: this user's group may look, but not touch.
        let state = seeded_state_with(|config| {
            config.management.acl =
                filt_rs::Filter::new(r#"claims.groups contains "owners" || method == "GET""#)
                    .unwrap();
        })
        .await;
        let session = session_for(&state);
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(state.clone()))
                .app_data(web::Data::new(Plane::Internal))
                .configure(configure_internal),
        )
        .await;
        let with_session = || {
            actix_web::cookie::Cookie::new(crate::auth::SESSION_COOKIE, session.clone())
        };

        let response = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/api/v1/projects")
                .cookie(with_session())
                .to_request(),
        )
        .await;
        assert_eq!(response.status().as_u16(), 200, "reads are permitted");

        let response = test::call_service(
            &app,
            test::TestRequest::delete()
                .uri("/api/v1/projects/SierraSoftworks/grey/symbols/aabbccdd")
                .cookie(with_session())
                .to_request(),
        )
        .await;
        assert_eq!(response.status().as_u16(), 403, "writes are not");
        // The symbol is still there.
        let (status, _) = get(&state, Plane::Internal, "/buildid/aabbccdd/debuginfo").await;
        assert_eq!(status, 200);
    }

    #[actix_web::test]
    async fn an_acl_rejection_renders_a_403_page_rather_than_looping_sign_in() {
        let state = seeded_state_with(|config| {
            config.management.acl = filt_rs::Filter::new("false").unwrap();
        })
        .await;
        let session = session_for(&state);
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(state.clone()))
                .app_data(web::Data::new(Plane::Internal))
                .configure(configure_internal),
        )
        .await;

        let response = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/")
                .cookie(actix_web::cookie::Cookie::new(
                    crate::auth::SESSION_COOKIE,
                    session,
                ))
                .to_request(),
        )
        .await;
        // A 302 back to /auth/login here would bounce the user round the
        // sign-in flow forever, since signing in again changes nothing.
        assert_eq!(response.status().as_u16(), 403);
        let body = String::from_utf8(test::read_body(response).await.to_vec()).unwrap();
        assert!(body.contains("not permitted"), "unexpected body: {body}");
    }
}
