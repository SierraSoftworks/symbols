use std::sync::Arc;

use actix_web::{HttpRequest, HttpResponse, http::header, web};
use bytes::Bytes;
use futures::StreamExt;
use serde::Deserialize;

use super::AppState;
use crate::auth::{GithubClaims, bearer_token};
use crate::compression::{self, Compression};
use crate::errors::Error;
use crate::formats::identify;
use crate::storage::{Project, SymbolMeta, UploadSession, Visibility};

/// Largest request body we will read. This is the encoded size — a gzipped
/// upload of this size holds far more DWARF than any build produces.
const MAX_UPLOAD_BYTES: usize = 1024 * 1024 * 1024;

/// Largest symbol file we will hold in memory once decoded. The whole file is
/// needed to derive its build ID, so this bounds the server's footprint (and
/// the damage a pathological compression ratio could do).
const MAX_SYMBOL_BYTES: usize = 2 * 1024 * 1024 * 1024;

/// Chunked uploads accept at most this many parts. Combined with the body
/// limit this is far beyond any real symbol file; it exists to bound the
/// assembly loop.
const MAX_UPLOAD_CHUNKS: u32 = 256;

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
///
/// The body may be sent gzipped (`Content-Encoding: gzip`), which is how the
/// publish action sends it: DWARF compresses several-fold, keeping large
/// uploads under the body limits of any CDN in front of the server. Those
/// bytes are also what gets stored, so a compressed upload costs the server
/// no re-encoding at all.
pub async fn upload_symbol(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    query: web::Query<UploadQuery>,
    payload: web::Payload,
) -> Result<HttpResponse, Error> {
    let claims = authorize_uploader(&req, &state).await?;

    let mut query = query.into_inner();
    normalize_metadata(&mut query);
    validate_metadata(&query)?;

    // The body is read only after the uploader has been authorized: it runs to
    // hundreds of megabytes, and there is no reason to buffer that for a
    // request we are about to reject.
    let body = read_body(payload, &req, MAX_UPLOAD_BYTES).await?;

    let encoding = declared_encoding(&req)?;
    store_symbols(&state, &claims, &query, body, encoding).await
}

/// The shared upload authorization: a valid GitHub Actions OIDC token, from a
/// repository in a trusted organization, running against an allowed ref.
async fn authorize_uploader(
    req: &HttpRequest,
    state: &AppState,
) -> Result<GithubClaims, Error> {
    let token = bearer_token(req)?;
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

    Ok(claims)
}

/// The tail of every upload, single-shot or chunked: work out the encoding,
/// derive the build ID, resolve the project, and store the symbols.
///
/// `encoding` is the request's declared `Content-Encoding` where there was a
/// single request to declare one; an assembled chunked body has none and
/// relies on the gzip sniff.
async fn store_symbols(
    state: &AppState,
    claims: &GithubClaims,
    query: &UploadQuery,
    body: Bytes,
    encoding: Option<Compression>,
) -> Result<HttpResponse, Error> {
    if body.is_empty() {
        return Err(Error::BadRequest("empty upload".to_string()));
    }

    // Everything is stored gzipped: a compressed upload is stored exactly as
    // it arrived, and a plain one is compressed here.
    let encoding = match encoding {
        Some(encoding) => encoding,
        None if compression::looks_gzipped(&body) => Compression::Gzip,
        None => Compression::None,
    };
    let (symbols, stored) = match encoding {
        Compression::Gzip => {
            let encoded = body.clone();
            let symbols =
                blocking(move || compression::decompress(&encoded, MAX_SYMBOL_BYTES)).await?;
            (symbols, body)
        }
        Compression::None => {
            let plain = body.clone();
            let stored = blocking(move || compression::compress(&plain)).await?;
            (body, stored)
        }
    };

    let info = identify(&symbols)?;

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

    let size = symbols.len() as u64;
    let stored_size = stored.len() as u64;
    // The decompressed copy has served its purpose (identifying the file); let
    // it go before the upload to storage rather than holding both.
    drop(symbols);

    let meta = SymbolMeta {
        id: info.id.clone(),
        format: info.format,
        // The file's own architecture wins; the uploader's tag only fills the
        // gap for formats that don't declare one (PDBs).
        arch: info.arch.clone().or_else(|| query.arch.clone()),
        version: query.version.clone(),
        size,
        compression: Compression::Gzip,
        stored_size: Some(stored_size),
        uploaded_at: chrono::Utc::now(),
        uploaded_from: claims.git_ref.clone(),
        os: query.os.as_deref().map(|os| os.to_ascii_lowercase()),
        commit: query.commit.as_deref().map(|c| c.to_ascii_lowercase()),
        build_url: query.build_url.clone(),
    };

    state.store.put_symbol(&project.name, &info, &meta, stored).await?;

    tracing::info!(
        project = %project.name,
        build_id = %info.id,
        format = ?info.format,
        arch = ?info.arch,
        version = %meta.version,
        size,
        stored_size,
        "Stored symbols"
    );

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "build_id": info.id,
        "project": project.name,
        "format": info.format,
        "arch": info.arch,
        "version": meta.version,
        "size": size,
        "stored_size": stored_size,
        "compression": meta.compression,
    })))
}

// --- Chunked uploads --------------------------------------------------------
//
// A single-request upload is bounded by whatever request-body limit the
// smallest hop in front of the server imposes (a CDN's cap is typically
// ~100MB). Large symbol files go up in parts instead:
//
//   POST /api/v1/uploads?version=...          -> { "upload_id": ... }
//   PUT  /api/v1/uploads/{id}/chunks/{index}  (raw bytes, in order from 0)
//   POST /api/v1/uploads/{id}/complete?chunks=N
//
// Chunks are staged in object storage under `_staging/{id}/`, so sessions
// survive server restarts and abandoned ones are swept by retention.
// Completion assembles the parts and feeds the result through exactly the
// same pipeline as a single-shot upload; the assembled body is expected to be
// the same gzipped stream the action would otherwise have POSTed whole.

/// `POST /api/v1/uploads` — opens a chunked upload session. Authentication and
/// metadata validation happen here, once; later requests on the session prove
/// they come from the same repository.
pub async fn create_upload(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    query: web::Query<UploadQuery>,
) -> Result<HttpResponse, Error> {
    let claims = authorize_uploader(&req, &state).await?;

    let mut query = query.into_inner();
    normalize_metadata(&mut query);
    validate_metadata(&query)?;

    let session = UploadSession {
        id: hex::encode(rand::random::<[u8; 16]>()),
        project: claims.repository.clone(),
        created_at: chrono::Utc::now(),
        version: query.version,
        os: query.os,
        arch: query.arch,
        commit: query.commit,
        build_url: query.build_url,
    };
    state.store.create_upload(&session).await?;

    tracing::info!(
        upload_id = %session.id,
        project = %session.project,
        version = %session.version,
        "Opened chunked upload session"
    );

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "upload_id": session.id,
        "max_chunks": MAX_UPLOAD_CHUNKS,
    })))
}

/// `PUT /api/v1/uploads/{id}/chunks/{index}` — stages one part of the body.
/// Parts carry raw slices of the (typically gzipped) file; no per-chunk
/// encoding applies.
pub async fn put_upload_chunk(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    path: web::Path<(String, u32)>,
    payload: web::Payload,
) -> Result<HttpResponse, Error> {
    let claims = authorize_uploader(&req, &state).await?;
    let (id, index) = path.into_inner();
    let session = load_session(&state, &id, &claims).await?;

    if index >= MAX_UPLOAD_CHUNKS {
        return Err(Error::BadRequest(format!(
            "chunk index {index} is out of range (at most {MAX_UPLOAD_CHUNKS} chunks)"
        )));
    }

    let body = read_body(payload, &req, MAX_UPLOAD_BYTES).await?;
    if body.is_empty() {
        return Err(Error::BadRequest("empty chunk".to_string()));
    }

    let size = body.len();
    state.store.put_upload_chunk(&session.id, index, body).await?;

    tracing::debug!(upload_id = %session.id, index, size, "Staged upload chunk");
    Ok(HttpResponse::Ok().json(serde_json::json!({ "received": index, "size": size })))
}

#[derive(Debug, Deserialize)]
pub struct CompleteQuery {
    /// How many chunks the client sent; completion fails if any of 0..N-1 is
    /// missing, so a dropped part can never produce silently truncated
    /// symbols.
    pub chunks: u32,
}

/// `POST /api/v1/uploads/{id}/complete` — assembles the staged chunks and
/// stores the result exactly as if it had arrived in one request.
pub async fn complete_upload(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    path: web::Path<String>,
    query: web::Query<CompleteQuery>,
) -> Result<HttpResponse, Error> {
    let claims = authorize_uploader(&req, &state).await?;
    let id = path.into_inner();
    let session = load_session(&state, &id, &claims).await?;

    let count = query.chunks;
    if count == 0 || count > MAX_UPLOAD_CHUNKS {
        return Err(Error::BadRequest(format!(
            "chunk count must be between 1 and {MAX_UPLOAD_CHUNKS}"
        )));
    }

    let body = assemble_chunks(&state.store, &session.id, count).await?;

    let upload_query = UploadQuery {
        version: session.version.clone(),
        os: session.os.clone(),
        arch: session.arch.clone(),
        commit: session.commit.clone(),
        build_url: session.build_url.clone(),
    };

    // Assembled bodies have no Content-Encoding of their own; the gzip sniff
    // in store_symbols decides.
    let response = store_symbols(&state, &claims, &upload_query, body, None).await?;

    // Best-effort: an orphaned staging area is only storage, and the sweep
    // clears it if this fails.
    if let Err(e) = state.store.delete_upload(&session.id).await {
        tracing::warn!(upload_id = %session.id, error = %e, "Failed to clear upload staging");
    }

    Ok(response)
}

/// Reads the staged chunks back in order and concatenates them, refusing a
/// session with a gap (a dropped part must never become silently truncated
/// symbols) or one that assembles past the body limit.
async fn assemble_chunks(
    store: &crate::storage::Store,
    id: &str,
    count: u32,
) -> Result<Bytes, Error> {
    let mut body = web::BytesMut::new();
    for index in 0..count {
        let chunk = store.get_upload_chunk(id, index).await?.ok_or_else(|| {
            Error::BadRequest(format!("chunk {index} of {count} was never uploaded"))
        })?;
        if body.len() + chunk.len() > MAX_UPLOAD_BYTES {
            return Err(Error::TooLarge(format!(
                "assembled upload exceeds the {MAX_UPLOAD_BYTES} byte limit"
            )));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body.freeze())
}

/// Fetches a session and proves the caller owns it: the token's `repository`
/// claim must match the one that opened the session, so one repository can
/// never write into (or complete) another's upload. Session ids arrive from
/// the client and are validated to the exact shape we mint before touching
/// storage paths.
async fn load_session(
    state: &AppState,
    id: &str,
    claims: &GithubClaims,
) -> Result<UploadSession, Error> {
    if !valid_upload_id(id) {
        return Err(Error::BadRequest("invalid upload id".to_string()));
    }

    let session = state
        .store
        .get_upload(id)
        .await?
        .ok_or(Error::NotFound)?;

    if session.project != claims.repository {
        // Indistinguishable from absent, so ids can't be probed across repos.
        return Err(Error::NotFound);
    }

    Ok(session)
}

/// Buffers the request body without decoding it, so a compressed upload keeps
/// the exact bytes we intend to store.
async fn read_body(
    mut payload: web::Payload,
    req: &HttpRequest,
    limit: usize,
) -> Result<Bytes, Error> {
    let declared = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok());
    if declared.is_some_and(|len| len > limit) {
        return Err(Error::TooLarge(format!(
            "uploads are limited to {limit} bytes; gzip the symbol file to fit"
        )));
    }

    let mut buffer = web::BytesMut::with_capacity(declared.unwrap_or(0).min(1024 * 1024));
    while let Some(chunk) = payload.next().await {
        let chunk = chunk.map_err(|e| Error::BadRequest(format!("reading the request body: {e}")))?;
        if buffer.len() + chunk.len() > limit {
            return Err(Error::TooLarge(format!(
                "uploads are limited to {limit} bytes; gzip the symbol file to fit"
            )));
        }
        buffer.extend_from_slice(&chunk);
    }

    Ok(buffer.freeze())
}

/// The request's declared `Content-Encoding`, if any. `None` falls back to
/// sniffing the gzip magic in `store_symbols` — no symbol format we accept
/// can be mistaken for gzip, and a client that sent a `.gz` without the
/// header still meant it.
fn declared_encoding(req: &HttpRequest) -> Result<Option<Compression>, Error> {
    match req
        .headers()
        .get(header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
    {
        Some(encoding) if encoding.eq_ignore_ascii_case("gzip") => Ok(Some(Compression::Gzip)),
        Some(encoding) if !encoding.eq_ignore_ascii_case("identity") => Err(Error::BadRequest(
            format!("unsupported Content-Encoding '{encoding}'; send the body raw or gzipped"),
        )),
        _ => Ok(None),
    }
}

/// Exactly the shape `create_upload` mints: 32 lowercase hex characters.
/// Anything else never touches a storage path.
fn valid_upload_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Runs a whole-file (de)compression off the worker threads.
async fn blocking<F>(work: F) -> Result<Bytes, Error>
where
    F: FnOnce() -> Result<Bytes, Error> + Send + 'static,
{
    web::block(work)
        .await
        .map_err(|e| Error::Internal(format!("compression task failed: {e}")))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{FromRequest, test};

    fn request(headers: &[(&str, &str)]) -> HttpRequest {
        let mut builder = test::TestRequest::post();
        for (name, value) in headers {
            builder = builder.insert_header((*name, *value));
        }
        builder.to_http_request()
    }

    async fn payload(body: &'static [u8]) -> (HttpRequest, web::Payload) {
        let (req, mut parts) = test::TestRequest::post()
            .set_payload(Bytes::from_static(body))
            .to_http_parts();
        let payload = web::Payload::from_request(&req, &mut parts).await.unwrap();
        (req, payload)
    }

    #[actix_web::test]
    async fn content_encoding_decides_how_the_body_is_read() {
        assert_eq!(
            declared_encoding(&request(&[("content-encoding", "gzip")])).unwrap(),
            Some(Compression::Gzip)
        );
        // No declaration (or an explicit identity) defers to the gzip sniff
        // in store_symbols.
        assert_eq!(declared_encoding(&request(&[])).unwrap(), None);
        assert_eq!(
            declared_encoding(&request(&[("content-encoding", "identity")])).unwrap(),
            None
        );
        assert!(matches!(
            declared_encoding(&request(&[("content-encoding", "br")])),
            Err(Error::BadRequest(_))
        ));
    }

    #[actix_web::test]
    async fn assembles_chunks_in_order_and_refuses_gaps() {
        let store = crate::storage::Store::in_memory();
        let id = "cd".repeat(16);
        // Out-of-order staging must not matter; assembly reads by index.
        store
            .put_upload_chunk(&id, 1, Bytes::from_static(b"world"))
            .await
            .unwrap();
        store
            .put_upload_chunk(&id, 0, Bytes::from_static(b"hello, "))
            .await
            .unwrap();

        let body = assemble_chunks(&store, &id, 2).await.unwrap();
        assert_eq!(body, &b"hello, world"[..]);

        // Claiming a chunk that was never staged is an error, not truncation.
        assert!(matches!(
            assemble_chunks(&store, &id, 3).await,
            Err(Error::BadRequest(_))
        ));
    }

    /// The full completion path minus HTTP and auth: chunks staged out of
    /// order assemble into a gzipped ELF, which store_symbols sniffs,
    /// identifies and stores exactly as a single-shot upload would have.
    #[actix_web::test]
    async fn chunked_uploads_complete_like_single_shot_ones() {
        let build_id = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let elf = crate::formats::minimal_elf_with_build_id(&build_id);
        let gzipped = compression::compress(&elf).unwrap();

        let state = AppState::new(
            crate::config::Config::test(),
            crate::storage::Store::in_memory(),
            reqwest::Client::new(),
        );

        // Stage the gzipped stream in deliberately small chunks.
        let id = "ef".repeat(16);
        let parts: Vec<_> = gzipped.chunks(gzipped.len() / 3 + 1).collect();
        for (index, part) in parts.iter().enumerate() {
            state
                .store
                .put_upload_chunk(&id, index as u32, Bytes::copy_from_slice(part))
                .await
                .unwrap();
        }

        let body = assemble_chunks(&state.store, &id, parts.len() as u32)
            .await
            .unwrap();
        assert_eq!(body, gzipped, "assembly must reproduce the original stream");

        let claims = GithubClaims {
            repository: "SierraSoftworks/analytics".to_string(),
            repository_owner: "SierraSoftworks".to_string(),
            repository_visibility: Some("public".to_string()),
            git_ref: Some("refs/tags/v0.2.1".to_string()),
        };
        let query = UploadQuery {
            version: "v0.2.1".to_string(),
            os: Some("linux".to_string()),
            arch: None,
            commit: None,
            build_url: None,
        };

        // No declared encoding, exactly like an assembled body: the sniff
        // must recognise the gzip stream.
        store_symbols(&state, &claims, &query, body, None).await.unwrap();

        let expected_id = hex::encode(build_id);
        let index = state.store.get_index(&expected_id).await.unwrap().unwrap();
        assert_eq!(index.project, "SierraSoftworks/analytics");
        let stored = state
            .store
            .get_symbol(&index.project, &expected_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.compression, Compression::Gzip);
        assert_eq!(
            stored.result.bytes().await.unwrap(),
            gzipped,
            "the stored bytes are the assembled upload, untranscoded"
        );
    }

    #[actix_web::test]
    async fn upload_ids_must_match_the_minted_shape() {
        assert!(valid_upload_id(&"ab".repeat(16)));
        assert!(!valid_upload_id(""));
        assert!(!valid_upload_id("abc"));
        assert!(!valid_upload_id(&"AB".repeat(16)), "uppercase is never minted");
        assert!(!valid_upload_id(&"zz".repeat(16)));
        assert!(!valid_upload_id("../projects/x/y/deadbeefdeadbeef"));
    }

    #[actix_web::test]
    async fn reads_the_body_without_decoding_it() {
        let gzipped = compression::compress(b"symbols").unwrap();
        let (req, mut parts) = test::TestRequest::post()
            .insert_header(("content-encoding", "gzip"))
            .set_payload(gzipped.clone())
            .to_http_parts();
        let payload = web::Payload::from_request(&req, &mut parts).await.unwrap();

        let body = read_body(payload, &req, MAX_UPLOAD_BYTES).await.unwrap();
        assert_eq!(body, gzipped, "the bytes we store must be the bytes we got");
    }

    #[actix_web::test]
    async fn refuses_bodies_past_the_limit() {
        let (req, payload) = payload(b"0123456789").await;
        assert!(matches!(
            read_body(payload, &req, 4).await,
            Err(Error::TooLarge(_))
        ));

        // A declared length over the limit is refused before anything is read.
        let (req, mut parts) = test::TestRequest::post()
            .insert_header(("content-length", "10000"))
            .to_http_parts();
        let payload = web::Payload::from_request(&req, &mut parts).await.unwrap();
        assert!(matches!(
            read_body(payload, &req, 4).await,
            Err(Error::TooLarge(_))
        ));
    }
}
