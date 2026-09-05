use std::sync::Arc;

use actix_web::{HttpRequest, HttpResponse, http::header, web};
use futures::StreamExt;
use serde::Deserialize;

use super::AppState;
use crate::auth::{GithubClaims, bearer_token};
use crate::compression::Compression;
use crate::errors::Error;
use crate::processor;
use crate::storage::{UploadSession, UploadStatus};

/// Largest upload body we will stage. This is the encoded size — a gzipped
/// upload of this size holds far more DWARF than any build produces.
const MAX_UPLOAD_BYTES: u64 = 1024 * 1024 * 1024;

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
/// The body is never buffered: it streams straight into the staging area
/// (bounded multipart parts), and once durably staged it runs through the
/// same worker pipeline as a chunked upload — awaited inline here, so the
/// response contract is unchanged. A crash mid-request loses nothing the
/// client wasn't already going to retry, and the sweep clears the orphan.
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
    // The header is only validated here; the worker sniffs the staged bytes,
    // which agrees with any Content-Encoding we accept.
    declared_encoding(&req)?;

    let mut session = new_session(&claims, query);
    session.chunks = Some(1);
    state.store.create_upload(&session).await?;

    let result: Result<serde_json::Value, Error> = async {
        let size = stream_to_chunk(&state, &session.id, 0, payload, &req, MAX_UPLOAD_BYTES).await?;
        if size == 0 {
            return Err(Error::BadRequest("empty upload".to_string()));
        }
        processor::process(&state, &session).await
    }
    .await;

    // Single-shot sessions leave no residue: the result went to the client,
    // so there is nothing to poll for.
    if let Err(e) = state.store.delete_upload(&session.id).await {
        tracing::warn!(upload_id = %session.id, error = %e, "Failed to clear upload staging");
    }

    Ok(HttpResponse::Ok().json(result?))
}

fn new_session(claims: &GithubClaims, query: UploadQuery) -> UploadSession {
    UploadSession {
        id: hex::encode(rand::random::<[u8; 16]>()),
        project: claims.repository.clone(),
        repository_visibility: claims.repository_visibility.clone(),
        git_ref: claims.git_ref.clone(),
        created_at: chrono::Utc::now(),
        status: UploadStatus::Uploading,
        chunks: None,
        result: None,
        error: None,
        version: query.version,
        os: query.os,
        arch: query.arch,
        commit: query.commit,
        build_url: query.build_url,
    }
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
// Completion verifies every part arrived, then hands the session to a worker
// job (`crate::processor`) that streams it to its final destination; the
// client polls `GET /api/v1/uploads/{id}` for the outcome. Splitting the
// wait from the work keeps the completion request well inside any proxy's
// response timeout, no matter how large the body.

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

    let session = new_session(&claims, query);
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

    if session.status != UploadStatus::Uploading {
        return Err(Error::BadRequest(
            "this upload was already completed".to_string(),
        ));
    }
    if index >= MAX_UPLOAD_CHUNKS {
        return Err(Error::BadRequest(format!(
            "chunk index {index} is out of range (at most {MAX_UPLOAD_CHUNKS} chunks)"
        )));
    }

    let size = stream_to_chunk(&state, &session.id, index, payload, &req, MAX_UPLOAD_BYTES).await?;
    if size == 0 {
        return Err(Error::BadRequest("empty chunk".to_string()));
    }

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

/// `POST /api/v1/uploads/{id}/complete` — verifies every chunk arrived, then
/// hands the session to a worker job and returns immediately; the client
/// polls the status endpoint for the outcome. Calling complete again on a
/// session already past uploading just reports where it is, so a retried
/// request never double-processes.
pub async fn complete_upload(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    path: web::Path<String>,
    query: web::Query<CompleteQuery>,
) -> Result<HttpResponse, Error> {
    let claims = authorize_uploader(&req, &state).await?;
    let id = path.into_inner();
    let mut session = load_session(&state, &id, &claims).await?;

    if session.status != UploadStatus::Uploading {
        return Ok(status_response(&session));
    }

    let count = query.chunks;
    if count == 0 || count > MAX_UPLOAD_CHUNKS {
        return Err(Error::BadRequest(format!(
            "chunk count must be between 1 and {MAX_UPLOAD_CHUNKS}"
        )));
    }

    // Every part must be durably staged before the job is recorded: a gap
    // found now is the client's error to fix; a gap found later would be a
    // truncated symbol file.
    let mut total: u64 = 0;
    for index in 0..count {
        let size = state
            .store
            .upload_chunk_size(&session.id, index)
            .await?
            .ok_or_else(|| {
                Error::BadRequest(format!("chunk {index} of {count} was never uploaded"))
            })?;
        total += size;
    }
    if total > MAX_UPLOAD_BYTES {
        return Err(Error::TooLarge(format!(
            "assembled upload exceeds the {MAX_UPLOAD_BYTES} byte limit"
        )));
    }

    session.chunks = Some(count);
    session.status = UploadStatus::Pending;
    state.store.create_upload(&session).await?;

    tracing::info!(
        upload_id = %session.id,
        project = %session.project,
        chunks = count,
        total,
        "Queued upload for processing"
    );
    processor::spawn(state.get_ref().clone(), session.clone());

    Ok(status_response(&session))
}

/// `GET /api/v1/uploads/{id}` — where a chunked upload is in its lifecycle;
/// on completion this carries the same payload the single-shot endpoint
/// returns.
pub async fn get_upload_status(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
    path: web::Path<String>,
) -> Result<HttpResponse, Error> {
    let claims = authorize_uploader(&req, &state).await?;
    let session = load_session(&state, &path.into_inner(), &claims).await?;
    Ok(status_response(&session))
}

fn status_response(session: &UploadSession) -> HttpResponse {
    let state = match session.status {
        UploadStatus::Uploading => "uploading",
        // Queued-or-running is an implementation detail; the client just
        // hasn't got a result yet.
        UploadStatus::Pending | UploadStatus::Processing => "processing",
        UploadStatus::Complete => "complete",
        UploadStatus::Failed => "failed",
    };
    HttpResponse::Ok().json(serde_json::json!({
        "upload_id": session.id,
        "state": state,
        "result": session.result,
        "error": session.error,
    }))
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

/// Streams the request body straight into a staged chunk with bounded
/// memory: bytes flow out as multipart parts as they arrive, and nothing is
/// visible at the chunk's path until the stream ends cleanly — a client that
/// disconnects mid-body leaves no partial chunk to assemble later. The limit
/// is enforced both against the declared Content-Length (refused before any
/// byte is read) and as the bytes flow.
async fn stream_to_chunk(
    state: &AppState,
    session_id: &str,
    index: u32,
    mut payload: web::Payload,
    req: &HttpRequest,
    limit: u64,
) -> Result<u64, Error> {
    let declared = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    if declared.is_some_and(|len| len > limit) {
        return Err(Error::TooLarge(format!(
            "uploads are limited to {limit} bytes per request"
        )));
    }

    let mut writer = state.store.upload_chunk_writer(session_id, index).await?;
    while let Some(chunk) = payload.next().await {
        let chunk = match chunk {
            Ok(chunk) => chunk,
            Err(e) => {
                abort_writer(writer).await;
                return Err(Error::BadRequest(format!("reading the request body: {e}")));
            }
        };
        if writer.written() + chunk.len() as u64 > limit {
            abort_writer(writer).await;
            return Err(Error::TooLarge(format!(
                "uploads are limited to {limit} bytes per request"
            )));
        }
        if let Err(e) = writer.write(chunk).await {
            abort_writer(writer).await;
            return Err(e);
        }
    }

    writer.finish().await
}

async fn abort_writer(writer: crate::storage::StreamingWriter) {
    if let Err(e) = writer.abort().await {
        tracing::warn!(error = %e, "Failed to abort interrupted chunk write");
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{FromRequest, test};
    use bytes::Bytes;

    use crate::compression;
    use crate::config::Config;
    use crate::storage::Store;

    fn request(headers: &[(&str, &str)]) -> HttpRequest {
        let mut builder = test::TestRequest::post();
        for (name, value) in headers {
            builder = builder.insert_header((*name, *value));
        }
        builder.to_http_request()
    }

    fn state() -> web::Data<Arc<AppState>> {
        web::Data::new(Arc::new(AppState::new(
            Config::test(),
            Store::in_memory(),
            reqwest::Client::new(),
        )))
    }

    fn claims(repo: &str) -> GithubClaims {
        GithubClaims {
            repository: repo.to_string(),
            repository_owner: repo.split('/').next().unwrap().to_string(),
            repository_visibility: Some("public".to_string()),
            git_ref: Some("refs/tags/v1.0.0".to_string()),
        }
    }

    fn session_for(claims: &GithubClaims, version: &str) -> UploadSession {
        new_session(
            claims,
            UploadQuery {
                version: version.to_string(),
                os: Some("linux".to_string()),
                arch: None,
                commit: None,
                build_url: None,
            },
        )
    }

    async fn payload_of(body: Bytes) -> (HttpRequest, web::Payload) {
        let (req, mut parts) = test::TestRequest::post().set_payload(body).to_http_parts();
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
        // in the worker.
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
    async fn upload_ids_must_match_the_minted_shape() {
        assert!(valid_upload_id(&"ab".repeat(16)));
        assert!(!valid_upload_id(""));
        assert!(!valid_upload_id("abc"));
        assert!(!valid_upload_id(&"AB".repeat(16)), "uppercase is never minted");
        assert!(!valid_upload_id(&"zz".repeat(16)));
        assert!(!valid_upload_id("../projects/x/y/deadbeefdeadbeef"));
    }

    /// The request body must land in staging byte-for-byte — it is the bytes
    /// the worker will store.
    #[actix_web::test]
    async fn streams_the_body_into_staging_without_decoding_it() {
        let state = state();
        let gzipped = compression::compress(b"symbols").unwrap();
        let (req, payload) = payload_of(gzipped.clone()).await;

        let size = stream_to_chunk(&state, &"ab".repeat(16), 0, payload, &req, MAX_UPLOAD_BYTES)
            .await
            .unwrap();
        assert_eq!(size, gzipped.len() as u64);

        let staged = state
            .store
            .get_upload_chunk(&"ab".repeat(16), 0)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(staged, gzipped, "the bytes we stage must be the bytes we got");
    }

    #[actix_web::test]
    async fn refuses_bodies_past_the_limit() {
        let state = state();
        let id = "cd".repeat(16);

        let (req, payload) = payload_of(Bytes::from_static(b"0123456789")).await;
        assert!(matches!(
            stream_to_chunk(&state, &id, 0, payload, &req, 4).await,
            Err(Error::TooLarge(_))
        ));
        // Nothing partial is left behind for a later complete to assemble.
        assert!(state.store.get_upload_chunk(&id, 0).await.unwrap().is_none());

        // A declared length over the limit is refused before anything is read.
        let (req, mut parts) = test::TestRequest::post()
            .insert_header(("content-length", "10000"))
            .to_http_parts();
        let payload = web::Payload::from_request(&req, &mut parts).await.unwrap();
        assert!(matches!(
            stream_to_chunk(&state, &id, 0, payload, &req, 4).await,
            Err(Error::TooLarge(_))
        ));
    }

    /// The full worker path: chunks staged out of order stream through
    /// decode, identify and the final write exactly as a single-shot upload
    /// would, and the stored bytes are the staged stream untranscoded.
    #[actix_web::test]
    async fn chunked_uploads_complete_like_single_shot_ones() {
        let build_id = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let elf = crate::formats::minimal_elf_with_build_id(&build_id);
        let gzipped = compression::compress(&elf).unwrap();

        let state = state();
        let claims = claims("SierraSoftworks/analytics");
        let mut session = session_for(&claims, "v0.2.1");

        // Stage the gzipped stream in deliberately small chunks, out of order.
        let parts: Vec<_> = gzipped.chunks(gzipped.len() / 3 + 1).collect();
        for (index, part) in parts.iter().enumerate().rev() {
            state
                .store
                .put_upload_chunk(&session.id, index as u32, Bytes::copy_from_slice(part))
                .await
                .unwrap();
        }
        session.chunks = Some(parts.len() as u32);

        let result = processor::process(&state, &session).await.unwrap();

        let expected_id = hex::encode(build_id);
        assert_eq!(result["build_id"], expected_id.as_str());
        assert_eq!(result["project"], "SierraSoftworks/analytics");
        assert_eq!(result["size"], elf.len() as u64);

        let index = state.store.get_index(&expected_id).await.unwrap().unwrap();
        assert_eq!(index.project, "SierraSoftworks/analytics");
        let stored = state
            .store
            .get_symbol(&index.project, &expected_id, None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.info.compression, Compression::Gzip);
        assert_eq!(
            stored.result.bytes().await.unwrap(),
            gzipped,
            "the stored bytes are the staged upload, untranscoded"
        );
    }

    /// A raw (uncompressed) upload is gzip-encoded on its way to storage.
    #[actix_web::test]
    async fn raw_uploads_are_compressed_at_rest() {
        let build_id = [0xaau8; 8];
        let elf = crate::formats::minimal_elf_with_build_id(&build_id);

        let state = state();
        let claims = claims("SierraSoftworks/grey");
        let mut session = session_for(&claims, "v1.0.0");
        state
            .store
            .put_upload_chunk(&session.id, 0, Bytes::from(elf.clone()))
            .await
            .unwrap();
        session.chunks = Some(1);

        let result = processor::process(&state, &session).await.unwrap();
        assert_eq!(result["size"], elf.len() as u64);

        let expected_id = hex::encode(build_id);
        let stored = state
            .store
            .get_symbol("SierraSoftworks/grey", &expected_id, None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.info.compression, Compression::Gzip);
        let decoded =
            compression::decompress(&stored.result.bytes().await.unwrap(), 1 << 20).unwrap();
        assert_eq!(decoded, elf, "round-trips through the at-rest encoding");
    }

    /// A gap in the staged chunks fails processing rather than storing a
    /// truncated symbol file.
    #[actix_web::test]
    async fn processing_refuses_missing_chunks() {
        let state = state();
        let claims = claims("SierraSoftworks/grey");
        let mut session = session_for(&claims, "v1.0.0");
        state
            .store
            .put_upload_chunk(&session.id, 0, Bytes::from_static(b"only part"))
            .await
            .unwrap();
        session.chunks = Some(2);

        let err = processor::process(&state, &session).await.unwrap_err();
        assert!(
            matches!(err, Error::Internal(_) | Error::BadRequest(_)),
            "got {err:?}"
        );
    }

    /// Garbage that is neither gzip nor a symbol format is rejected by the
    /// worker, not stored.
    #[actix_web::test]
    async fn processing_rejects_unidentifiable_uploads() {
        let state = state();
        let claims = claims("SierraSoftworks/grey");
        let mut session = session_for(&claims, "v1.0.0");
        state
            .store
            .put_upload_chunk(&session.id, 0, Bytes::from_static(b"not a symbol file at all"))
            .await
            .unwrap();
        session.chunks = Some(1);

        assert!(matches!(
            processor::process(&state, &session).await.unwrap_err(),
            Error::UnrecognisedFormat(_)
        ));
    }
}
