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
use crate::storage::{Project, SymbolMeta, Visibility};

/// Largest request body we will read. This is the encoded size — a gzipped
/// upload of this size holds far more DWARF than any build produces.
const MAX_UPLOAD_BYTES: usize = 1024 * 1024 * 1024;

/// Largest symbol file we will hold in memory once decoded. The whole file is
/// needed to derive its build ID, so this bounds the server's footprint (and
/// the damage a pathological compression ratio could do).
const MAX_SYMBOL_BYTES: usize = 2 * 1024 * 1024 * 1024;

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

    // The body is read only after the uploader has been authorized: it runs to
    // hundreds of megabytes, and there is no reason to buffer that for a
    // request we are about to reject.
    let body = read_body(payload, &req, MAX_UPLOAD_BYTES).await?;
    if body.is_empty() {
        return Err(Error::BadRequest("empty upload".to_string()));
    }

    // Everything is stored gzipped: a compressed upload is stored exactly as
    // it arrived, and a plain one is compressed here.
    let (symbols, stored) = match body_encoding(&req, &body)? {
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

/// How the body is encoded. `Content-Encoding` decides it; without one we
/// sniff, since no symbol format we accept can be mistaken for gzip and a
/// client that sent a `.gz` without the header still means it.
fn body_encoding(req: &HttpRequest, body: &[u8]) -> Result<Compression, Error> {
    match req
        .headers()
        .get(header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
    {
        Some(encoding) if encoding.eq_ignore_ascii_case("gzip") => Ok(Compression::Gzip),
        Some(encoding) if !encoding.eq_ignore_ascii_case("identity") => Err(Error::BadRequest(
            format!("unsupported Content-Encoding '{encoding}'; send the body raw or gzipped"),
        )),
        _ if compression::looks_gzipped(body) => Ok(Compression::Gzip),
        _ => Ok(Compression::None),
    }
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
        let gzipped = compression::compress(b"\x7fELF").unwrap();

        assert_eq!(
            body_encoding(&request(&[("content-encoding", "gzip")]), &gzipped).unwrap(),
            Compression::Gzip
        );
        assert_eq!(
            body_encoding(&request(&[]), b"\x7fELF...").unwrap(),
            Compression::None
        );
        // Sniffed: a client that sent a .gz without saying so still meant it.
        assert_eq!(body_encoding(&request(&[]), &gzipped).unwrap(), Compression::Gzip);
        assert_eq!(
            body_encoding(&request(&[("content-encoding", "identity")]), &gzipped).unwrap(),
            Compression::Gzip
        );
        assert!(matches!(
            body_encoding(&request(&[("content-encoding", "br")]), &gzipped),
            Err(Error::BadRequest(_))
        ));
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
