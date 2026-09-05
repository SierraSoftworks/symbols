use std::ops::Range;
use std::sync::Arc;
use std::time::SystemTime;

use actix_web::body::{self, SizedStream};
use actix_web::http::header::{
    self, ContentRange, ContentRangeSpec, ETag, EntityTag, Header, HttpDate, IfModifiedSince,
    IfNoneMatch, IfRange, LastModified, Range as RangeHeader,
};
use actix_web::http::{Method, StatusCode};
use actix_web::{HttpRequest, HttpResponse, HttpResponseBuilder, web};
use bytes::Bytes;
use chrono::{DateTime, Utc};
use futures::{StreamExt, TryStreamExt};

use super::{AppState, Plane};
use crate::compression::{self, ByteStream, Compression};
use crate::errors::Error;
use crate::formats::sanitize_id;
use crate::storage::{ObjectInfo, Store, StoredObject, Visibility};

/// Symbols are addressed by build ID and the bytes behind one never change,
/// so any cache may keep a response for as long as it likes. (Withdrawing a
/// project from the public plane is not retroactive for caches that already
/// hold its symbols — the same is true of any CDN in front of the server.)
const CACHE_CONTROL: &str = "public, max-age=31536000, immutable";

/// `GET`/`HEAD /buildid/{id}/debuginfo` — the debuginfod lookup protocol, as
/// spoken by Pyroscope's symbolizer, elfutils tooling (`DEBUGINFOD_URLS`),
/// gdb, etc. A HEAD gets exactly the headers the GET would, and no body.
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
            // The symbol's metadata records the file's own size, which is
            // what an inflated response's Content-Length reports.
            let size = state
                .store
                .get_symbol_meta(&index.project, &id)
                .await?
                .map(|meta| meta.size);
            let source = Source::Symbol {
                project: &index.project,
                id: &id,
            };
            if let Some(response) = serve(&req, &state.store, source, size).await? {
                tracing::debug!(build_id = %id, project = %index.project, "Serving stored symbol");
                return Ok(response);
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

/// Where a served object lives. Locally published symbols and the federated
/// upstream cache are stored the same way, so one response path — content
/// negotiation, HEAD, byte ranges, conditional requests — covers both.
#[derive(Clone, Copy)]
enum Source<'a> {
    Symbol { project: &'a str, id: &'a str },
    Upstream { id: &'a str },
}

impl Source<'_> {
    fn id(&self) -> &str {
        match self {
            Source::Symbol { id, .. } | Source::Upstream { id } => id,
        }
    }

    async fn head(&self, store: &Store) -> Result<Option<ObjectInfo>, Error> {
        match *self {
            Source::Symbol { project, id } => store.head_symbol(project, id).await,
            Source::Upstream { id } => store.head_upstream(id).await,
        }
    }

    async fn get(
        &self,
        store: &Store,
        range: Option<Range<u64>>,
    ) -> Result<Option<StoredObject>, Error> {
        match *self {
            Source::Symbol { project, id } => store.get_symbol(project, id, range).await,
            Source::Upstream { id } => store.get_upstream(id, range).await,
        }
    }
}

/// Answers a GET or HEAD for a stored object, or `None` when there is no such
/// object. `size` is the symbol file's inflated length when the caller knows
/// it; what the object itself records is the fallback.
///
/// Symbols are held gzipped. A client that advertises gzip gets those bytes
/// untouched — no inflation here, no re-compression at the edge, and a
/// fraction of the bytes on the wire; anyone else gets the same stream
/// inflated on the way past. Either way the server never holds a whole
/// symbol file in memory to serve it.
async fn serve(
    req: &HttpRequest,
    store: &Store,
    source: Source<'_>,
    size: Option<u64>,
) -> Result<Option<HttpResponse>, Error> {
    let head_only = req.method() == Method::HEAD;
    // Anything that may end without a body — a HEAD, a 304, a 416 or a range
    // — is decided on the object's metadata alone, so no body is fetched only
    // to be dropped. A plain GET goes straight for the object.
    let metadata_first = head_only
        || [header::RANGE, header::IF_NONE_MATCH, header::IF_MODIFIED_SINCE]
            .iter()
            .any(|name| req.headers().contains_key(name));

    let (info, object) = if metadata_first {
        match source.head(store).await? {
            Some(info) => (info, None),
            None => return Ok(None),
        }
    } else {
        match source.get(store, None).await? {
            Some(object) => (object.info.clone(), Some(object)),
            None => return Ok(None),
        }
    };

    let gzip = info.compression == Compression::Gzip && accepts_gzip(req);
    // Whether the stored bytes go out as they are (a gzip client, or a plain
    // object), as opposed to inflated on the way past.
    let verbatim = gzip || info.compression == Compression::None;
    let size = size
        .or(info.size)
        .or((info.compression == Compression::None).then_some(info.stored_size));
    let validators = Validators::new(&info, source.id(), verbatim);

    if validators.not_modified(req) {
        let mut response = HttpResponse::build(StatusCode::NOT_MODIFIED);
        validators.apply(&mut response);
        return Ok(Some(response.body(body::None::new())));
    }

    // Byte ranges apply to the bytes we send untouched — the stored object,
    // which storage reads as a range — never to an inflated response: a range
    // of *that* representation could only be served by inflating from the
    // start. There, `Accept-Ranges: none` says so and any Range is ignored.
    let range = if verbatim && !head_only {
        requested_range(req, &validators, info.stored_size)
    } else {
        RangeOutcome::Full
    };

    let mut response = HttpResponse::build(match range {
        RangeOutcome::Full => StatusCode::OK,
        RangeOutcome::Partial(_) => StatusCode::PARTIAL_CONTENT,
        RangeOutcome::Unsatisfiable => StatusCode::RANGE_NOT_SATISFIABLE,
    });
    response.content_type("application/octet-stream");
    validators.apply(&mut response);
    response.insert_header((header::ACCEPT_RANGES, if verbatim { "bytes" } else { "none" }));
    if let Some(size) = size {
        // The debuginfod protocol's own size header: always the symbol
        // file's size, whatever encoding it travels in.
        response.insert_header(("x-debuginfod-size", size));
    }
    if gzip {
        response.insert_header((header::CONTENT_ENCODING, "gzip"));
    }

    let partial = match range {
        RangeOutcome::Unsatisfiable => {
            response.insert_header(ContentRange(ContentRangeSpec::Bytes {
                range: None,
                instance_length: Some(info.stored_size),
            }));
            return Ok(Some(response.body(body::None::new())));
        }
        RangeOutcome::Partial(range) => Some(range),
        RangeOutcome::Full => None,
    };

    if head_only {
        // The length the GET would carry, and no body.
        let length = if verbatim { Some(info.stored_size) } else { size };
        return Ok(Some(match length {
            Some(length) => sized(&mut response, length, empty_body()),
            None => response.body(body::None::new()),
        }));
    }

    let object = match object {
        Some(object) => object,
        None => match source.get(store, partial).await? {
            Some(object) => object,
            None => return Ok(None),
        },
    };
    let served = object.range.clone();
    let stream: ByteStream = Box::pin(
        object
            .result
            .into_stream()
            .map_err(|e| std::io::Error::other(format!("storage stream: {e}"))),
    );

    Ok(Some(if verbatim {
        if served != (0..info.stored_size) {
            response.insert_header(ContentRange(ContentRangeSpec::Bytes {
                range: Some((served.start, served.end - 1)),
                instance_length: Some(info.stored_size),
            }));
        }
        sized(&mut response, served.end - served.start, stream)
    } else {
        let inflated = compression::decode_stream(stream);
        match size {
            Some(size) => sized(&mut response, size, inflated),
            // The inflated length isn't recorded for this object (an upstream
            // cache entry from before it was), so this goes out chunked.
            None => response.streaming(inflated),
        }
    }))
}

fn empty_body() -> futures::stream::Empty<Result<Bytes, std::io::Error>> {
    futures::stream::empty()
}

/// A body of known length: `Content-Length` rather than chunked framing —
/// which is also what lets a HEAD report the length with no body at all.
fn sized<S>(response: &mut HttpResponseBuilder, length: u64, stream: S) -> HttpResponse
where
    S: futures::Stream<Item = Result<Bytes, std::io::Error>> + 'static,
{
    response.no_chunking(length);
    response.body(SizedStream::new(length, stream))
}

/// The validators a response carries and conditional requests are judged
/// against. The ETag is the store's own (S3 derives it from the object's
/// content, so it is a strong validator of the stored bytes and survives a
/// re-upload of the same build ID only if the bytes are the same); an
/// inflated response is a different representation and carries a distinct
/// tag. Without a store ETag, the build ID and write time stand in.
struct Validators {
    etag: EntityTag,
    /// Truncated to the second, which is all an HTTP date carries — so the
    /// date sent out compares equal to the same date coming back.
    last_modified: DateTime<Utc>,
}

impl Validators {
    fn new(info: &ObjectInfo, id: &str, verbatim: bool) -> Self {
        let stored = info
            .e_tag
            .as_deref()
            .map(|tag| {
                tag.trim_start_matches("W/")
                    .chars()
                    .filter(|c| c.is_ascii_graphic() && *c != '"')
                    .collect::<String>()
            })
            .filter(|tag| !tag.is_empty())
            .unwrap_or_else(|| format!("{id}-{}", info.last_modified.timestamp()));
        let tag = if verbatim {
            stored
        } else {
            format!("{stored}-identity")
        };
        let last_modified = DateTime::from_timestamp(info.last_modified.timestamp(), 0)
            .unwrap_or(info.last_modified);
        Self {
            etag: EntityTag::new_strong(tag),
            last_modified,
        }
    }

    fn http_date(&self) -> HttpDate {
        HttpDate::from(SystemTime::from(self.last_modified))
    }

    /// The headers every response about this object carries, 304s included.
    fn apply(&self, response: &mut HttpResponseBuilder) {
        response
            // What comes back depends on what the client accepts, and there
            // are caches (a CDN, at least) between us and it.
            .insert_header((header::VARY, "accept-encoding"))
            .insert_header((header::CACHE_CONTROL, CACHE_CONTROL))
            .insert_header(ETag(self.etag.clone()))
            .insert_header(LastModified(self.http_date()));
    }

    /// Whether the client's copy is current. `If-None-Match` wins when both
    /// it and `If-Modified-Since` are present (RFC 9110 §13.1.3).
    fn not_modified(&self, req: &HttpRequest) -> bool {
        // An absent header parses as an empty list, which is no condition.
        match IfNoneMatch::parse(req) {
            Ok(IfNoneMatch::Any) => return true,
            Ok(IfNoneMatch::Items(tags)) if !tags.is_empty() => {
                return tags.iter().any(|tag| tag.weak_eq(&self.etag));
            }
            _ => {}
        }
        match IfModifiedSince::parse(req) {
            Ok(IfModifiedSince(since)) => {
                SystemTime::from(self.last_modified) <= SystemTime::from(since)
            }
            Err(_) => false,
        }
    }
}

enum RangeOutcome {
    Full,
    /// Half-open, in bytes of the stored object.
    Partial(Range<u64>),
    Unsatisfiable,
}

/// The single byte range a client asked for, against a representation `len`
/// bytes long. Anything that can't be honoured — several ranges, another
/// unit, an unparseable spec, an `If-Range` naming a different version — is
/// answered with the whole representation rather than an error; only a
/// well-formed range lying entirely past the end is unsatisfiable.
fn requested_range(req: &HttpRequest, validators: &Validators, len: u64) -> RangeOutcome {
    let Ok(RangeHeader::Bytes(specs)) = RangeHeader::parse(req) else {
        return RangeOutcome::Full;
    };
    let [spec] = specs.as_slice() else {
        return RangeOutcome::Full;
    };
    // If-Range: the range only makes sense against the copy the client
    // already holds, identified by a strong ETag match or the exact
    // Last-Modified; otherwise it needs the whole thing again.
    match IfRange::parse(req) {
        Ok(IfRange::EntityTag(tag)) if !tag.strong_eq(&validators.etag) => {
            return RangeOutcome::Full;
        }
        Ok(IfRange::Date(date))
            if SystemTime::from(date) != SystemTime::from(validators.last_modified) =>
        {
            return RangeOutcome::Full;
        }
        _ => {}
    }
    match spec.to_satisfiable_range(len) {
        Some((first, last)) => RangeOutcome::Partial(first..last + 1),
        None => RangeOutcome::Unsatisfiable,
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
    let head_only = req.method() == Method::HEAD;

    // Cached entries are served exactly like our own symbols: negotiated,
    // ranged, conditional, HEAD-able.
    if let Some(response) = serve(req, &state.store, Source::Upstream { id }, None).await? {
        tracing::debug!(build_id = %id, "Serving upstream symbol from cache");
        return Ok(response);
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
            let mut response = HttpResponse::Ok();
            response.content_type("application/octet-stream");
            if head_only {
                // Nothing is known about the whole yet, and nothing of it is
                // wanted: the upstream stream is dropped here.
                return Ok(response.body(body::None::new()));
            }
            let prefix = futures::stream::once(async move {
                Ok::<Bytes, std::io::Error>(Bytes::from(buffer))
            });
            let first = futures::stream::once(async move { Ok(chunk) });
            let rest = body.map_err(|e| std::io::Error::other(format!("upstream stream: {e}")));
            let combined = prefix.chain(first.chain(rest));
            return Ok(response.streaming(combined));
        }
        buffer.extend_from_slice(&chunk);
    }

    let data = Bytes::from(buffer);
    let size = data.len() as u64;

    // Cached entries are compressed like our own symbols, so the cache costs a
    // fraction of the storage and re-serves without re-encoding.
    let cacheable = data.clone();
    match web::block(move || compression::compress(&cacheable)).await {
        Ok(Ok(compressed)) => {
            let stored_size = compressed.len();
            // Cache writes are best-effort: the caller still gets their symbols
            // during a storage outage.
            if let Err(e) = state.store.put_upstream(id, compressed, size).await {
                tracing::warn!(build_id = %id, error = %e, "Failed to cache upstream symbol");
            } else {
                tracing::info!(build_id = %id, size, stored_size, "Cached upstream symbol");
                // Now that it is stored, the cache path answers this request
                // too — same headers and semantics as every later one, at the
                // cost of reading back what was just written.
                if let Some(response) =
                    serve(req, &state.store, Source::Upstream { id }, Some(size)).await?
                {
                    return Ok(response);
                }
            }
        }
        Ok(Err(e)) => {
            tracing::warn!(build_id = %id, error = %e, "Failed to compress upstream symbol")
        }
        Err(e) => tracing::warn!(build_id = %id, error = %e, "Compression task failed"),
    }

    // Not cached (or not readable back yet): the bytes in hand, as they came.
    let mut response = HttpResponse::Ok();
    response
        .content_type("application/octet-stream")
        .insert_header((header::CACHE_CONTROL, CACHE_CONTROL))
        .insert_header(("x-debuginfod-size", size));
    Ok(if head_only {
        sized(&mut response, size, empty_body())
    } else {
        response.body(data)
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use actix_web::http::Method;
    use actix_web::{App, test, web};

    use crate::api::{AppState, Plane, configure_internal, configure_public};
    use crate::compression::{Compression, compress, decompress};
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

    /// A response: status, the raw (undecoded) body, and every header.
    struct Reply {
        status: u16,
        body: Vec<u8>,
        headers: actix_web::http::header::HeaderMap,
    }

    impl Reply {
        fn header(&self, name: &str) -> Option<String> {
            self.headers
                .get(name)
                .map(|v| v.to_str().unwrap().to_string())
        }
    }

    async fn send(state: &Arc<AppState>, plane: Plane, request: test::TestRequest) -> Reply {
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

        let response = test::call_service(&app, request.to_request()).await;
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let body = test::read_body(response).await.to_vec();
        Reply {
            status,
            body,
            headers,
        }
    }

    async fn get(state: &Arc<AppState>, plane: Plane, path: &str) -> (u16, Vec<u8>) {
        let reply = send(state, plane, test::TestRequest::get().uri(path)).await;
        (reply.status, reply.body)
    }

    /// Returns the status, the raw body (undecoded) and the response's
    /// `Content-Encoding` and `Vary` headers.
    async fn request(
        state: &Arc<AppState>,
        plane: Plane,
        path: &str,
        accept_encoding: Option<&str>,
    ) -> (u16, Vec<u8>, Option<String>, Option<String>) {
        let mut request = test::TestRequest::get().uri(path);
        if let Some(encoding) = accept_encoding {
            request = request.insert_header(("accept-encoding", encoding));
        }
        let reply = send(state, plane, request).await;
        let (encoding, vary) = (reply.header("content-encoding"), reply.header("vary"));
        (reply.status, reply.body, encoding, vary)
    }

    /// A debuginfod lookup with the given method, optionally accepting gzip.
    fn debuginfo(method: Method, id: &str, gzip: bool) -> test::TestRequest {
        let mut request = test::TestRequest::default()
            .method(method)
            .uri(&format!("/buildid/{id}/debuginfo"));
        if gzip {
            request = request.insert_header(("accept-encoding", "gzip"));
        }
        request
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

    #[actix_web::test]
    async fn head_carries_the_headers_a_get_would_and_no_body() {
        let state = seeded_state().await;
        for gzip in [false, true] {
            let get = send(&state, Plane::Public, debuginfo(Method::GET, "aabbccdd", gzip)).await;
            let head = send(&state, Plane::Public, debuginfo(Method::HEAD, "aabbccdd", gzip)).await;
            assert_eq!(head.status, 200, "gzip: {gzip}");
            assert!(head.body.is_empty(), "gzip: {gzip}");
            for name in [
                "content-length",
                "content-type",
                "content-encoding",
                "etag",
                "last-modified",
                "cache-control",
                "accept-ranges",
                "vary",
                "x-debuginfod-size",
            ] {
                assert_eq!(head.header(name), get.header(name), "{name} (gzip: {gzip})");
            }
            assert_eq!(
                get.header("content-length").unwrap().parse::<usize>().unwrap(),
                get.body.len(),
                "gzip: {gzip}"
            );
        }

        // Absent, hidden and unsupported look the same to HEAD as to GET.
        let hidden = send(&state, Plane::Public, debuginfo(Method::HEAD, "11223344", false)).await;
        assert_eq!(hidden.status, 404);
        let missing = send(&state, Plane::Internal, debuginfo(Method::HEAD, "deadbeef", false)).await;
        assert_eq!(missing.status, 404);
        let section = test::TestRequest::default()
            .method(Method::HEAD)
            .uri("/buildid/aabbccdd/executable");
        assert_eq!(send(&state, Plane::Internal, section).await.status, 404);
        let health = test::TestRequest::default().method(Method::HEAD).uri("/health");
        assert_eq!(send(&state, Plane::Public, health).await.status, 200);
    }

    #[actix_web::test]
    async fn responses_describe_the_symbol_file_and_its_representation() {
        let state = seeded_state().await;

        let identity = send(&state, Plane::Public, debuginfo(Method::GET, "aabbccdd", false)).await;
        assert_eq!(identity.status, 200);
        assert_eq!(identity.body, b"public symbols");
        // Inflated on the way out, but the length is known from the metadata.
        assert_eq!(identity.header("content-length").as_deref(), Some("14"));
        assert_eq!(identity.header("x-debuginfod-size").as_deref(), Some("14"));
        assert_eq!(
            identity.header("accept-ranges").as_deref(),
            Some("none"),
            "an inflated response can't be ranged"
        );
        assert_eq!(
            identity.header("cache-control").as_deref(),
            Some("public, max-age=31536000, immutable")
        );
        assert_eq!(identity.header("vary").as_deref(), Some("accept-encoding"));
        assert!(identity.header("etag").unwrap().starts_with('"'), "a strong validator");
        assert!(identity.header("last-modified").is_some());

        let gzip = send(&state, Plane::Public, debuginfo(Method::GET, "aabbccdd", true)).await;
        assert_eq!(gzip.status, 200);
        assert_eq!(
            gzip.header("x-debuginfod-size").as_deref(),
            Some("14"),
            "the protocol's size header is the file's, whatever the encoding"
        );
        assert_eq!(
            gzip.header("content-length").unwrap().parse::<usize>().unwrap(),
            gzip.body.len()
        );
        assert_eq!(gzip.header("accept-ranges").as_deref(), Some("bytes"));
        assert_ne!(
            gzip.header("etag"),
            identity.header("etag"),
            "distinct representations carry distinct validators"
        );

        // A plain object is one representation for everyone.
        let legacy = send(&state, Plane::Public, debuginfo(Method::GET, "99887766", false)).await;
        assert_eq!(legacy.header("content-length").as_deref(), Some("14"));
        assert_eq!(legacy.header("x-debuginfod-size").as_deref(), Some("14"));
        assert_eq!(legacy.header("accept-ranges").as_deref(), Some("bytes"));
    }

    #[actix_web::test]
    async fn byte_ranges_apply_to_the_bytes_sent_verbatim() {
        let state = seeded_state().await;
        let full = send(&state, Plane::Public, debuginfo(Method::GET, "aabbccdd", true)).await;
        let stored = full.body.clone();
        let len = stored.len();

        for (range, expected) in [
            ("bytes=0-3", &stored[0..4]),
            ("bytes=5-", &stored[5..]),
            ("bytes=-4", &stored[len - 4..]),
            // An end past the last byte is clipped, not refused.
            ("bytes=2-9999", &stored[2..]),
        ] {
            let request = debuginfo(Method::GET, "aabbccdd", true).insert_header(("range", range));
            let reply = send(&state, Plane::Public, request).await;
            assert_eq!(reply.status, 206, "{range}");
            assert_eq!(reply.body, expected, "{range}");
            assert_eq!(reply.header("content-encoding").as_deref(), Some("gzip"), "{range}");
            assert_eq!(
                reply.header("content-length").as_deref(),
                Some(expected.len().to_string().as_str()),
                "{range}"
            );
            assert_eq!(reply.header("accept-ranges").as_deref(), Some("bytes"), "{range}");
            assert_eq!(reply.header("etag"), full.header("etag"), "{range}");
        }
        let request = debuginfo(Method::GET, "aabbccdd", true).insert_header(("range", "bytes=0-3"));
        let reply = send(&state, Plane::Public, request).await;
        assert_eq!(
            reply.header("content-range").as_deref(),
            Some(format!("bytes 0-3/{len}").as_str())
        );

        // Objects stored plain are ranged for every client.
        let request = debuginfo(Method::GET, "99887766", false).insert_header(("range", "bytes=0-5"));
        let reply = send(&state, Plane::Public, request).await;
        assert_eq!(reply.status, 206);
        assert_eq!(reply.body, b"legacy");
        assert_eq!(reply.header("content-range").as_deref(), Some("bytes 0-5/14"));
        assert_eq!(reply.header("content-encoding"), None);
    }

    #[actix_web::test]
    async fn ranges_past_the_end_are_unsatisfiable() {
        let state = seeded_state().await;
        let len = send(&state, Plane::Public, debuginfo(Method::GET, "aabbccdd", true))
            .await
            .body
            .len();

        for range in ["bytes=9999-", "bytes=9999-10000", "bytes=-0"] {
            let request = debuginfo(Method::GET, "aabbccdd", true).insert_header(("range", range));
            let reply = send(&state, Plane::Public, request).await;
            assert_eq!(reply.status, 416, "{range}");
            assert!(reply.body.is_empty(), "{range}");
            assert_eq!(
                reply.header("content-range").as_deref(),
                Some(format!("bytes */{len}").as_str()),
                "{range}"
            );
        }
    }

    #[actix_web::test]
    async fn ranges_that_cannot_be_honoured_are_ignored() {
        let state = seeded_state().await;
        let full = send(&state, Plane::Public, debuginfo(Method::GET, "aabbccdd", true)).await;
        let etag = full.header("etag").unwrap();
        let last_modified = full.header("last-modified").unwrap();

        let cases: Vec<(bool, Vec<(&str, &str)>)> = vec![
            // An inflated response.
            (false, vec![("range", "bytes=0-3")]),
            // Several ranges.
            (true, vec![("range", "bytes=0-1,3-4")]),
            // Another unit, or nonsense.
            (true, vec![("range", "items=0-1")]),
            (true, vec![("range", "bytes=garbage")]),
            // If-Range naming some other version.
            (true, vec![("range", "bytes=0-3"), ("if-range", "\"stale\"")]),
            (
                true,
                vec![("range", "bytes=0-3"), ("if-range", "Sat, 01 Jan 2000 00:00:00 GMT")],
            ),
        ];
        for (gzip, headers) in cases {
            let mut request = debuginfo(Method::GET, "aabbccdd", gzip);
            for (name, value) in &headers {
                request = request.insert_header((*name, *value));
            }
            let reply = send(&state, Plane::Public, request).await;
            assert_eq!(reply.status, 200, "{headers:?}");
            assert!(reply.header("content-range").is_none(), "{headers:?}");
            let body = if gzip {
                decompress(&reply.body, 1 << 20).unwrap().to_vec()
            } else {
                reply.body
            };
            assert_eq!(body, b"public symbols", "{headers:?}");
        }

        // ...whereas an If-Range naming the current version is honoured,
        // by tag or by date.
        for value in [etag.as_str(), last_modified.as_str()] {
            let request = debuginfo(Method::GET, "aabbccdd", true)
                .insert_header(("range", "bytes=0-3"))
                .insert_header(("if-range", value));
            let reply = send(&state, Plane::Public, request).await;
            assert_eq!(reply.status, 206, "if-range: {value}");
        }

        // A HEAD describes the whole representation, range or no range.
        let request = debuginfo(Method::HEAD, "aabbccdd", true).insert_header(("range", "bytes=0-3"));
        let reply = send(&state, Plane::Public, request).await;
        assert_eq!(reply.status, 200);
        assert_eq!(reply.header("content-length"), full.header("content-length"));
    }

    #[actix_web::test]
    async fn conditional_requests_are_answered_with_304() {
        let state = seeded_state().await;
        for gzip in [false, true] {
            let full = send(&state, Plane::Public, debuginfo(Method::GET, "aabbccdd", gzip)).await;
            let etag = full.header("etag").unwrap();
            let last_modified = full.header("last-modified").unwrap();

            /// Sends a conditional GET and reports whether it came back 304;
            /// a 304 must carry the validators and caching headers of the 200.
            async fn not_modified(
                state: &Arc<AppState>,
                gzip: bool,
                full: &Reply,
                headers: Vec<(&'static str, String)>,
            ) -> bool {
                let mut request = debuginfo(Method::GET, "aabbccdd", gzip);
                for (name, value) in headers {
                    request = request.insert_header((name, value));
                }
                let reply = send(state, Plane::Public, request).await;
                if reply.status == 304 {
                    assert!(reply.body.is_empty());
                    assert_eq!(reply.header("etag"), full.header("etag"));
                    assert_eq!(reply.header("cache-control"), full.header("cache-control"));
                    assert_eq!(reply.header("vary"), full.header("vary"));
                } else {
                    assert_eq!(reply.status, 200);
                }
                reply.status == 304
            }

            // The tag itself, in a list, weakened, or `*`.
            for value in [
                etag.clone(),
                format!("\"other\", {etag}"),
                format!("W/{etag}"),
                "*".to_string(),
            ] {
                assert!(
                    not_modified(&state, gzip, &full, vec![("if-none-match", value.clone())]).await,
                    "{value}"
                );
            }
            let other = || ("if-none-match", "\"other\"".to_string());
            assert!(!not_modified(&state, gzip, &full, vec![other()]).await);

            // By date.
            let since = |value: &str| ("if-modified-since", value.to_string());
            assert!(not_modified(&state, gzip, &full, vec![since(&last_modified)]).await);
            assert!(
                !not_modified(&state, gzip, &full, vec![since("Sat, 01 Jan 2000 00:00:00 GMT")])
                    .await
            );
            // If-None-Match decides when both are present.
            assert!(!not_modified(&state, gzip, &full, vec![other(), since(&last_modified)]).await);

            // A HEAD is conditional in the same way.
            let request = debuginfo(Method::HEAD, "aabbccdd", gzip).insert_header(("if-none-match", etag));
            assert_eq!(send(&state, Plane::Public, request).await.status, 304);
        }

        // One representation's tag says nothing about the other.
        let identity = send(&state, Plane::Public, debuginfo(Method::GET, "aabbccdd", false)).await;
        let request = debuginfo(Method::GET, "aabbccdd", true)
            .insert_header(("if-none-match", identity.header("etag").unwrap()));
        assert_eq!(send(&state, Plane::Public, request).await.status, 200);
    }

    #[actix_web::test]
    async fn cached_upstream_symbols_are_served_the_same_way() {
        let state = seeded_state_with(|config| {
            // Nothing listens here: a cache hit must never consult upstream.
            config.federation.upstream = Some("http://127.0.0.1:1".to_string());
        })
        .await;
        let data = b"upstream symbols";
        state
            .store
            .put_upstream("cafebabe", compress(data).unwrap(), data.len() as u64)
            .await
            .unwrap();

        let identity = send(&state, Plane::Public, debuginfo(Method::GET, "cafebabe", false)).await;
        assert_eq!(identity.status, 200);
        assert_eq!(identity.body, data);
        assert_eq!(identity.header("content-length").as_deref(), Some("16"));
        assert_eq!(identity.header("x-debuginfod-size").as_deref(), Some("16"));
        assert_eq!(identity.header("accept-ranges").as_deref(), Some("none"));
        assert_eq!(
            identity.header("cache-control").as_deref(),
            Some("public, max-age=31536000, immutable")
        );

        let gzip = send(&state, Plane::Public, debuginfo(Method::GET, "cafebabe", true)).await;
        assert_eq!(gzip.status, 200);
        assert_eq!(gzip.header("content-encoding").as_deref(), Some("gzip"));
        assert_eq!(&decompress(&gzip.body, 1 << 20).unwrap()[..], data);

        let head = send(&state, Plane::Public, debuginfo(Method::HEAD, "cafebabe", true)).await;
        assert_eq!(head.status, 200);
        assert!(head.body.is_empty());
        assert_eq!(head.header("content-length"), gzip.header("content-length"));
        assert_eq!(head.header("etag"), gzip.header("etag"));

        let request = debuginfo(Method::GET, "cafebabe", true).insert_header(("range", "bytes=0-1"));
        let part = send(&state, Plane::Public, request).await;
        assert_eq!(part.status, 206);
        assert_eq!(part.body, &gzip.body[0..2]);
        assert_eq!(
            part.header("content-range").as_deref(),
            Some(format!("bytes 0-1/{}", gzip.body.len()).as_str())
        );

        let request = debuginfo(Method::GET, "cafebabe", true)
            .insert_header(("if-none-match", gzip.header("etag").unwrap()));
        assert_eq!(send(&state, Plane::Public, request).await.status, 304);

        // The cache is plane-independent, like the upstream it fronts.
        let internal = send(&state, Plane::Internal, debuginfo(Method::GET, "cafebabe", false)).await;
        assert_eq!(internal.status, 200);
    }
}
