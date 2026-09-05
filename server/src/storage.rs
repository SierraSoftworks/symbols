use std::ops::Range;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use futures::{StreamExt, TryStreamExt};
use object_store::{
    Attribute, Attributes, GetOptions, GetRange, ObjectStore, ObjectStoreExt, PutOptions,
    PutPayload, path::Path,
};
use serde::{Deserialize, Serialize};

use crate::compression::Compression;
use crate::config::StorageConfig;
use crate::errors::Error;
use crate::formats::{SymbolFormat, SymbolInfo};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Visibility {
    /// Served to anyone on the public plane (and internally).
    Public,
    /// Served only on the internal plane.
    Internal,
}

/// A project registers one GitHub repository's symbols. Projects live in
/// object storage (not in config) so they can be created automatically on
/// first upload and managed through the API without a config rollout.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    /// "org/repo", matching the GitHub `repository` OIDC claim.
    pub name: String,
    pub visibility: Visibility,
    /// Overrides the server-wide default when set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keep_versions: Option<usize>,
    pub created_at: DateTime<Utc>,
    /// Where the project came from: "auto" (trusted-org upload) or "api".
    pub created_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolMeta {
    pub id: String,
    pub format: SymbolFormat,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,
    /// Release/version tag supplied by the uploader; used to group symbols
    /// for retention. Untagged uploads share the "" pseudo-version.
    #[serde(default)]
    pub version: String,
    /// The symbol file's own size, before storage compression.
    pub size: u64,
    /// How the stored object is encoded. Objects written before the server
    /// compressed at rest carry no value here and read back as `none`.
    #[serde(default)]
    pub compression: Compression,
    /// Size of the object as stored; absent on those older objects, where it
    /// is the same as `size`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stored_size: Option<u64>,
    pub uploaded_at: DateTime<Utc>,
    /// The `ref` claim of the uploading workflow, for audit purposes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uploaded_from: Option<String>,
    /// Uploader-supplied OS tag ("linux", "macos", "windows"); when absent
    /// the UI infers it from the symbol format. All the fields below are
    /// additive with defaults, so meta.json written before they existed still
    /// deserialises.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    /// Commit SHA the symbols were built from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    /// Link to the CI run that produced the upload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_url: Option<String>,
}

/// The global build-id index entry: resolves an id to the project holding it
/// without listing every project on the read path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexEntry {
    pub project: String,
}

/// Where an upload session is in its lifecycle. `Pending` and `Processing`
/// both mean "the worker owns it now" — the split only matters for recovery,
/// where either state after a restart means the job must run again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UploadStatus {
    /// Chunks are still arriving.
    Uploading,
    /// Complete was requested; a worker will pick it up.
    Pending,
    /// A worker is streaming it to its final destination.
    Processing,
    /// Done — `result` carries what the upload endpoint would have returned.
    Complete,
    /// The worker gave up — `error` says why.
    Failed,
}

/// A chunked upload in progress. Sessions live in object storage (under
/// `_staging/`) rather than in server memory, so an in-flight upload survives
/// a restart and never depends on which replica a chunk lands on. The
/// retention sweep prunes sessions that were never completed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadSession {
    pub id: String,
    /// "org/repo" from the creating token's `repository` claim; every later
    /// request on the session must present a token for the same repository.
    pub project: String,
    /// The repository's visibility claim, seeding the project if the upload
    /// auto-creates it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository_visibility: Option<String>,
    /// The uploading workflow's ref, recorded on the stored symbols.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_ref: Option<String>,
    pub created_at: DateTime<Utc>,
    pub status: UploadStatus,
    /// Set when completion is requested: how many chunks make up the body.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunks: Option<u32>,
    /// On `Complete`: the response the upload endpoint would have returned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    /// On `Failed`: what went wrong.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// The metadata query from the create call, replayed at completion.
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_url: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct UpstreamStats {
    pub entries: usize,
    pub total_size: u64,
}

#[derive(Clone)]
pub struct Store {
    inner: Arc<dyn ObjectStore>,
}

fn project_path(name: &str) -> Path {
    Path::from(format!("projects/{name}/.project.json"))
}

/// Stored objects append the encoding's suffix to this base (`debuginfo.gz`
/// for gzip), so the lookup path learns how to serve an object from its key
/// rather than by reading its metadata.
fn symbol_data_base(project: &str, id: &str) -> String {
    format!("projects/{project}/{id}/debuginfo")
}

fn symbol_meta_path(project: &str, id: &str) -> Path {
    Path::from(format!("projects/{project}/{id}/meta.json"))
}

fn index_path(id: &str) -> Path {
    Path::from(format!("buildids/{id}"))
}

fn upstream_base(id: &str) -> String {
    format!("_upstream/{id}/debuginfo")
}

fn upload_session_path(id: &str) -> Path {
    Path::from(format!("_staging/{id}/.upload.json"))
}

fn upload_chunk_path(id: &str, index: u32) -> Path {
    Path::from(format!("_staging/{id}/chunks/{index:08}"))
}

fn encoded_path(base: &str, compression: Compression) -> Path {
    Path::from(format!("{base}{}", compression.suffix()))
}

/// A bounded-memory writer to one object: bytes go out as ~16MB multipart
/// parts as they arrive, so writing a gigabyte-scale object costs the server
/// a few buffers, never the object. Abandoning the writer without `finish`
/// leaves at most an incomplete multipart upload for the store to expire.
pub struct StreamingWriter {
    inner: object_store::WriteMultipart,
    written: u64,
}

/// Multipart part size. S3 requires ≥5MB for all but the last part; 16MB
/// keeps part counts low without meaningfully raising memory use.
const STREAM_PART_SIZE: usize = 16 * 1024 * 1024;

/// How many parts may be in flight at once per writer.
const STREAM_CONCURRENCY: usize = 4;

impl StreamingWriter {
    async fn open(store: &Arc<dyn ObjectStore>, path: Path) -> Result<Self, Error> {
        let upload = store.put_multipart(&path).await?;
        Ok(Self {
            inner: object_store::WriteMultipart::new_with_chunk_size(upload, STREAM_PART_SIZE),
            written: 0,
        })
    }

    pub async fn write(&mut self, data: bytes::Bytes) -> Result<(), Error> {
        self.inner
            .wait_for_capacity(STREAM_CONCURRENCY)
            .await
            .map_err(Error::Storage)?;
        self.written += data.len() as u64;
        self.inner.put(data);
        Ok(())
    }

    pub fn written(&self) -> u64 {
        self.written
    }

    /// Completes the object; nothing is visible at the path until this
    /// succeeds.
    pub async fn finish(self) -> Result<u64, Error> {
        self.inner
            .finish()
            .await
            .map_err(Error::Storage)?;
        Ok(self.written)
    }

    /// Abandons the write, cleaning up any parts already uploaded.
    pub async fn abort(self) -> Result<(), Error> {
        self.inner
            .abort()
            .await
            .map_err(Error::Storage)?;
        Ok(())
    }
}

/// What storage knows about an object without reading it: enough to answer
/// a HEAD, evaluate a conditional request, or validate a byte range before
/// any body is fetched.
#[derive(Debug, Clone)]
pub struct ObjectInfo {
    /// Size of the object on disk — the compressed size unless `compression`
    /// is `None`.
    pub stored_size: u64,
    pub compression: Compression,
    /// The symbol file's own (inflated) size, when the object records it —
    /// the upstream cache does so in object metadata; published symbols carry
    /// theirs in `meta.json` instead.
    pub size: Option<u64>,
    /// When the object was written.
    pub last_modified: DateTime<Utc>,
    /// The store's own validator for the stored bytes (S3's ETag), when it
    /// has one.
    pub e_tag: Option<String>,
}

/// An object as it sits in storage, ready to be streamed to a client either
/// verbatim or through a decoder.
pub struct StoredObject {
    pub info: ObjectInfo,
    /// Which bytes of the stored object `result` carries — the whole object
    /// unless a range was requested.
    pub range: Range<u64>,
    pub result: object_store::GetResult,
}

/// Object metadata key recording an upstream cache entry's inflated size.
const SIZE_ATTRIBUTE: &str = "symbol-size";

fn object_info(
    meta: &object_store::ObjectMeta,
    attributes: &Attributes,
    compression: Compression,
) -> ObjectInfo {
    let size = attributes
        .get(&Attribute::Metadata(SIZE_ATTRIBUTE.into()))
        .and_then(|v| v.as_ref().parse::<u64>().ok());
    ObjectInfo {
        stored_size: meta.size,
        compression,
        size,
        last_modified: meta.last_modified,
        e_tag: meta.e_tag.clone(),
    }
}

impl Store {
    pub fn new(cfg: &StorageConfig) -> Result<Self, Error> {
        let store = object_store::aws::AmazonS3Builder::new()
            .with_endpoint(&cfg.endpoint)
            .with_region(&cfg.region)
            .with_bucket_name(&cfg.bucket)
            .with_access_key_id(&cfg.access_key_id)
            .with_secret_access_key(&cfg.secret_access_key)
            .with_virtual_hosted_style_request(false)
            .with_allow_http(true)
            .build()?;
        Ok(Self {
            inner: Arc::new(store),
        })
    }

    #[cfg(test)]
    pub fn in_memory() -> Self {
        Self {
            inner: Arc::new(object_store::memory::InMemory::new()),
        }
    }

    async fn get_json<T: serde::de::DeserializeOwned>(&self, path: &Path) -> Result<Option<T>, Error> {
        match self.inner.get(path).await {
            Ok(result) => {
                let data = result.bytes().await?;
                serde_json::from_slice(&data)
                    .map(Some)
                    .map_err(|e| Error::Internal(format!("corrupt object at {path}: {e}")))
            }
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    async fn put_json<T: serde::Serialize>(&self, path: &Path, value: &T) -> Result<(), Error> {
        let data = serde_json::to_vec(value)
            .map_err(|e| Error::Internal(format!("serializing {path}: {e}")))?;
        self.inner.put(path, PutPayload::from(data)).await?;
        Ok(())
    }

    // --- Projects ---------------------------------------------------------

    pub async fn get_project(&self, name: &str) -> Result<Option<Project>, Error> {
        self.get_json(&project_path(name)).await
    }

    pub async fn put_project(&self, project: &Project) -> Result<(), Error> {
        self.put_json(&project_path(&project.name), project).await
    }

    pub async fn list_projects(&self) -> Result<Vec<Project>, Error> {
        // Two delimiter levels: projects/{org}/ then projects/{org}/{repo}/.
        let mut projects = Vec::new();
        let orgs = self
            .inner
            .list_with_delimiter(Some(&Path::from("projects")))
            .await?;
        for org in orgs.common_prefixes {
            let repos = self.inner.list_with_delimiter(Some(&org)).await?;
            for repo in repos.common_prefixes {
                let path = Path::from(format!("{repo}/.project.json"));
                if let Some(project) = self.get_json::<Project>(&path).await? {
                    projects.push(project);
                }
            }
        }
        projects.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(projects)
    }

    // --- Symbols ----------------------------------------------------------

    /// Writes a symbol in one call. The serving path writes through
    /// [`symbol_writer`](Self::symbol_writer) + [`put_symbol_meta`](Self::put_symbol_meta)
    /// instead; this stays for tests seeding fixtures.
    #[cfg(test)]
    pub async fn put_symbol(
        &self,
        project: &str,
        info: &SymbolInfo,
        meta: &SymbolMeta,
        data: bytes::Bytes,
    ) -> Result<(), Error> {
        self.inner
            .put(
                &encoded_path(&symbol_data_base(project, &info.id), meta.compression),
                PutPayload::from(data),
            )
            .await?;
        self.put_json(&symbol_meta_path(project, &info.id), meta).await?;
        self.put_json(
            &index_path(&info.id),
            &IndexEntry {
                project: project.to_string(),
            },
        )
        .await?;
        Ok(())
    }

    pub async fn get_index(&self, id: &str) -> Result<Option<IndexEntry>, Error> {
        self.get_json(&index_path(id)).await
    }

    /// Fetches an object by trying each encoding's key in turn. Compressed is
    /// tried first because everything written now is compressed; the plain key
    /// is the fallback for objects stored before that. With `range`, only
    /// those bytes of the stored object are read (an S3 range read) — the
    /// caller validates the range against the object's size first.
    async fn get_encoded(
        &self,
        base: &str,
        range: Option<Range<u64>>,
    ) -> Result<Option<StoredObject>, Error> {
        for compression in [Compression::Gzip, Compression::None] {
            let options = GetOptions::new().with_range(range.clone().map(GetRange::Bounded));
            match self.inner.get_opts(&encoded_path(base, compression), options).await {
                Ok(result) => {
                    let info = object_info(&result.meta, &result.attributes, compression);
                    return Ok(Some(StoredObject {
                        info,
                        range: result.range.clone(),
                        result,
                    }));
                }
                Err(object_store::Error::NotFound { .. }) => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(None)
    }

    /// Like [`get_encoded`](Self::get_encoded), but reads only the object's
    /// metadata — no body is transferred.
    async fn head_encoded(&self, base: &str) -> Result<Option<ObjectInfo>, Error> {
        for compression in [Compression::Gzip, Compression::None] {
            let options = GetOptions::new().with_head(true);
            match self.inner.get_opts(&encoded_path(base, compression), options).await {
                Ok(result) => {
                    return Ok(Some(object_info(&result.meta, &result.attributes, compression)));
                }
                Err(object_store::Error::NotFound { .. }) => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(None)
    }

    /// Returns the stored symbol, ready to stream, with the encoding it is
    /// stored in. `range` selects a slice of the stored bytes.
    pub async fn get_symbol(
        &self,
        project: &str,
        id: &str,
        range: Option<Range<u64>>,
    ) -> Result<Option<StoredObject>, Error> {
        self.get_encoded(&symbol_data_base(project, id), range).await
    }

    /// The stored symbol's metadata, without reading it.
    pub async fn head_symbol(&self, project: &str, id: &str) -> Result<Option<ObjectInfo>, Error> {
        self.head_encoded(&symbol_data_base(project, id)).await
    }

    pub async fn get_symbol_meta(&self, project: &str, id: &str) -> Result<Option<SymbolMeta>, Error> {
        self.get_json(&symbol_meta_path(project, id)).await
    }

    pub async fn list_symbols(&self, project: &str) -> Result<Vec<SymbolMeta>, Error> {
        let prefix = Path::from(format!("projects/{project}"));
        let listing = self.inner.list_with_delimiter(Some(&prefix)).await?;
        let mut symbols = Vec::new();
        for entry in listing.common_prefixes {
            let path = Path::from(format!("{entry}/meta.json"));
            if let Some(meta) = self.get_json::<SymbolMeta>(&path).await? {
                symbols.push(meta);
            }
        }
        symbols.sort_by_key(|s| std::cmp::Reverse(s.uploaded_at));
        Ok(symbols)
    }

    pub async fn delete_symbol(&self, project: &str, id: &str) -> Result<(), Error> {
        // The index entry goes first: a dangling index is a served 404, while a
        // dangling data object is only an orphan the next sweep can ignore.
        let data = symbol_data_base(project, id);
        for path in [
            index_path(id),
            symbol_meta_path(project, id),
            // Both encodings: which one is present depends on when it was
            // uploaded, and a stale sibling would resurrect a deleted symbol.
            encoded_path(&data, Compression::Gzip),
            encoded_path(&data, Compression::None),
        ] {
            match self.inner.delete(&path).await {
                Ok(()) | Err(object_store::Error::NotFound { .. }) => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }

    // --- Upstream federation cache ---------------------------------------

    pub async fn get_upstream(
        &self,
        id: &str,
        range: Option<Range<u64>>,
    ) -> Result<Option<StoredObject>, Error> {
        self.get_encoded(&upstream_base(id), range).await
    }

    pub async fn head_upstream(&self, id: &str) -> Result<Option<ObjectInfo>, Error> {
        self.head_encoded(&upstream_base(id)).await
    }

    /// Caches an upstream symbol. `data` is already gzip-encoded, matching how
    /// our own symbols are stored; `size` is the symbol file's own length,
    /// recorded on the object so the inflated response can carry a
    /// `Content-Length` without a metadata file of its own.
    pub async fn put_upstream(&self, id: &str, data: bytes::Bytes, size: u64) -> Result<(), Error> {
        let options = PutOptions {
            attributes: Attributes::from_iter([(
                Attribute::Metadata(SIZE_ATTRIBUTE.into()),
                size.to_string(),
            )]),
            ..Default::default()
        };
        self.inner
            .put_opts(
                &encoded_path(&upstream_base(id), Compression::Gzip),
                PutPayload::from(data),
                options,
            )
            .await?;
        Ok(())
    }

    /// Sums the upstream federation cache for the stats surfaces.
    pub async fn upstream_stats(&self) -> Result<UpstreamStats, Error> {
        let mut entries = self.inner.list(Some(&Path::from("_upstream")));
        let mut stats = UpstreamStats::default();
        while let Some(meta) = entries.try_next().await? {
            stats.entries += 1;
            stats.total_size += meta.size;
        }
        Ok(stats)
    }

    // --- Chunked upload staging -------------------------------------------

    pub async fn create_upload(&self, session: &UploadSession) -> Result<(), Error> {
        self.put_json(&upload_session_path(&session.id), session).await
    }

    pub async fn get_upload(&self, id: &str) -> Result<Option<UploadSession>, Error> {
        self.get_json(&upload_session_path(id)).await
    }

    #[cfg(test)]
    pub async fn put_upload_chunk(
        &self,
        id: &str,
        index: u32,
        data: bytes::Bytes,
    ) -> Result<(), Error> {
        self.inner
            .put(&upload_chunk_path(id, index), PutPayload::from(data))
            .await?;
        Ok(())
    }

    /// Opens a bounded-memory streaming writer for one staged chunk.
    pub async fn upload_chunk_writer(&self, id: &str, index: u32) -> Result<StreamingWriter, Error> {
        StreamingWriter::open(&self.inner, upload_chunk_path(id, index)).await
    }

    /// Opens a bounded-memory streaming writer for a symbol's final object
    /// (always the gzip-encoded key). The caller writes the data, then records
    /// metadata with [`put_symbol_meta`](Self::put_symbol_meta).
    pub async fn symbol_writer(&self, project: &str, id: &str) -> Result<StreamingWriter, Error> {
        let path = encoded_path(&symbol_data_base(project, id), Compression::Gzip);
        StreamingWriter::open(&self.inner, path).await
    }

    /// Records a symbol's metadata and build-id index entry; the data object
    /// itself was already written through [`symbol_writer`](Self::symbol_writer).
    pub async fn put_symbol_meta(
        &self,
        project: &str,
        info: &SymbolInfo,
        meta: &SymbolMeta,
    ) -> Result<(), Error> {
        self.put_json(&symbol_meta_path(project, &info.id), meta).await?;
        self.put_json(
            &index_path(&info.id),
            &IndexEntry {
                project: project.to_string(),
            },
        )
        .await?;
        Ok(())
    }

    #[cfg(test)]
    pub async fn get_upload_chunk(&self, id: &str, index: u32) -> Result<Option<bytes::Bytes>, Error> {
        match self.inner.get(&upload_chunk_path(id, index)).await {
            Ok(result) => Ok(Some(result.bytes().await?)),
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Size of one staged chunk, or None if it was never uploaded.
    pub async fn upload_chunk_size(&self, id: &str, index: u32) -> Result<Option<u64>, Error> {
        match self.inner.head(&upload_chunk_path(id, index)).await {
            Ok(meta) => Ok(Some(meta.size)),
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Streams the staged chunks of a session back in order as one contiguous
    /// byte stream — the reassembled upload body, without ever holding it.
    pub fn upload_body_stream(
        &self,
        id: &str,
        chunks: u32,
    ) -> futures::stream::BoxStream<'static, Result<bytes::Bytes, std::io::Error>> {
        let inner = self.inner.clone();
        let id = id.to_string();
        futures::stream::iter(0..chunks)
            .then(move |index| {
                let inner = inner.clone();
                let path = upload_chunk_path(&id, index);
                async move {
                    let result = inner
                        .get(&path)
                        .await
                        .map_err(|e| std::io::Error::other(format!("reading {path}: {e}")))?;
                    Ok::<_, std::io::Error>(
                        result
                            .into_stream()
                            .map_err(|e| std::io::Error::other(format!("chunk stream: {e}"))),
                    )
                }
            })
            .try_flatten()
            .boxed()
    }

    /// Every upload session currently staged, for recovery and the sweep.
    pub async fn list_upload_sessions(&self) -> Result<Vec<UploadSession>, Error> {
        let mut sessions = Vec::new();
        let listing = self
            .inner
            .list_with_delimiter(Some(&Path::from("_staging")))
            .await?;
        for prefix in listing.common_prefixes {
            let path = Path::from(format!("{prefix}/.upload.json"));
            if let Some(session) = self.get_json::<UploadSession>(&path).await? {
                sessions.push(session);
            }
        }
        Ok(sessions)
    }

    /// Removes a session's staged chunks, leaving the session document (with
    /// its result) behind for status polling until the sweep clears it.
    pub async fn delete_upload_chunks(&self, id: &str) -> Result<(), Error> {
        let prefix = Path::from(format!("_staging/{id}/chunks"));
        let mut entries = self.inner.list(Some(&prefix));
        let mut paths = Vec::new();
        while let Some(meta) = entries.try_next().await? {
            paths.push(meta.location);
        }
        for path in paths {
            match self.inner.delete(&path).await {
                Ok(()) | Err(object_store::Error::NotFound { .. }) => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }

    /// Removes a session and everything staged under it.
    pub async fn delete_upload(&self, id: &str) -> Result<(), Error> {
        let prefix = Path::from(format!("_staging/{id}"));
        let mut entries = self.inner.list(Some(&prefix));
        let mut paths = Vec::new();
        while let Some(meta) = entries.try_next().await? {
            paths.push(meta.location);
        }
        for path in paths {
            match self.inner.delete(&path).await {
                Ok(()) | Err(object_store::Error::NotFound { .. }) => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }

    /// Drops upload sessions older than the cutoff — whole sessions at a
    /// time, judged by the session's own creation time, so a slowly-arriving
    /// chunk can never outlive its session document as an orphan. Objects
    /// under `_staging/` with no session document at all (interrupted
    /// deletes) go by their own age. Returns the number of sessions removed.
    pub async fn prune_staging(&self, cutoff: DateTime<Utc>) -> Result<usize, Error> {
        let mut dropped = 0;
        let mut live = std::collections::HashSet::new();
        for session in self.list_upload_sessions().await? {
            if session.created_at < cutoff {
                self.delete_upload(&session.id).await?;
                dropped += 1;
            } else {
                live.insert(session.id);
            }
        }

        // Orphaned objects: anything staged that no live session accounts for.
        let mut entries = self.inner.list(Some(&Path::from("_staging")));
        let mut stale = Vec::new();
        while let Some(meta) = entries.try_next().await? {
            let session_id = meta.location.as_ref().split('/').nth(1).unwrap_or("");
            if !live.contains(session_id) && meta.last_modified < cutoff {
                stale.push(meta.location);
            }
        }
        for location in stale {
            match self.inner.delete(&location).await {
                Ok(()) | Err(object_store::Error::NotFound { .. }) => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(dropped)
    }

    /// Drops upstream cache entries older than the cutoff; returns the number dropped.
    pub async fn prune_upstream(&self, cutoff: DateTime<Utc>) -> Result<usize, Error> {
        let mut dropped = 0;
        let mut entries = self.inner.list(Some(&Path::from("_upstream")));
        let mut stale = Vec::new();
        while let Some(meta) = entries.try_next().await? {
            if meta.last_modified < cutoff {
                stale.push(meta.location);
            }
        }
        for location in stale {
            match self.inner.delete(&location).await {
                Ok(()) => dropped += 1,
                Err(object_store::Error::NotFound { .. }) => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(dropped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::SymbolFormat;

    fn info(id: &str) -> SymbolInfo {
        SymbolInfo {
            id: id.to_string(),
            format: SymbolFormat::Elf,
            arch: Some("aarch64".to_string()),
        }
    }

    fn meta(id: &str, version: &str) -> SymbolMeta {
        SymbolMeta {
            id: id.to_string(),
            format: SymbolFormat::Elf,
            arch: Some("aarch64".to_string()),
            version: version.to_string(),
            size: 4,
            compression: Compression::Gzip,
            stored_size: Some(4),
            uploaded_at: Utc::now(),
            uploaded_from: Some("refs/tags/v1.0.0".to_string()),
            os: Some("linux".to_string()),
            commit: None,
            build_url: None,
        }
    }

    #[tokio::test]
    async fn symbol_roundtrip_and_index() {
        let store = Store::in_memory();
        let project = "SierraSoftworks/grey";

        store
            .put_symbol(
                project,
                &info("abcd1234"),
                &meta("abcd1234", "v1.0.0"),
                bytes::Bytes::from_static(b"data"),
            )
            .await
            .unwrap();

        let index = store.get_index("abcd1234").await.unwrap().unwrap();
        assert_eq!(index.project, project);

        let stored = store.get_symbol(project, "abcd1234", None).await.unwrap().unwrap();
        assert_eq!(stored.info.stored_size, 4);
        assert_eq!(stored.info.compression, Compression::Gzip);
        assert_eq!(stored.range, 0..4);
        assert_eq!(&stored.result.bytes().await.unwrap()[..], b"data");

        // Metadata alone, and a slice of the stored bytes.
        let info = store.head_symbol(project, "abcd1234").await.unwrap().unwrap();
        assert_eq!(info.stored_size, 4);
        assert_eq!(info.compression, Compression::Gzip);
        assert!(info.e_tag.is_some(), "the store should hand back its validator");
        let meta = store.get_symbol_meta(project, "abcd1234").await.unwrap().unwrap();
        assert_eq!(meta.version, "v1.0.0");
        let part = store.get_symbol(project, "abcd1234", Some(1..3)).await.unwrap().unwrap();
        assert_eq!(part.range, 1..3);
        assert_eq!(part.info.stored_size, 4, "the info describes the whole object");
        assert_eq!(&part.result.bytes().await.unwrap()[..], b"at");

        let symbols = store.list_symbols(project).await.unwrap();
        assert_eq!(symbols.len(), 1);
        assert_eq!(symbols[0].version, "v1.0.0");

        store.delete_symbol(project, "abcd1234").await.unwrap();
        assert!(store.get_index("abcd1234").await.unwrap().is_none());
        assert!(store.get_symbol(project, "abcd1234", None).await.unwrap().is_none());
        assert!(store.head_symbol(project, "abcd1234").await.unwrap().is_none());
        assert!(store.get_symbol_meta(project, "abcd1234").await.unwrap().is_none());
    }

    /// Symbols written before the server compressed at rest sit at the
    /// unsuffixed key with no `compression` in their metadata; they must keep
    /// resolving, and deleting one must clear it.
    #[tokio::test]
    async fn legacy_uncompressed_objects_still_resolve() {
        let store = Store::in_memory();
        let project = "SierraSoftworks/grey";

        let mut legacy = meta("deadbeef", "v0.9.0");
        legacy.compression = Compression::None;
        legacy.stored_size = None;
        store
            .put_symbol(project, &info("deadbeef"), &legacy, bytes::Bytes::from_static(b"data"))
            .await
            .unwrap();

        let stored = store.get_symbol(project, "deadbeef", None).await.unwrap().unwrap();
        assert_eq!(stored.info.compression, Compression::None);
        assert_eq!(&stored.result.bytes().await.unwrap()[..], b"data");

        store.delete_symbol(project, "deadbeef").await.unwrap();
        assert!(store.get_symbol(project, "deadbeef", None).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn upload_staging_roundtrip_and_prune() {
        let store = Store::in_memory();
        let session = UploadSession {
            id: "aa".repeat(16),
            project: "SierraSoftworks/analytics".to_string(),
            repository_visibility: Some("public".to_string()),
            git_ref: Some("refs/tags/v0.2.1".to_string()),
            created_at: Utc::now(),
            status: UploadStatus::Uploading,
            chunks: None,
            result: None,
            error: None,
            version: "v0.2.1".to_string(),
            os: Some("linux".to_string()),
            arch: None,
            commit: None,
            build_url: None,
        };

        store.create_upload(&session).await.unwrap();
        let loaded = store.get_upload(&session.id).await.unwrap().unwrap();
        assert_eq!(loaded.project, session.project);
        assert_eq!(loaded.version, "v0.2.1");

        store
            .put_upload_chunk(&session.id, 0, bytes::Bytes::from_static(b"first-"))
            .await
            .unwrap();
        store
            .put_upload_chunk(&session.id, 1, bytes::Bytes::from_static(b"second"))
            .await
            .unwrap();
        assert_eq!(
            store.get_upload_chunk(&session.id, 0).await.unwrap().unwrap(),
            &b"first-"[..]
        );
        assert!(store.get_upload_chunk(&session.id, 2).await.unwrap().is_none());

        // delete_upload clears the session and every staged chunk.
        store.delete_upload(&session.id).await.unwrap();
        assert!(store.get_upload(&session.id).await.unwrap().is_none());
        assert!(store.get_upload_chunk(&session.id, 0).await.unwrap().is_none());

        // prune_staging drops whole sessions older than the cutoff — the
        // session document and every chunk staged under it.
        store.create_upload(&session).await.unwrap();
        store
            .put_upload_chunk(&session.id, 0, bytes::Bytes::from_static(b"stale"))
            .await
            .unwrap();
        let dropped = store
            .prune_staging(Utc::now() + chrono::Duration::hours(1))
            .await
            .unwrap();
        assert_eq!(dropped, 1, "one session, chunks and all");
        assert!(store.get_upload(&session.id).await.unwrap().is_none());
        assert!(store.get_upload_chunk(&session.id, 0).await.unwrap().is_none());

        // A young session is untouched even when the sweep runs.
        store.create_upload(&session).await.unwrap();
        store
            .put_upload_chunk(&session.id, 0, bytes::Bytes::from_static(b"fresh"))
            .await
            .unwrap();
        let dropped = store
            .prune_staging(Utc::now() - chrono::Duration::hours(1))
            .await
            .unwrap();
        assert_eq!(dropped, 0);
        assert!(store.get_upload(&session.id).await.unwrap().is_some());
        assert!(store.get_upload_chunk(&session.id, 0).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn upstream_cache_roundtrip() {
        let store = Store::in_memory();
        store
            .put_upstream("cafebabe", bytes::Bytes::from_static(b"gzipped"), 1234)
            .await
            .unwrap();

        let stored = store.get_upstream("cafebabe", None).await.unwrap().unwrap();
        assert_eq!(stored.info.compression, Compression::Gzip);
        assert_eq!(stored.info.size, Some(1234), "the inflated size rides on the object");
        assert_eq!(&stored.result.bytes().await.unwrap()[..], b"gzipped");

        let info = store.head_upstream("cafebabe").await.unwrap().unwrap();
        assert_eq!(info.size, Some(1234));
        assert_eq!(info.stored_size, 7);
    }

    #[tokio::test]
    async fn project_roundtrip_and_listing() {
        let store = Store::in_memory();
        for name in ["SierraSoftworks/grey", "SierraSoftworks/bender", "OtherOrg/thing"] {
            store
                .put_project(&Project {
                    name: name.to_string(),
                    visibility: Visibility::Public,
                    keep_versions: None,
                    created_at: Utc::now(),
                    created_by: "test".to_string(),
                })
                .await
                .unwrap();
        }

        assert!(store.get_project("SierraSoftworks/grey").await.unwrap().is_some());
        assert!(store.get_project("SierraSoftworks/unknown").await.unwrap().is_none());

        let projects = store.list_projects().await.unwrap();
        let names: Vec<_> = projects.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["OtherOrg/thing", "SierraSoftworks/bender", "SierraSoftworks/grey"]
        );
    }
}
