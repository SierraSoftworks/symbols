use std::sync::Arc;

use chrono::{DateTime, Utc};
use futures::TryStreamExt;
use object_store::{ObjectStore, ObjectStoreExt, PutPayload, path::Path};
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
    pub created_at: DateTime<Utc>,
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

/// An object as it sits in storage, ready to be streamed to a client either
/// verbatim or through a decoder.
pub struct StoredObject {
    /// Size of the object on disk — the compressed size unless `compression`
    /// is `None`.
    pub stored_size: u64,
    pub compression: Compression,
    pub result: object_store::GetResult,
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

    /// Writes a symbol. `data` is already encoded as `meta.compression` says —
    /// the upload path stores the bytes it received rather than transcoding
    /// them.
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
    /// is the fallback for objects stored before that.
    async fn get_encoded(&self, base: &str) -> Result<Option<StoredObject>, Error> {
        for compression in [Compression::Gzip, Compression::None] {
            match self.inner.get(&encoded_path(base, compression)).await {
                Ok(result) => {
                    return Ok(Some(StoredObject {
                        stored_size: result.meta.size,
                        compression,
                        result,
                    }));
                }
                Err(object_store::Error::NotFound { .. }) => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(None)
    }

    /// Returns the stored symbol, ready to stream, with the encoding it is
    /// stored in.
    pub async fn get_symbol(&self, project: &str, id: &str) -> Result<Option<StoredObject>, Error> {
        self.get_encoded(&symbol_data_base(project, id)).await
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

    pub async fn get_upstream(&self, id: &str) -> Result<Option<StoredObject>, Error> {
        self.get_encoded(&upstream_base(id)).await
    }

    /// Caches an upstream symbol. `data` is already gzip-encoded, matching how
    /// our own symbols are stored.
    pub async fn put_upstream(&self, id: &str, data: bytes::Bytes) -> Result<(), Error> {
        self.inner
            .put(
                &encoded_path(&upstream_base(id), Compression::Gzip),
                PutPayload::from(data),
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

    pub async fn get_upload_chunk(&self, id: &str, index: u32) -> Result<Option<bytes::Bytes>, Error> {
        match self.inner.get(&upload_chunk_path(id, index)).await {
            Ok(result) => Ok(Some(result.bytes().await?)),
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(e) => Err(e.into()),
        }
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

    /// Drops staged upload data older than the cutoff — sessions whose
    /// uploader died before completing. Returns the number of objects removed.
    pub async fn prune_staging(&self, cutoff: DateTime<Utc>) -> Result<usize, Error> {
        let mut dropped = 0;
        let mut entries = self.inner.list(Some(&Path::from("_staging")));
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

        let stored = store.get_symbol(project, "abcd1234").await.unwrap().unwrap();
        assert_eq!(stored.stored_size, 4);
        assert_eq!(stored.compression, Compression::Gzip);
        assert_eq!(&stored.result.bytes().await.unwrap()[..], b"data");

        let symbols = store.list_symbols(project).await.unwrap();
        assert_eq!(symbols.len(), 1);
        assert_eq!(symbols[0].version, "v1.0.0");

        store.delete_symbol(project, "abcd1234").await.unwrap();
        assert!(store.get_index("abcd1234").await.unwrap().is_none());
        assert!(store.get_symbol(project, "abcd1234").await.unwrap().is_none());
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

        let stored = store.get_symbol(project, "deadbeef").await.unwrap().unwrap();
        assert_eq!(stored.compression, Compression::None);
        assert_eq!(&stored.result.bytes().await.unwrap()[..], b"data");

        store.delete_symbol(project, "deadbeef").await.unwrap();
        assert!(store.get_symbol(project, "deadbeef").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn upload_staging_roundtrip_and_prune() {
        let store = Store::in_memory();
        let session = UploadSession {
            id: "aa".repeat(16),
            project: "SierraSoftworks/analytics".to_string(),
            created_at: Utc::now(),
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

        // prune_staging drops whatever is older than the cutoff.
        store.create_upload(&session).await.unwrap();
        store
            .put_upload_chunk(&session.id, 0, bytes::Bytes::from_static(b"stale"))
            .await
            .unwrap();
        let dropped = store
            .prune_staging(Utc::now() + chrono::Duration::hours(1))
            .await
            .unwrap();
        assert_eq!(dropped, 2, "the session doc and its chunk");
        assert!(store.get_upload(&session.id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn upstream_cache_roundtrip() {
        let store = Store::in_memory();
        store
            .put_upstream("cafebabe", bytes::Bytes::from_static(b"gzipped"))
            .await
            .unwrap();

        let stored = store.get_upstream("cafebabe").await.unwrap().unwrap();
        assert_eq!(stored.compression, Compression::Gzip);
        assert_eq!(&stored.result.bytes().await.unwrap()[..], b"gzipped");
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
