use std::sync::Arc;

use chrono::{DateTime, Utc};
use futures::TryStreamExt;
use object_store::{ObjectStore, PutPayload, path::Path};
use serde::{Deserialize, Serialize};

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
    pub size: u64,
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

fn symbol_data_path(project: &str, id: &str) -> Path {
    Path::from(format!("projects/{project}/{id}/debuginfo"))
}

fn symbol_meta_path(project: &str, id: &str) -> Path {
    Path::from(format!("projects/{project}/{id}/meta.json"))
}

fn index_path(id: &str) -> Path {
    Path::from(format!("buildids/{id}"))
}

fn upstream_path(id: &str) -> Path {
    Path::from(format!("_upstream/{id}/debuginfo"))
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

    pub async fn put_symbol(
        &self,
        project: &str,
        info: &SymbolInfo,
        meta: &SymbolMeta,
        data: bytes::Bytes,
    ) -> Result<(), Error> {
        self.inner
            .put(&symbol_data_path(project, &info.id), PutPayload::from(data))
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

    /// Returns the stored symbol as a byte stream plus its size.
    pub async fn get_symbol(
        &self,
        project: &str,
        id: &str,
    ) -> Result<Option<(u64, object_store::GetResult)>, Error> {
        match self.inner.get(&symbol_data_path(project, id)).await {
            Ok(result) => {
                let size = result.meta.size as u64;
                Ok(Some((size, result)))
            }
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(e) => Err(e.into()),
        }
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
        for path in [
            index_path(id),
            symbol_meta_path(project, id),
            symbol_data_path(project, id),
        ] {
            match self.inner.delete(&path).await {
                Ok(()) | Err(object_store::Error::NotFound { .. }) => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }

    // --- Upstream federation cache ---------------------------------------

    pub async fn get_upstream(&self, id: &str) -> Result<Option<(u64, object_store::GetResult)>, Error> {
        match self.inner.get(&upstream_path(id)).await {
            Ok(result) => {
                let size = result.meta.size as u64;
                Ok(Some((size, result)))
            }
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub async fn put_upstream(&self, id: &str, data: bytes::Bytes) -> Result<(), Error> {
        self.inner
            .put(&upstream_path(id), PutPayload::from(data))
            .await?;
        Ok(())
    }

    /// Sums the upstream federation cache for the stats surfaces.
    pub async fn upstream_stats(&self) -> Result<UpstreamStats, Error> {
        let mut entries = self.inner.list(Some(&Path::from("_upstream")));
        let mut stats = UpstreamStats::default();
        while let Some(meta) = entries.try_next().await? {
            stats.entries += 1;
            stats.total_size += meta.size as u64;
        }
        Ok(stats)
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
            .put_symbol(project, &info("abcd1234"), &meta("abcd1234", "v1.0.0"), bytes::Bytes::from_static(b"data"))
            .await
            .unwrap();

        let index = store.get_index("abcd1234").await.unwrap().unwrap();
        assert_eq!(index.project, project);

        let (size, result) = store.get_symbol(project, "abcd1234").await.unwrap().unwrap();
        assert_eq!(size, 4);
        assert_eq!(&result.bytes().await.unwrap()[..], b"data");

        let symbols = store.list_symbols(project).await.unwrap();
        assert_eq!(symbols.len(), 1);
        assert_eq!(symbols[0].version, "v1.0.0");

        store.delete_symbol(project, "abcd1234").await.unwrap();
        assert!(store.get_index("abcd1234").await.unwrap().is_none());
        assert!(store.get_symbol(project, "abcd1234").await.unwrap().is_none());
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
