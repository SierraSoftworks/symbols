//! View models handed to the UI by the server. These are deliberately
//! independent of the server's storage types: the server maps its domain
//! structs into these at render time, so the UI never grows a dependency on
//! storage internals (mirroring how grey keeps its `grey-api` types separate).

use chrono::{DateTime, Utc};

/// The signed-in management user, shown in the header and used for nothing
/// else client-side (authorization happens server-side).
#[derive(Debug, Clone, PartialEq)]
pub struct SessionUser {
    pub subject: String,
    pub name: Option<String>,
    pub email: Option<String>,
}

impl SessionUser {
    /// The friendliest identifier we have for the header chip.
    pub fn display_name(&self) -> &str {
        self.name
            .as_deref()
            .or(self.email.as_deref())
            .unwrap_or(&self.subject)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visibility {
    Public,
    Internal,
}

impl Visibility {
    pub fn label(&self) -> &'static str {
        match self {
            Visibility::Public => "public",
            Visibility::Internal => "internal",
        }
    }
}

/// Server-wide numbers for the dashboard's stat tiles.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct StatsSummary {
    pub project_count: usize,
    pub symbol_count: usize,
    pub total_size: u64,
    pub upstream_entries: usize,
    pub upstream_size: u64,
    pub last_upload: Option<DateTime<Utc>>,
}

/// One row of the dashboard's project table.
#[derive(Debug, Clone, PartialEq)]
pub struct ProjectRow {
    pub name: String,
    pub visibility: Visibility,
    pub version_count: usize,
    pub symbol_count: usize,
    pub total_size: u64,
    pub last_upload: Option<DateTime<Utc>>,
}

/// The operating system a symbol targets, shown as an icon. Derived from the
/// uploader-supplied `os` tag when present, falling back to what the symbol
/// format implies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    Linux,
    MacOs,
    Windows,
    Other,
}

impl Os {
    pub fn infer(os: Option<&str>, format: &str) -> Self {
        match os.map(|o| o.to_ascii_lowercase()).as_deref() {
            Some("linux") => Os::Linux,
            Some("macos") | Some("darwin") | Some("osx") => Os::MacOs,
            Some("windows") => Os::Windows,
            Some(_) => Os::Other,
            None => match format {
                "elf" => Os::Linux,
                "macho" => Os::MacOs,
                "pdb" => Os::Windows,
                _ => Os::Other,
            },
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Os::Linux => "Linux",
            Os::MacOs => "macOS",
            Os::Windows => "Windows",
            Os::Other => "Other",
        }
    }
}

/// Normalises the mixture of toolchain ("x86_64", "aarch64") and runner
/// ("X64", "ARM64") architecture labels into the conventional short names
/// shown on target chips.
pub fn arch_label(arch: &str) -> String {
    match arch.to_ascii_lowercase().as_str() {
        "x86_64" | "amd64" | "x64" => "amd64".to_string(),
        "aarch64" | "arm64" => "arm64".to_string(),
        "i386" | "i686" | "x86" => "i386".to_string(),
        other => other.to_string(),
    }
}

/// One stored symbol within a release: a single (OS, architecture) target.
#[derive(Debug, Clone, PartialEq)]
pub struct TargetRow {
    pub build_id: String,
    pub os: Os,
    pub arch: Option<String>,
    pub format: String,
    pub size: u64,
    pub uploaded_at: DateTime<Utc>,
    /// Commit SHA the symbols were built from, when the uploader supplied it.
    pub commit: Option<String>,
    /// Link to the CI run that produced the upload.
    pub build_url: Option<String>,
    /// The git ref the uploading workflow ran for (e.g. "refs/tags/v1.2.3").
    pub uploaded_from: Option<String>,
}

/// A release version grouping every target uploaded under one version tag.
#[derive(Debug, Clone, PartialEq)]
pub struct ReleaseRow {
    /// Empty string is the untagged pseudo-version.
    pub version: String,
    pub updated_at: DateTime<Utc>,
    pub total_size: u64,
    pub targets: Vec<TargetRow>,
}

impl ReleaseRow {
    pub fn display_version(&self) -> &str {
        if self.version.is_empty() {
            "untagged"
        } else {
            &self.version
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProjectDetail {
    /// "org/repo".
    pub name: String,
    pub visibility: Visibility,
    pub keep_versions: Option<usize>,
    /// The server-wide retention default, shown when no override is set.
    pub default_keep_versions: usize,
    pub created_at: DateTime<Utc>,
    pub total_size: u64,
    pub releases: Vec<ReleaseRow>,
}

/// Everything the setup page needs to render copy-pasteable snippets.
#[derive(Debug, Clone, PartialEq)]
pub struct SetupInfo {
    /// The public plane's base URL (public projects + upstream federation).
    pub public_url: String,
    /// The management/internal plane's base URL (serves everything).
    pub internal_url: String,
    /// The OIDC audience the upload endpoint expects from GitHub Actions.
    pub github_audience: String,
}

/// A one-shot notice rendered after a form action completes (carried across
/// the POST→redirect→GET hop as a query parameter).
#[derive(Debug, Clone, PartialEq)]
pub struct Flash {
    pub message: String,
    pub error: bool,
}
