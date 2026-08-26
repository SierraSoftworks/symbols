use serde::Deserialize;

/// Bootstrap configuration. Deliberately small: everything that can change at
/// runtime (most importantly the project registry) lives in object storage and
/// is managed through the API, so rolling out config is only needed for
/// infrastructure-level changes.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub storage: StorageConfig,
    pub github: GithubConfig,
    pub management: ManagementConfig,
    #[serde(default)]
    pub federation: FederationConfig,
    #[serde(default)]
    pub retention: RetentionConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// The public plane: debuginfod reads of public projects and symbol
    /// uploads. Fronted by the edge load balancer as
    /// https://symbols.sierrasoftworks.com.
    pub public_addr: String,
    /// The internal plane: everything the public plane serves plus
    /// unrestricted debuginfod reads, the management API, and the management
    /// UI. Only ever bound to an address reachable from inside the
    /// tailnet/cluster (Pyroscope's symbolizer and developer tooling).
    pub internal_addr: String,
    /// The public plane's externally reachable base URL, shown in the setup
    /// page's snippets. Defaults to "https://{github.audience}".
    #[serde(default)]
    pub public_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StorageConfig {
    /// S3 endpoint, e.g. "http://100.x.y.z:13900" or "https://s3.raptor-perch.ts.net".
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    pub access_key_id: String,
    pub secret_access_key: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GithubConfig {
    /// GitHub organizations whose repositories may publish symbols. An upload
    /// from a repo in a trusted org automatically creates the corresponding
    /// project (named "org/repo") on first use.
    pub trusted_orgs: Vec<String>,
    /// The audience expected in GitHub Actions OIDC tokens.
    pub audience: String,
    /// Restrict uploads to refs with one of these prefixes (e.g.
    /// ["refs/tags/"]). Empty means any ref.
    #[serde(default)]
    pub ref_prefixes: Vec<String>,
    /// The GitHub Actions OIDC issuer; overridable for tests.
    #[serde(default = "default_github_issuer")]
    pub issuer: String,
}

fn default_github_issuer() -> String {
    "https://token.actions.githubusercontent.com".to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct ManagementConfig {
    /// The OIDC client this server authenticates management access against —
    /// both browser sign-in and bearer tokens presented to the API.
    pub oidc: OidcConfig,
    /// A `filt-rs` expression deciding who may use the management plane. It is
    /// evaluated against the validated token claims (addressed under the
    /// `claims.` prefix) plus the request's `method` and `path`, e.g.
    /// `claims.email endswith "@example.com"` or
    /// `claims.groups contains "symbols-admins" || method == "GET"`.
    ///
    /// Defaults to admitting any identity the issuer vouches for, which is
    /// the right posture when the issuer itself gates membership (tsidp only
    /// mints tokens for tailnet members) and the management plane is bound to
    /// an internal address anyway.
    #[serde(default = "default_management_acl")]
    pub acl: filt_rs::Filter,
    /// Secret used to sign browser session cookies. Randomised at startup
    /// when unset, which signs everyone out on every deploy — set it to keep
    /// sessions across restarts.
    #[serde(default)]
    pub session_secret: Option<String>,
    /// How long a browser session lasts before the user must sign in again.
    #[serde(with = "humantime_serde", default = "default_session_duration")]
    pub session_duration: std::time::Duration,
}

const fn default_session_duration() -> std::time::Duration {
    std::time::Duration::from_secs(8 * 3600)
}

/// Admits every authenticated identity; see [`ManagementConfig::acl`].
fn default_management_acl() -> filt_rs::Filter {
    filt_rs::Filter::new("true").expect("the allow-all management ACL must parse")
}

#[derive(Debug, Clone, Deserialize)]
pub struct OidcConfig {
    /// OIDC issuer whose tokens grant access to the management plane (tsidp),
    /// and which users sign in against.
    pub issuer: String,
    /// OAuth client registered with the issuer. Because every management
    /// token — a browser id-token or an API access token — is minted for this
    /// client, the client id is also the audience tokens must carry. The
    /// redirect URI to register is "{management UI base URL}/auth/callback".
    pub client_id: String,
    /// Client secret; the code exchange happens server-side so this never
    /// reaches a browser.
    pub client_secret: String,
    /// Scopes requested at sign-in.
    #[serde(default = "default_oidc_scopes")]
    pub scopes: Vec<String>,
}

fn default_oidc_scopes() -> Vec<String> {
    vec!["openid".to_string(), "profile".to_string(), "email".to_string()]
}

#[derive(Debug, Clone, Deserialize)]
pub struct FederationConfig {
    /// Upstream debuginfod server consulted for build IDs we don't hold
    /// (distro packages such as glibc). Set to null/empty to disable.
    #[serde(default = "default_upstream")]
    pub upstream: Option<String>,
    /// Upstream responses up to this size are cached in object storage;
    /// larger responses are streamed through uncached.
    #[serde(default = "default_cache_limit")]
    pub cache_limit_bytes: u64,
}

fn default_upstream() -> Option<String> {
    Some("https://debuginfod.elfutils.org".to_string())
}

const fn default_cache_limit() -> u64 {
    256 * 1024 * 1024
}

impl Default for FederationConfig {
    fn default() -> Self {
        Self {
            upstream: default_upstream(),
            cache_limit_bytes: default_cache_limit(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct RetentionConfig {
    /// How many distinct versions of each project's symbols to keep (per
    /// project override via the management API). Symbols with no version tag
    /// are grouped as a single pseudo-version.
    #[serde(default = "default_keep_versions")]
    pub default_keep_versions: usize,
    /// How often the retention sweep runs.
    #[serde(with = "humantime_serde", default = "default_sweep_interval")]
    pub sweep_interval: std::time::Duration,
    /// Upstream federation cache entries older than this are dropped.
    #[serde(with = "humantime_serde", default = "default_upstream_max_age")]
    pub upstream_cache_max_age: std::time::Duration,
}

const fn default_keep_versions() -> usize {
    10
}

const fn default_sweep_interval() -> std::time::Duration {
    std::time::Duration::from_secs(24 * 3600)
}

const fn default_upstream_max_age() -> std::time::Duration {
    std::time::Duration::from_secs(90 * 24 * 3600)
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            default_keep_versions: default_keep_versions(),
            sweep_interval: default_sweep_interval(),
            upstream_cache_max_age: default_upstream_max_age(),
        }
    }
}

impl Config {
    #[cfg(test)]
    pub fn test() -> Self {
        Self {
            server: ServerConfig {
                public_addr: "127.0.0.1:0".to_string(),
                internal_addr: "127.0.0.1:0".to_string(),
                public_url: Some("https://symbols.example.com".to_string()),
            },
            storage: StorageConfig {
                endpoint: "http://localhost:1".to_string(),
                region: "test".to_string(),
                bucket: "symbols".to_string(),
                access_key_id: "test".to_string(),
                secret_access_key: "test".to_string(),
            },
            github: GithubConfig {
                trusted_orgs: vec!["SierraSoftworks".to_string()],
                audience: "symbols.example.com".to_string(),
                ref_prefixes: vec![],
                issuer: default_github_issuer(),
            },
            management: ManagementConfig {
                oidc: OidcConfig {
                    issuer: "https://idp.example.com".to_string(),
                    client_id: "symbols-ui".to_string(),
                    client_secret: "test-secret".to_string(),
                    scopes: default_oidc_scopes(),
                },
                acl: default_management_acl(),
                session_secret: Some("test-session-secret".to_string()),
                session_duration: default_session_duration(),
            },
            federation: FederationConfig {
                upstream: None,
                cache_limit_bytes: default_cache_limit(),
            },
            retention: RetentionConfig::default(),
        }
    }

    pub fn load(path: &std::path::Path) -> Result<Self, crate::errors::Error> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| crate::errors::Error::Config(format!("reading {}: {e}", path.display())))?;
        serde_yaml::from_str(&raw)
            .map_err(|e| crate::errors::Error::Config(format!("parsing {}: {e}", path.display())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The documented configuration surface has to remain the real one.
    #[test]
    fn the_example_config_parses() {
        let config: Config =
            serde_yaml::from_str(include_str!("../../config.example.yaml")).unwrap();
        assert_eq!(config.management.oidc.client_id, "symbols");
        // The ACL is commented out there, so the default applies.
        assert_eq!(config.management.acl.raw(), "true");
    }

    /// An ACL that doesn't parse is a startup failure, not a filter that
    /// quietly matches nothing.
    #[test]
    fn a_malformed_acl_is_rejected() {
        let yaml = include_str!("../../config.example.yaml")
            .replace("  #acl: claims.email", "  acl: claims.email &&& \"x\"\n  #acl: claims.email");
        let err = serde_yaml::from_str::<Config>(&yaml).unwrap_err().to_string();
        assert!(
            err.contains("management.acl") && err.contains("not a valid operator"),
            "unexpected error: {err}"
        );
    }
}
