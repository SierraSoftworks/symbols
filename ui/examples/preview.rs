//! Renders every page with fixture data into ./preview-*.html for visual
//! checks without a running server (the SSR-only analogue of grey's
//! debug-only /controls gallery):
//!
//! ```sh
//! cargo run -p symbols-ui --example preview
//! ```

use chrono::{Duration, Utc};
use symbols_ui::*;

/// A minimal stand-in for the server's document shell (server/src/api/pages.rs).
fn shell(title: &str, body: &str) -> String {
    format!(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>{title}</title><style>{}</style></head>\
         <body>{body}<script>{}</script></body></html>",
        STYLESHEET, SCRIPT,
    )
}

fn target(id: &str, os: Os, arch: &str, size: u64, days: i64) -> TargetRow {
    TargetRow {
        build_id: id.repeat(10),
        os,
        arch: if arch.is_empty() {
            None
        } else {
            Some(arch.to_string())
        },
        format: match os {
            Os::Linux => "elf",
            Os::MacOs => "macho",
            _ => "pdb",
        }
        .to_string(),
        size,
        uploaded_at: Utc::now() - Duration::days(days),
        commit: Some("0123456789abcdef0123456789abcdef01234567".to_string()),
        build_url: Some("https://github.com/SierraSoftworks/grey/actions/runs/42".to_string()),
        uploaded_from: Some("refs/tags/v1.2.3".to_string()),
    }
}

fn sample_user() -> Option<SessionUser> {
    Some(SessionUser {
        subject: "u-123".to_string(),
        name: Some("Benjamin Pannell".to_string()),
        email: Some("benjamin@example.com".to_string()),
    })
}

#[tokio::main]
async fn main() {
    let pages: Vec<(&str, AppProps)> = vec![
        (
            "dashboard",
            AppProps {
                user: sample_user(),
                body: PageBody::Dashboard {
                    stats: StatsSummary {
                        project_count: 3,
                        symbol_count: 24,
                        total_size: 512 * 1024 * 1024,
                        stored_size: 119 * 1024 * 1024,
                        upstream_entries: 12,
                        upstream_size: 96 * 1024 * 1024,
                        last_upload: Some(Utc::now() - Duration::hours(3)),
                    },
                    projects: vec![
                        ProjectRow {
                            name: "SierraSoftworks/grey".to_string(),
                            visibility: Visibility::Public,
                            version_count: 4,
                            symbol_count: 12,
                            total_size: 320 * 1024 * 1024,
                            last_upload: Some(Utc::now() - Duration::hours(3)),
                        },
                        ProjectRow {
                            name: "SierraSoftworks/symbols".to_string(),
                            visibility: Visibility::Internal,
                            version_count: 2,
                            symbol_count: 8,
                            total_size: 128 * 1024 * 1024,
                            last_upload: Some(Utc::now() - Duration::days(2)),
                        },
                        ProjectRow {
                            name: "SierraSoftworks/mail-backup".to_string(),
                            visibility: Visibility::Internal,
                            version_count: 1,
                            symbol_count: 4,
                            total_size: 64 * 1024 * 1024,
                            last_upload: None,
                        },
                    ],
                    flash: Some(Flash {
                        message: "Sweep complete: pruned 3 symbol file(s), dropped 1 upstream cache entry".to_string(),
                        error: false,
                    }),
                },
            },
        ),
        (
            "project",
            AppProps {
                user: sample_user(),
                body: PageBody::Project {
                    detail: ProjectDetail {
                        name: "SierraSoftworks/grey".to_string(),
                        visibility: Visibility::Public,
                        keep_versions: None,
                        default_keep_versions: 10,
                        created_at: Utc::now() - Duration::days(90),
                        total_size: 320 * 1024 * 1024,
                        releases: vec![
                            ReleaseRow {
                                version: "v1.3.0".to_string(),
                                updated_at: Utc::now() - Duration::hours(3),
                                total_size: 120 * 1024 * 1024,
                                targets: vec![
                                    target("ab12", Os::Linux, "x86_64", 40 * 1024 * 1024, 0),
                                    target("cd34", Os::Linux, "aarch64", 38 * 1024 * 1024, 0),
                                    target("ef56", Os::MacOs, "aarch64", 22 * 1024 * 1024, 0),
                                    target("0912", Os::Windows, "", 20 * 1024 * 1024, 0),
                                ],
                            },
                            ReleaseRow {
                                version: "v1.2.3".to_string(),
                                updated_at: Utc::now() - Duration::days(12),
                                total_size: 100 * 1024 * 1024,
                                targets: vec![
                                    target("aa11", Os::Linux, "x86_64", 52 * 1024 * 1024, 12),
                                    target("bb22", Os::Linux, "arm64", 48 * 1024 * 1024, 12),
                                ],
                            },
                            ReleaseRow {
                                version: String::new(),
                                updated_at: Utc::now() - Duration::days(40),
                                total_size: 30 * 1024 * 1024,
                                targets: vec![target("cc33", Os::Other, "riscv64", 30 * 1024 * 1024, 40)],
                            },
                        ],
                    },
                    flash: None,
                },
            },
        ),
        (
            "setup",
            AppProps {
                user: None,
                body: PageBody::Setup {
                    info: SetupInfo {
                        public_url: "https://symbols.sierrasoftworks.com".to_string(),
                        internal_url: "https://symbols.raptor-perch.ts.net".to_string(),
                        github_audience: "symbols.sierrasoftworks.com".to_string(),
                    },
                },
            },
        ),
        (
            "error",
            AppProps {
                user: None,
                body: PageBody::Error {
                    status: 404,
                    message: "No project named 'SierraSoftworks/unknown' exists.".to_string(),
                },
            },
        ),
    ];

    for (name, props) in pages {
        let title = props.body.title();
        let html = shell(&title, &render(props).await);
        let path = format!("preview-{name}.html");
        std::fs::write(&path, html).expect("write preview file");
        println!("wrote {path}");
    }
}
