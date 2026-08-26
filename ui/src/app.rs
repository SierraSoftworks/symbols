use yew::prelude::*;

use crate::components::{Layout, Nav};
use crate::models::{Flash, ProjectDetail, ProjectRow, SessionUser, SetupInfo, StatsSummary};
use crate::views::{DashboardView, ErrorView, ProjectView, SetupView};

/// The page being rendered, with everything it needs. The server resolves all
/// data before rendering — views never fetch (there is no client runtime to
/// fetch with).
#[derive(Clone, PartialEq)]
pub enum PageBody {
    Dashboard {
        stats: StatsSummary,
        projects: Vec<ProjectRow>,
        flash: Option<Flash>,
    },
    Project {
        detail: ProjectDetail,
        flash: Option<Flash>,
    },
    Setup {
        info: SetupInfo,
    },
    Error {
        status: u16,
        message: String,
    },
}

impl PageBody {
    /// The document title the server puts in the HTML shell's `<title>`.
    pub fn title(&self) -> String {
        match self {
            PageBody::Dashboard { .. } => "Dashboard · symbols".to_string(),
            PageBody::Project { detail, .. } => format!("{} · symbols", detail.name),
            PageBody::Setup { .. } => "Setup · symbols".to_string(),
            PageBody::Error { status, .. } => format!("{status} · symbols"),
        }
    }

    fn nav(&self) -> Nav {
        match self {
            PageBody::Dashboard { .. } | PageBody::Project { .. } => Nav::Dashboard,
            PageBody::Setup { .. } => Nav::Setup,
            PageBody::Error { .. } => Nav::None,
        }
    }
}

#[derive(Properties, PartialEq)]
pub struct AppProps {
    pub user: Option<SessionUser>,
    pub body: PageBody,
}

/// The root component: shared layout around the current page. This plays the
/// role of grey's `App` + `switch()`, with the page selected by the server
/// (which owns routing) rather than by a client-side router.
#[function_component(App)]
pub fn app(props: &AppProps) -> Html {
    let body = match &props.body {
        PageBody::Dashboard {
            stats,
            projects,
            flash,
        } => html! {
            <DashboardView stats={stats.clone()} projects={projects.clone()} flash={flash.clone()} />
        },
        PageBody::Project { detail, flash } => html! {
            <ProjectView detail={detail.clone()} flash={flash.clone()} />
        },
        PageBody::Setup { info } => html! { <SetupView info={info.clone()} /> },
        PageBody::Error { status, message } => html! {
            <ErrorView status={*status} message={message.clone()} />
        },
    };

    html! {
        <Layout user={props.user.clone()} active={props.body.nav()}>
            { body }
        </Layout>
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    async fn render(body: PageBody, user: Option<SessionUser>) -> String {
        crate::render(AppProps { user, body }).await
    }

    #[tokio::test]
    async fn dashboard_renders_projects_and_session() {
        let html = render(
            PageBody::Dashboard {
                stats: StatsSummary {
                    project_count: 1,
                    symbol_count: 3,
                    total_size: 1536,
                    stored_size: 512,
                    upstream_entries: 2,
                    upstream_size: 2048,
                    last_upload: Some(Utc::now()),
                },
                projects: vec![ProjectRow {
                    name: "SierraSoftworks/grey".to_string(),
                    visibility: crate::models::Visibility::Public,
                    version_count: 2,
                    symbol_count: 3,
                    total_size: 1536,
                    last_upload: Some(Utc::now()),
                }],
                flash: None,
            },
            Some(SessionUser {
                subject: "user-1".to_string(),
                name: Some("Benjamin".to_string()),
                email: Some("benjamin@example.com".to_string()),
            }),
        )
        .await;

        assert!(html.contains("SierraSoftworks/grey"));
        assert!(html.contains("1.5 KiB"));
        assert!(html.contains("Benjamin"));
        assert!(html.contains("Sign out"));
        assert!(html.contains("Run retention sweep"));
    }

    #[tokio::test]
    async fn project_page_renders_targets_and_purge_forms() {
        let html = render(
            PageBody::Project {
                detail: ProjectDetail {
                    name: "SierraSoftworks/grey".to_string(),
                    visibility: crate::models::Visibility::Internal,
                    keep_versions: Some(5),
                    default_keep_versions: 10,
                    created_at: Utc::now(),
                    total_size: 4096,
                    releases: vec![crate::models::ReleaseRow {
                        version: "v1.2.3".to_string(),
                        updated_at: Utc::now(),
                        total_size: 4096,
                        targets: vec![crate::models::TargetRow {
                            build_id: "aabbccddeeff00112233".to_string(),
                            os: crate::models::Os::Linux,
                            arch: Some("x86_64".to_string()),
                            format: "elf".to_string(),
                            size: 4096,
                            uploaded_at: Utc::now(),
                            commit: Some("0123456789abcdef".to_string()),
                            build_url: Some("https://github.com/SierraSoftworks/grey/actions/runs/1".to_string()),
                            uploaded_from: Some("refs/tags/v1.2.3".to_string()),
                        }],
                    }],
                },
                flash: None,
            },
            None,
        )
        .await;

        assert!(html.contains("v1.2.3"));
        // Toolchain arch labels are normalised for display.
        assert!(html.contains("amd64"));
        assert!(html.contains("aabbccddeeff…"));
        assert!(html.contains("/projects/SierraSoftworks/grey/purge"));
        assert!(html.contains("0123456"));
        // Unauthenticated layout offers sign-in.
        assert!(html.contains("Sign in"));
    }

    #[tokio::test]
    async fn setup_page_embeds_server_urls() {
        let html = render(
            PageBody::Setup {
                info: SetupInfo {
                    public_url: "https://symbols.example.com".to_string(),
                    internal_url: "https://symbols-internal.example.com".to_string(),
                    github_audience: "symbols.example.com".to_string(),
                },
            },
            None,
        )
        .await;

        assert!(html.contains("DEBUGINFOD_URLS=\"https://symbols-internal.example.com\""));
        assert!(html.contains("SierraSoftworks/symbols@v1"));
        assert!(html.contains("audience: symbols.example.com"));
    }
}
