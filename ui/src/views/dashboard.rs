use yew::prelude::*;

use crate::components::{FlashBanner, VisibilityBadge};
use crate::formatters::{ago, human_bytes, timestamp};
use crate::models::{Flash, ProjectRow, StatsSummary};
use crate::routes;

#[derive(Properties, PartialEq)]
pub struct DashboardProps {
    pub stats: StatsSummary,
    pub projects: Vec<ProjectRow>,
    pub flash: Option<Flash>,
}

#[function_component(DashboardView)]
pub fn dashboard_view(props: &DashboardProps) -> Html {
    html! {
        <div class="content">
            <FlashBanner flash={props.flash.clone()} />

            <section class="stats">
                { stat_tile("Projects", props.stats.project_count.to_string(), None) }
                { stat_tile("Stored symbols", props.stats.symbol_count.to_string(), None) }
                { stat_tile("Symbols size", human_bytes(props.stats.total_size), None) }
                { stat_tile(
                    "Upstream cache",
                    human_bytes(props.stats.upstream_size),
                    Some(format!("{} cached entries", props.stats.upstream_entries)),
                ) }
                {
                    match props.stats.last_upload {
                        Some(when) => stat_tile("Last upload", ago(when), Some(timestamp(when))),
                        None => stat_tile("Last upload", "never".to_string(), None),
                    }
                }
            </section>

            <section class="card">
                <h2 class="card__title">{"Projects"}</h2>
                {
                    if props.projects.is_empty() {
                        html! {
                            <p class="empty">
                                {"No projects yet — the first symbol upload from a trusted \
                                  repository creates its project automatically."}
                            </p>
                        }
                    } else {
                        html! {
                            <div class="table-scroll">
                                <table class="table">
                                    <thead>
                                        <tr>
                                            <th>{"Project"}</th>
                                            <th>{"Visibility"}</th>
                                            <th class="table__num">{"Versions"}</th>
                                            <th class="table__num">{"Symbols"}</th>
                                            <th class="table__num">{"Size"}</th>
                                            <th>{"Last upload"}</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        { for props.projects.iter().map(project_row) }
                                    </tbody>
                                </table>
                            </div>
                        }
                    }
                }
            </section>

            <section class="card">
                <h2 class="card__title">{"Maintenance"}</h2>
                <p>
                    {"The retention sweep prunes versions beyond each project's retention \
                      window and ages out the upstream federation cache. It runs on a \
                      schedule, but can be run immediately here."}
                </p>
                <form method="post" action={routes::sweep()}>
                    <button type="submit" class="button">{"Run retention sweep now"}</button>
                </form>
            </section>
        </div>
    }
}

fn stat_tile(label: &str, value: String, detail: Option<String>) -> Html {
    html! {
        <div class="stat">
            <span class="stat__label">{label}</span>
            <span class="stat__value">{value}</span>
            {
                match detail {
                    Some(detail) => html! { <span class="stat__detail">{detail}</span> },
                    None => Html::default(),
                }
            }
        </div>
    }
}

fn project_row(project: &ProjectRow) -> Html {
    html! {
        <tr>
            <td><a class="table__link" href={routes::project(&project.name)}>{&project.name}</a></td>
            <td><VisibilityBadge visibility={project.visibility} /></td>
            <td class="table__num">{project.version_count}</td>
            <td class="table__num">{project.symbol_count}</td>
            <td class="table__num">{human_bytes(project.total_size)}</td>
            <td>
                {
                    match project.last_upload {
                        Some(when) => html! { <span title={timestamp(when)}>{ago(when)}</span> },
                        None => html! { <span class="muted">{"never"}</span> },
                    }
                }
            </td>
        </tr>
    }
}
