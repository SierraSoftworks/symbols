use yew::prelude::*;
use yewi::prelude::*;

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
    let stats = &props.stats;
    html! {
        <Stack gap={Space::Lg}>
            <FlashBanner flash={props.flash.clone()} />

            <Grid min="11rem" gap={Space::Md}>
                <StatTile label="Projects" value={stats.project_count.to_string()} />
                <StatTile label="Stored symbols" value={stats.symbol_count.to_string()} />
                <StatTile
                    label="Symbols size"
                    value={human_bytes(stats.total_size)}
                    detail={format!("{} stored", human_bytes(stats.stored_size))}
                />
                <StatTile
                    label="Upstream cache"
                    value={human_bytes(stats.upstream_size)}
                    detail={format!("{} cached entries", stats.upstream_entries)}
                />
                {
                    match stats.last_upload {
                        Some(when) => html! {
                            <StatTile label="Last upload" value={ago(when)} detail={timestamp(when)} />
                        },
                        None => html! { <StatTile label="Last upload" value="never" /> },
                    }
                }
            </Grid>

            <Card title="Projects" flush={!props.projects.is_empty()}>
                {
                    if props.projects.is_empty() {
                        html! {
                            <EmptyState title="No projects yet" icon={icons::PACKAGE_OPEN}>
                                {"The first symbol upload from a trusted repository creates \
                                  its project automatically."}
                            </EmptyState>
                        }
                    } else {
                        html! {
                            <SimpleTable label="Projects">
                                <thead>
                                    <tr>
                                        <th scope="col">{"Project"}</th>
                                        <th scope="col">{"Visibility"}</th>
                                        <th scope="col" class="yi-table__cell--end">{"Versions"}</th>
                                        <th scope="col" class="yi-table__cell--end">{"Symbols"}</th>
                                        <th scope="col" class="yi-table__cell--end">{"Size"}</th>
                                        <th scope="col">{"Last upload"}</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    { for props.projects.iter().map(project_row) }
                                </tbody>
                            </SimpleTable>
                        }
                    }
                }
            </Card>

            <Card title="Maintenance">
                <Stack gap={Space::Md} align={Align::Start}>
                    <Text color={TextColor::Muted}>
                        {"The retention sweep prunes versions beyond each project's retention \
                          window and ages out the upstream federation cache. It runs on a \
                          schedule, but can be run immediately here."}
                    </Text>
                    <form method="post" action={routes::sweep()}>
                        <Button kind={ButtonKind::Submit} icon={icons::BRUSH_CLEANING}>
                            {"Run retention sweep now"}
                        </Button>
                    </form>
                </Stack>
            </Card>
        </Stack>
    }
}

fn project_row(project: &ProjectRow) -> Html {
    html! {
        <tr class="yi-table__row">
            <th scope="row"><Link href={routes::project(&project.name)}>{&project.name}</Link></th>
            <td><VisibilityBadge visibility={project.visibility} /></td>
            <td class="yi-table__cell--end">{project.version_count}</td>
            <td class="yi-table__cell--end">{project.symbol_count}</td>
            <td class="yi-table__cell--end">{human_bytes(project.total_size)}</td>
            <td>
                {
                    match project.last_upload {
                        Some(when) => html! { <span title={timestamp(when)}>{ago(when)}</span> },
                        None => html! { <Text color={TextColor::Subtle}>{"never"}</Text> },
                    }
                }
            </td>
        </tr>
    }
}
