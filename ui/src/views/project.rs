use yew::prelude::*;
use yewi::prelude::*;

use crate::components::{ArchChip, FlashBanner, OsIcon, VisibilityBadge};
use crate::formatters::{ago, human_bytes, timestamp};
use crate::models::{Flash, ProjectDetail, ReleaseRow, TargetRow};
use crate::routes;

#[derive(Properties, PartialEq)]
pub struct ProjectProps {
    pub detail: ProjectDetail,
    pub flash: Option<Flash>,
}

#[function_component(ProjectView)]
pub fn project_view(props: &ProjectProps) -> Html {
    let detail = &props.detail;
    let meta = html! {
        <>
            <VisibilityBadge visibility={detail.visibility} />
            <Text color={TextColor::Muted}>
                {format!("{} across {} releases · created {}",
                    human_bytes(detail.total_size),
                    detail.releases.len(),
                    detail.created_at.format("%Y-%m-%d"))}
            </Text>
        </>
    };
    html! {
        <Stack gap={Space::Lg}>
            <FlashBanner flash={props.flash.clone()} />

            <PageHeader title={detail.name.clone()} {meta} />

            { settings_card(detail) }

            <Card title="Releases">
                {
                    if detail.releases.is_empty() {
                        html! {
                            <EmptyState title="No releases yet" icon={icons::PACKAGE_OPEN}>
                                {"No symbols stored for this project yet."}
                            </EmptyState>
                        }
                    } else {
                        html! {
                            <Stack gap={Space::Md}>
                                { for detail.releases.iter().map(|r| release_section(&detail.name, r)) }
                            </Stack>
                        }
                    }
                }
            </Card>
        </Stack>
    }
}

fn settings_card(detail: &ProjectDetail) -> Html {
    html! {
        <Card title="Settings">
            <form method="post" action={routes::project_settings(&detail.name)}>
                <Stack gap={Space::Lg} align={Align::Start}>
                    <Field label="Visibility" group=true>
                        // Native radios: they submit with the form and need
                        // no client runtime, unlike yewi's Select.
                        <RadioGroup name="visibility" value={detail.visibility.label()}>
                            <Radio value="public" description={html! { "Served to anyone." }}>
                                {"Public"}
                            </Radio>
                            <Radio value="internal" description={html! { "Served on the internal plane only." }}>
                                {"Internal"}
                            </Radio>
                        </RadioGroup>
                    </Field>
                    <Field
                        label="Keep versions"
                        hint={html! {
                            "Leave empty to follow the server-wide default. Older versions \
                             beyond the window are pruned by the retention sweep."
                        }}
                    >
                        // The stepper buttons need a client runtime; typing
                        // a number does not.
                        <NumberInput
                            name="keep_versions"
                            min={1.0}
                            stepper=false
                            value={detail.keep_versions.map(|keep| keep as f64)}
                            placeholder={format!("default ({})", detail.default_keep_versions)}
                            class="keep-versions"
                        />
                    </Field>
                    <Button kind={ButtonKind::Submit} variant={ButtonVariant::Primary}>{"Save"}</Button>
                </Stack>
            </form>
        </Card>
    }
}

fn release_section(project: &str, release: &ReleaseRow) -> Html {
    let purge = html! {
        <form
            method="post"
            action={routes::project_purge(project)}
            data-confirm={format!("Purge all symbols for {} {}? This cannot be undone.",
                project, release.display_version())}
        >
            <input type="hidden" name="version" value={release.version.clone()} />
            <Button kind={ButtonKind::Submit} variant={ButtonVariant::Danger} size={Size::Small} icon={icons::TRASH_2}>
                {"Purge release"}
            </Button>
        </form>
    };
    html! {
        <Panel
            title={release.display_version().to_string()}
            subtitle={format!("{} · updated {}", human_bytes(release.total_size), ago(release.updated_at))}
            actions={purge}
            flush=true
            attrs={attrs! { "title" => timestamp(release.updated_at) }}
        >
            <SimpleTable label={format!("Targets of {}", release.display_version())} compact=true>
                <thead>
                    <tr>
                        <th scope="col">{"Target"}</th>
                        <th scope="col">{"Build ID"}</th>
                        <th scope="col" class="yi-table__cell--end">{"Size"}</th>
                        <th scope="col">{"Uploaded"}</th>
                        <th scope="col">{"Source"}</th>
                        <th scope="col" aria-label="Actions"></th>
                    </tr>
                </thead>
                <tbody>
                    { for release.targets.iter().map(|t| target_row(project, release, t)) }
                </tbody>
            </SimpleTable>
        </Panel>
    }
}

fn target_row(project: &str, release: &ReleaseRow, target: &TargetRow) -> Html {
    html! {
        <tr class="yi-table__row">
            <td>
                <Cluster gap={Space::Xs} nowrap=true>
                    <OsIcon os={target.os} />
                    <ArchChip arch={target.arch.clone()} />
                    <Tag mono=true class="muted">{&target.format}</Tag>
                </Cluster>
            </td>
            <td>
                <Text mono=true color={TextColor::Muted} attrs={attrs! { "title" => target.build_id.clone() }}>
                    {short_id(&target.build_id)}
                </Text>
            </td>
            <td class="yi-table__cell--end">{human_bytes(target.size)}</td>
            <td><span title={timestamp(target.uploaded_at)}>{ago(target.uploaded_at)}</span></td>
            <td><Cluster gap={Space::Sm} nowrap=true>{ source_links(project, target) }</Cluster></td>
            <td class="yi-table__cell--end">
                <form
                    method="post"
                    action={routes::project_purge(project)}
                    data-confirm={format!("Purge this {} {} symbol for {}? This cannot be undone.",
                        target.os.label(),
                        target.arch.as_deref().unwrap_or("unknown-arch"),
                        release.display_version())}
                >
                    <input type="hidden" name="build_id" value={target.build_id.clone()} />
                    <Button kind={ButtonKind::Submit} variant={ButtonVariant::Subtle} size={Size::Small} icon={icons::TRASH_2}>
                        {"Purge"}
                    </Button>
                </form>
            </td>
        </tr>
    }
}

/// Build IDs are 32–40+ hex characters; the first 12 are plenty to recognise
/// one, and the full ID sits in the title attribute.
fn short_id(id: &str) -> String {
    if id.len() > 12 {
        format!("{}…", &id[..12])
    } else {
        id.to_string()
    }
}

fn source_links(project: &str, target: &TargetRow) -> Html {
    let commit = target.commit.as_deref().map(|sha| {
        let short: String = sha.chars().take(7).collect();
        html! {
            <Link href={format!("https://github.com/{project}/commit/{sha}")}>
                <Text mono=true>{short}</Text>
            </Link>
        }
    });
    let run = target.build_url.as_deref().map(|url| {
        html! { <Link href={url.to_string()}>{"build"}</Link> }
    });
    let git_ref = target.uploaded_from.as_deref().map(|r| {
        html! {
            <Text color={TextColor::Subtle} attrs={attrs! { "title" => "Uploading workflow ref" }}>{r.to_string()}</Text>
        }
    });

    if commit.is_none() && run.is_none() && git_ref.is_none() {
        return html! { <Text color={TextColor::Subtle}>{"—"}</Text> };
    }
    html! { <>{commit}{run}{git_ref}</> }
}
