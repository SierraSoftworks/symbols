use yew::prelude::*;

use crate::components::{ArchChip, FlashBanner, OsIcon, VisibilityBadge};
use crate::formatters::{ago, human_bytes, timestamp};
use crate::models::{Flash, ProjectDetail, ReleaseRow, TargetRow, Visibility};
use crate::routes;

#[derive(Properties, PartialEq)]
pub struct ProjectProps {
    pub detail: ProjectDetail,
    pub flash: Option<Flash>,
}

#[function_component(ProjectView)]
pub fn project_view(props: &ProjectProps) -> Html {
    let detail = &props.detail;
    html! {
        <div class="content">
            <FlashBanner flash={props.flash.clone()} />

            <div class="page-head">
                <h1 class="page-head__title">{&detail.name}</h1>
                <VisibilityBadge visibility={detail.visibility} />
                <span class="page-head__meta">
                    {format!("{} across {} releases · created {}",
                        human_bytes(detail.total_size),
                        detail.releases.len(),
                        detail.created_at.format("%Y-%m-%d"))}
                </span>
            </div>

            { settings_card(detail) }

            <section class="card">
                <h2 class="card__title">{"Releases"}</h2>
                {
                    if detail.releases.is_empty() {
                        html! { <p class="empty">{"No symbols stored for this project yet."}</p> }
                    } else {
                        html! { <>{ for detail.releases.iter().map(|r| release_section(&detail.name, r)) }</> }
                    }
                }
            </section>
        </div>
    }
}

fn settings_card(detail: &ProjectDetail) -> Html {
    let keep = detail
        .keep_versions
        .map(|k| k.to_string())
        .unwrap_or_default();
    html! {
        <section class="card">
            <h2 class="card__title">{"Settings"}</h2>
            <form method="post" action={routes::project_settings(&detail.name)} class="form form--row">
                <label class="form__field">
                    <span class="form__label">{"Visibility"}</span>
                    <select name="visibility">
                        <option value="public" selected={detail.visibility == Visibility::Public}>
                            {"public — served to anyone"}
                        </option>
                        <option value="internal" selected={detail.visibility == Visibility::Internal}>
                            {"internal — internal plane only"}
                        </option>
                    </select>
                </label>
                <label class="form__field">
                    <span class="form__label">{"Keep versions"}</span>
                    <input
                        type="number"
                        name="keep_versions"
                        min="1"
                        value={keep}
                        placeholder={format!("default ({})", detail.default_keep_versions)}
                    />
                </label>
                <button type="submit" class="button">{"Save"}</button>
            </form>
            <p class="form__hint">
                {"Leave “keep versions” empty to follow the server-wide default. Older \
                  versions beyond the window are pruned by the retention sweep."}
            </p>
        </section>
    }
}

fn release_section(project: &str, release: &ReleaseRow) -> Html {
    html! {
        <div class="release">
            <div class="release__head">
                <h3 class="release__version">{release.display_version()}</h3>
                <span class="release__meta" title={timestamp(release.updated_at)}>
                    {format!("{} · updated {}", human_bytes(release.total_size), ago(release.updated_at))}
                </span>
                <form
                    method="post"
                    action={routes::project_purge(project)}
                    data-confirm={format!("Purge all symbols for {} {}? This cannot be undone.",
                        project, release.display_version())}
                >
                    <input type="hidden" name="version" value={release.version.clone()} />
                    <button type="submit" class="button button--danger button--small">{"Purge release"}</button>
                </form>
            </div>
            <div class="table-scroll">
                <table class="table">
                    <thead>
                        <tr>
                            <th>{"Target"}</th>
                            <th>{"Build ID"}</th>
                            <th class="table__num">{"Size"}</th>
                            <th>{"Uploaded"}</th>
                            <th>{"Source"}</th>
                            <th></th>
                        </tr>
                    </thead>
                    <tbody>
                        { for release.targets.iter().map(|t| target_row(project, release, t)) }
                    </tbody>
                </table>
            </div>
        </div>
    }
}

fn target_row(project: &str, release: &ReleaseRow, target: &TargetRow) -> Html {
    html! {
        <tr>
            <td class="target">
                <OsIcon os={target.os} />
                <ArchChip arch={target.arch.clone()} />
                <span class="chip chip--muted">{&target.format}</span>
            </td>
            <td>
                <code class="build-id" title={target.build_id.clone()}>{short_id(&target.build_id)}</code>
            </td>
            <td class="table__num">{human_bytes(target.size)}</td>
            <td><span title={timestamp(target.uploaded_at)}>{ago(target.uploaded_at)}</span></td>
            <td class="source-links">{ source_links(project, target) }</td>
            <td>
                <form
                    method="post"
                    action={routes::project_purge(project)}
                    data-confirm={format!("Purge this {} {} symbol for {}? This cannot be undone.",
                        target.os.label(),
                        target.arch.as_deref().unwrap_or("unknown-arch"),
                        release.display_version())}
                >
                    <input type="hidden" name="build_id" value={target.build_id.clone()} />
                    <button type="submit" class="button button--danger button--small">{"Purge"}</button>
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
            <a class="source-links__item" href={format!("https://github.com/{project}/commit/{sha}")}>
                {short}
            </a>
        }
    });
    let run = target.build_url.as_deref().map(|url| {
        html! { <a class="source-links__item" href={url.to_string()}>{"build"}</a> }
    });
    let git_ref = target.uploaded_from.as_deref().map(|r| {
        html! { <span class="source-links__item muted" title="Uploading workflow ref">{r}</span> }
    });

    if commit.is_none() && run.is_none() && git_ref.is_none() {
        return html! { <span class="muted">{"—"}</span> };
    }
    html! { <>{commit}{run}{git_ref}</> }
}
