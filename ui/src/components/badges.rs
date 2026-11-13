use yew::prelude::*;
use yewi::prelude::*;

use crate::models::Visibility;

#[derive(Properties, PartialEq)]
pub struct VisibilityBadgeProps {
    pub visibility: Visibility,
}

#[function_component(VisibilityBadge)]
pub fn visibility_badge(props: &VisibilityBadgeProps) -> Html {
    let tone = match props.visibility {
        Visibility::Public => Tone::Ok,
        Visibility::Internal => Tone::Warn,
    };
    html! { <Pill {tone}>{props.visibility.label()}</Pill> }
}

#[derive(Properties, PartialEq)]
pub struct ArchChipProps {
    pub arch: Option<String>,
}

/// The architecture chip next to each target's OS icon. An absent
/// architecture (PDBs don't carry one unless the uploader tagged it) renders
/// as an explicit unknown rather than disappearing.
#[function_component(ArchChip)]
pub fn arch_chip(props: &ArchChipProps) -> Html {
    match &props.arch {
        Some(arch) => html! { <Tag mono=true>{crate::models::arch_label(arch)}</Tag> },
        None => html! { <Tag mono=true class="muted">{"arch?"}</Tag> },
    }
}
