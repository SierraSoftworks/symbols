use yew::prelude::*;

use crate::models::Visibility;

#[derive(Properties, PartialEq)]
pub struct VisibilityBadgeProps {
    pub visibility: Visibility,
}

#[function_component(VisibilityBadge)]
pub fn visibility_badge(props: &VisibilityBadgeProps) -> Html {
    let class = match props.visibility {
        Visibility::Public => "badge badge--public",
        Visibility::Internal => "badge badge--internal",
    };
    html! { <span {class}>{props.visibility.label()}</span> }
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
        Some(arch) => html! { <span class="chip">{crate::models::arch_label(arch)}</span> },
        None => html! { <span class="chip chip--muted">{"arch?"}</span> },
    }
}
