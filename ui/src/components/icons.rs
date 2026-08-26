use yew::prelude::*;

use crate::models::Os;

/// Renders a raw SVG icon. Safe use of `from_html_unchecked`: every input is
/// one of the static, hand-authored SVG constants below — no request- or
/// storage-derived data ever flows through here.
fn icon(raw: &'static str) -> Html {
    Html::from_html_unchecked(AttrValue::Static(raw))
}

/// A simplified penguin: egg-shaped body with belly and eye cut-outs.
const LINUX: &str = r#"<svg class="icon" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path fill-rule="evenodd" d="M12 1.5c-3 0-5 2.2-5 5.1 0 1.2-.3 2.3-.9 3.4-.9 1.7-1.9 3.6-1.9 5.9 0 4 3.4 6.6 7.8 6.6s7.8-2.6 7.8-6.6c0-2.3-1-4.2-1.9-5.9-.6-1.1-.9-2.2-.9-3.4 0-2.9-2-5.1-5-5.1Zm-2 3.1a.9.9 0 1 0 0 1.8.9.9 0 0 0 0-1.8Zm4 0a.9.9 0 1 0 0 1.8.9.9 0 0 0 0-1.8ZM12 10c-2.1 0-3.7 2.3-3.7 5.2 0 2.8 1.6 4.6 3.7 4.6s3.7-1.8 3.7-4.6C15.7 12.3 14.1 10 12 10Z"/></svg>"#;

/// A generic apple-with-leaf silhouette.
const MACOS: &str = r#"<svg class="icon" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M15.8 2c.1 1.1-.3 2.2-1 3-.7.9-1.8 1.5-2.9 1.4-.1-1 .4-2.1 1-2.9.7-.8 1.9-1.4 2.9-1.5ZM19.4 17c-.5 1.2-.8 1.7-1.5 2.8-.9 1.5-2.3 3.3-3.9 3.3-1.5 0-1.8-1-3.8-1s-2.4 1-3.8 1c-1.7 0-2.9-1.6-3.9-3.1C.7 16.1.4 11.6 1.9 9.2c1-1.7 2.7-2.7 4.3-2.7 1.6 0 2.6 1 3.9 1 1.3 0 2.1-1 3.9-1 1.4 0 2.9.8 3.9 2.1-3.4 1.9-2.9 6.8 1.5 8.4Z"/></svg>"#;

/// The requested 2×2 grid of panes.
const WINDOWS: &str = r#"<svg class="icon" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M3 3h8.5v8.5H3V3Zm9.5 0H21v8.5h-8.5V3ZM3 12.5h8.5V21H3v-8.5Zm9.5 0H21V21h-8.5v-8.5Z"/></svg>"#;

/// A generic chip for anything we can't classify.
const OTHER: &str = r#"<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><rect x="6" y="6" width="12" height="12" rx="1.5"/><path d="M9 2v3M15 2v3M9 19v3M15 19v3M2 9h3M2 15h3M19 9h3M19 15h3"/></svg>"#;

#[derive(Properties, PartialEq)]
pub struct OsIconProps {
    pub os: Os,
}

/// The OS marker shown on each symbol target row.
#[function_component(OsIcon)]
pub fn os_icon(props: &OsIconProps) -> Html {
    let raw = match props.os {
        Os::Linux => LINUX,
        Os::MacOs => MACOS,
        Os::Windows => WINDOWS,
        Os::Other => OTHER,
    };
    html! {
        <span class="os-icon" title={props.os.label()}>
            { icon(raw) }
            <span class="visually-hidden">{props.os.label()}</span>
        </span>
    }
}
