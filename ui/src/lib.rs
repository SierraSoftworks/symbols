pub mod app;
pub mod components;
pub mod formatters;
pub mod models;
pub mod routes;
pub mod views;

pub use app::{App, AppProps, PageBody};
pub use models::*;

/// The management UI's stylesheet, compiled into the server binary and served
/// at `/static/styles.css`.
pub const STYLESHEET: &str = include_str!("../styles.css");

/// Progressive enhancement only (copy-to-clipboard buttons and purge
/// confirmations); every page works without it.
pub const SCRIPT: &str = include_str!("../app.js");

/// Renders a full page to its HTML body. The server wraps the result in the
/// document shell (doctype, `<head>`, stylesheet/script links).
pub async fn render(props: AppProps) -> String {
    yew::ServerRenderer::<App>::with_props(move || props)
        // Pure SSR: no client bundle ever hydrates this markup, so skip the
        // hydration marker comments yew would otherwise emit.
        .hydratable(false)
        .render()
        .await
}
