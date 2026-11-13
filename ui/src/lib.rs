pub mod app;
pub mod components;
pub mod formatters;
pub mod models;
pub mod routes;
pub mod views;

pub use app::{App, AppProps, PageBody};
pub use models::*;

/// The self-hosted yewi font files, for the server to embed and serve.
pub use yewi::fonts;

/// The URL prefix the server serves [`fonts::FILES`] under.
pub const FONTS_URL: &str = "/static/fonts";

/// App-level rules layered over yewi's stylesheet: the accent and page frame.
const APP_STYLES: &str = include_str!("../styles.css");

/// The management UI's stylesheet, served at `/static/styles.css`: the font
/// faces, yewi's compiled stylesheet, then the app's own rules. One file, so
/// a page costs a single stylesheet request.
pub fn stylesheet() -> &'static str {
    static STYLESHEET: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
        [&fonts::css(FONTS_URL), yewi::STYLESHEET, APP_STYLES].concat()
    });
    &STYLESHEET
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stylesheet_bundles_fonts_design_system_and_app_rules() {
        let css = stylesheet();
        assert!(css.contains(&format!("{FONTS_URL}/{}", fonts::FILES[0].name)));
        assert!(css.contains("@layer yewi"));
        assert!(css.contains("--yi-accent: light-dark(#6d4aff"));
    }
}
