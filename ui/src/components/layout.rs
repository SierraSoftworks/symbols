use chrono::Datelike;
use yew::prelude::*;
use yewi::prelude::*;

use crate::models::SessionUser;
use crate::routes;

/// Which top-level navigation entry the current page belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Nav {
    Dashboard,
    Setup,
    None,
}

#[derive(Properties, PartialEq)]
pub struct LayoutProps {
    pub user: Option<SessionUser>,
    pub active: Nav,
    pub children: Children,
}

/// The shared page chrome: app bar with navigation and the session chip, the
/// page content, and a footer.
#[function_component(Layout)]
pub fn layout(props: &LayoutProps) -> Html {
    let brand = html! {
        <AppBarBrand href={routes::dashboard()} logo={html! { <span class="brand-mark">{"{;}"}</span> }}>
            {"symbols"}
        </AppBarBrand>
    };

    // Plain links rather than yewi's UserMenu: its popover needs a client
    // runtime, and this UI ships none.
    let session = match &props.user {
        Some(user) => html! {
            <>
                <Text
                    class="session-user"
                    color={TextColor::Muted}
                    truncate=true
                    attrs={attrs! { "title" => user.email.clone().unwrap_or_else(|| user.subject.clone()) }}
                >
                    {user.display_name()}
                </Text>
                <Button href={routes::logout()} variant={ButtonVariant::Subtle} icon={icons::LOG_OUT}>
                    {"Sign out"}
                </Button>
            </>
        },
        None => html! {
            <Button href={routes::login()} variant={ButtonVariant::Primary} icon={icons::LOG_IN}>
                {"Sign in"}
            </Button>
        },
    };

    html! {
        <>
            <AppBar {brand} actions={session}>
                // Two destinations always fit, so the menu never collapses
                // into a dropdown (which would need a client runtime).
                <TopMenu collapse={TopMenuCollapse::Never}>
                    <TopMenuItem href={routes::dashboard()} current={props.active == Nav::Dashboard}>
                        {"Dashboard"}
                    </TopMenuItem>
                    <TopMenuItem href={routes::setup()} current={props.active == Nav::Setup}>
                        {"Setup"}
                    </TopMenuItem>
                </TopMenu>
            </AppBar>
            <main class="page">
                { for props.children.iter() }
            </main>
            <footer class="footer">
                <Text size={TextSize::Sm} color={TextColor::Muted}>
                    {format!("Copyright © {} Sierra Softworks", chrono::Utc::now().year())}
                </Text>
            </footer>
        </>
    }
}
