use chrono::Datelike;
use yew::prelude::*;

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

/// The shared page chrome: header with navigation and the session chip, the
/// page content, and a footer.
#[function_component(Layout)]
pub fn layout(props: &LayoutProps) -> Html {
    let nav_class = |nav: Nav| {
        if props.active == nav {
            "header__nav-link header__nav-link--active"
        } else {
            "header__nav-link"
        }
    };

    html! {
        <>
            <header class="header">
                <div class="header__inner">
                    <a class="header__brand" href={routes::dashboard()}>
                        <span class="header__brand-mark">{"{;}"}</span>
                        <span class="header__brand-name">{"symbols"}</span>
                    </a>
                    <nav class="header__nav">
                        <a class={nav_class(Nav::Dashboard)} href={routes::dashboard()}>{"Dashboard"}</a>
                        <a class={nav_class(Nav::Setup)} href={routes::setup()}>{"Setup"}</a>
                    </nav>
                    <div class="header__session">
                        {
                            match &props.user {
                                Some(user) => html! {
                                    <>
                                        <span class="header__user" title={user.email.clone().unwrap_or_else(|| user.subject.clone())}>
                                            {user.display_name()}
                                        </span>
                                        <a class="header__auth-link" href={routes::logout()}>{"Sign out"}</a>
                                    </>
                                },
                                None => html! {
                                    <a class="header__auth-link" href={routes::login()}>{"Sign in"}</a>
                                },
                            }
                        }
                    </div>
                </div>
            </header>
            <main class="page">
                { for props.children.iter() }
            </main>
            <footer class="footer">
                <p>{format!("Copyright © {} Sierra Softworks", chrono::Utc::now().year())}</p>
            </footer>
        </>
    }
}
