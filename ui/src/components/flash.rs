use yew::prelude::*;
use yewi::prelude::*;

use crate::models::Flash;

#[derive(Properties, PartialEq)]
pub struct FlashBannerProps {
    pub flash: Option<Flash>,
}

/// The one-shot notice shown after a form action (saved settings, purge
/// results, sweep results). Renders nothing when there is no notice.
#[function_component(FlashBanner)]
pub fn flash_banner(props: &FlashBannerProps) -> Html {
    match &props.flash {
        Some(flash) => {
            let tone = if flash.error { Tone::Danger } else { Tone::Ok };
            html! { <Alert {tone}>{&flash.message}</Alert> }
        }
        None => Html::default(),
    }
}
