use yew::prelude::*;
use yewi::prelude::*;

use crate::routes;

#[derive(Properties, PartialEq)]
pub struct ErrorProps {
    pub status: u16,
    pub message: String,
}

#[function_component(ErrorView)]
pub fn error_view(props: &ErrorProps) -> Html {
    let (icon, tone) = match props.status {
        404 => (icons::SEARCH_X, Tone::Neutral),
        401 | 403 => (icons::TRIANGLE_ALERT, Tone::Warn),
        _ => (icons::TRIANGLE_ALERT, Tone::Danger),
    };
    let actions = html! {
        <Button href={routes::dashboard()} variant={ButtonVariant::Primary}>{"Back to the dashboard"}</Button>
    };
    html! {
        <div class="page--narrow">
            <Card>
                <EmptyState title={props.status.to_string()} {icon} {tone} {actions} size={Size::Large}>
                    {&props.message}
                </EmptyState>
            </Card>
        </div>
    }
}
