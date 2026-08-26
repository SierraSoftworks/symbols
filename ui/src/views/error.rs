use yew::prelude::*;

use crate::routes;

#[derive(Properties, PartialEq)]
pub struct ErrorProps {
    pub status: u16,
    pub message: String,
}

#[function_component(ErrorView)]
pub fn error_view(props: &ErrorProps) -> Html {
    html! {
        <div class="content content--narrow">
            <div class="card error-card">
                <h1 class="error-card__status">{props.status}</h1>
                <p class="error-card__message">{&props.message}</p>
                <a class="button" href={routes::dashboard()}>{"Back to the dashboard"}</a>
            </div>
        </div>
    }
}
