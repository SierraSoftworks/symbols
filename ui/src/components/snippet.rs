use yew::prelude::*;

#[derive(Properties, PartialEq)]
pub struct SnippetProps {
    /// Unique per page; ties the copy button to its <pre> element.
    pub id: AttrValue,
    /// Short language/format tag shown in the snippet header ("bash", "yaml").
    pub lang: AttrValue,
    pub code: AttrValue,
}

/// A copy-pasteable code block. The copy button is wired up by app.js when
/// JavaScript is available; without it the block is still selectable text.
#[function_component(Snippet)]
pub fn snippet(props: &SnippetProps) -> Html {
    html! {
        <div class="snippet">
            <div class="snippet__bar">
                <span class="snippet__lang">{&props.lang}</span>
                <button type="button" class="snippet__copy" data-copy={props.id.clone()}>{"Copy"}</button>
            </div>
            <pre id={props.id.clone()} class="snippet__code"><code>{&props.code}</code></pre>
        </div>
    }
}
