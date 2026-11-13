use yew::prelude::*;
use yewi::prelude::*;

#[derive(Properties, PartialEq)]
pub struct SnippetProps {
    /// Unique per page; ties the copy button to its code block.
    pub id: AttrValue,
    /// Language tag for the header and the highlighter ("bash", "yaml").
    pub lang: AttrValue,
    pub code: AttrValue,
}

/// A copy-pasteable code block. yewi's own copy button needs a client
/// runtime, so the button here is wired up by app.js when JavaScript is
/// available; without it the block is still selectable text.
#[function_component(Snippet)]
pub fn snippet(props: &SnippetProps) -> Html {
    let copy = html! {
        <Button
            size={Size::Small}
            variant={ButtonVariant::Subtle}
            icon={icons::COPY}
            attrs={attrs! { "data-copy" => props.id.clone() }}
        >
            {"Copy"}
        </Button>
    };
    html! {
        <CodeBlock
            id={props.id.clone()}
            code={props.code.clone()}
            language={props.lang.clone()}
            copy=false
            actions={copy}
        />
    }
}
