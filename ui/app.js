// Progressive enhancement for the SSR-only management UI. Everything here is
// optional: without JavaScript the copy buttons degrade to selectable text
// and destructive forms submit without a confirmation prompt.
"use strict";

// Copy-to-clipboard for setup snippets: <button data-copy="<code block id>">.
// yewi's own CopyButton needs a wasm runtime, which this UI does not ship.
document.addEventListener("click", (event) => {
  const button = event.target.closest("[data-copy]");
  if (!button) return;
  const source = document.querySelector(`#${CSS.escape(button.dataset.copy)} pre`);
  if (!source || !navigator.clipboard) return;
  navigator.clipboard.writeText(source.textContent).then(() => {
    const label = button.lastChild;
    const text = label.textContent;
    label.textContent = "Copied";
    setTimeout(() => {
      label.textContent = text;
    }, 1500);
  });
});

// Confirmation prompts for destructive forms: <form data-confirm="...">.
document.addEventListener("submit", (event) => {
  const form = event.target;
  if (form.dataset && form.dataset.confirm && !window.confirm(form.dataset.confirm)) {
    event.preventDefault();
  }
});
