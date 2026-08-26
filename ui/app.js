// Progressive enhancement for the SSR-only management UI. Everything here is
// optional: without JavaScript the copy buttons degrade to selectable text
// and destructive forms submit without a confirmation prompt.
"use strict";

// Copy-to-clipboard for setup snippets: <button data-copy="<pre id>">.
document.addEventListener("click", (event) => {
  const button = event.target.closest("[data-copy]");
  if (!button) return;
  const source = document.getElementById(button.dataset.copy);
  if (!source || !navigator.clipboard) return;
  navigator.clipboard.writeText(source.innerText).then(() => {
    const label = button.textContent;
    button.classList.add("copied");
    button.textContent = "Copied";
    setTimeout(() => {
      button.classList.remove("copied");
      button.textContent = label;
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
