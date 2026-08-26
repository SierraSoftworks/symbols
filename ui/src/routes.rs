//! Href builders for every page and form action, so paths are defined once
//! and shared by the UI (links/forms) and the server (route registration —
//! see `server/src/api/mod.rs`, which must register a handler for each).
//!
//! With no client-side router there is no `Routable` enum to derive these
//! from; plain functions keep the same single-source-of-truth property.

pub fn dashboard() -> &'static str {
    "/"
}

/// `name` is "org/repo"; both parts are GitHub identifiers and URL-safe.
pub fn project(name: &str) -> String {
    format!("/projects/{name}")
}

pub fn project_settings(name: &str) -> String {
    format!("/projects/{name}/settings")
}

pub fn project_purge(name: &str) -> String {
    format!("/projects/{name}/purge")
}

pub fn setup() -> &'static str {
    "/setup"
}

pub fn sweep() -> &'static str {
    "/admin/sweep"
}

pub fn login() -> &'static str {
    "/auth/login"
}

pub fn logout() -> &'static str {
    "/auth/logout"
}
