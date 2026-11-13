//! The UI's static assets, embedded in the binary at compile time (the SSR
//! equivalent of grey embedding its Trunk `dist/`). The filenames aren't
//! fingerprinted, so cache lifetimes stay short.

use actix_web::{web, HttpResponse};

const CACHE_CONTROL: (&str, &str) = ("Cache-Control", "public, max-age=300");

pub async fn stylesheet() -> HttpResponse {
    HttpResponse::Ok()
        .content_type("text/css; charset=utf-8")
        .insert_header(CACHE_CONTROL)
        .body(symbols_ui::stylesheet())
}

pub async fn script() -> HttpResponse {
    HttpResponse::Ok()
        .content_type("text/javascript; charset=utf-8")
        .insert_header(CACHE_CONTROL)
        .body(symbols_ui::SCRIPT)
}

/// The design system's self-hosted fonts (`/static/fonts/{name}`). Without
/// them the pages fall back to system fonts.
pub async fn font(name: web::Path<String>) -> HttpResponse {
    match symbols_ui::fonts::FILES
        .iter()
        .find(|file| file.name == name.as_str())
    {
        Some(file) => HttpResponse::Ok()
            .content_type(symbols_ui::fonts::CONTENT_TYPE)
            // Font files only change with a yewi release.
            .insert_header(("Cache-Control", "public, max-age=604800"))
            .body(file.bytes),
        None => HttpResponse::NotFound().finish(),
    }
}
