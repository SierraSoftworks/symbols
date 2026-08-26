//! The UI's static assets, embedded in the binary at compile time (the SSR
//! equivalent of grey embedding its Trunk `dist/`). The filenames aren't
//! fingerprinted, so cache lifetimes stay short.

use actix_web::HttpResponse;

const CACHE_CONTROL: (&str, &str) = ("Cache-Control", "public, max-age=300");

pub async fn stylesheet() -> HttpResponse {
    HttpResponse::Ok()
        .content_type("text/css; charset=utf-8")
        .insert_header(CACHE_CONTROL)
        .body(symbols_ui::STYLESHEET)
}

pub async fn script() -> HttpResponse {
    HttpResponse::Ok()
        .content_type("text/javascript; charset=utf-8")
        .insert_header(CACHE_CONTROL)
        .body(symbols_ui::SCRIPT)
}
