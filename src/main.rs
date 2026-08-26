use std::sync::Arc;

use actix_web::{App, HttpServer, web};
use clap::Parser;

mod api;
mod auth;
mod config;
mod errors;
mod formats;
mod retention;
mod storage;

use api::{AppState, Plane};

/// Uploads up to this size are accepted; the largest artifacts are full-DWARF
/// debug files, which stay well under this.
const MAX_UPLOAD_BYTES: usize = 1024 * 1024 * 1024;

#[derive(Parser, Debug)]
#[clap(author, version, about)]
struct Args {
    /// Path to the server configuration file.
    #[clap(short, long, value_parser)]
    config: std::path::PathBuf,
}

#[actix_web::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let telemetry = tracing_batteries::Session::new("symbols", env!("CARGO_PKG_VERSION"))
        .with_battery(tracing_batteries::OpenTelemetry::new(""));

    let config = config::Config::load(&args.config)?;
    let store = storage::Store::new(&config.storage)?;

    let http = reqwest::Client::builder()
        .user_agent(format!("symbols/{}", env!("CARGO_PKG_VERSION")))
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(300))
        .build()?;

    let state = Arc::new(AppState {
        github_auth: auth::Validator::new(
            http.clone(),
            &config.github.issuer,
            &config.github.audience,
        ),
        management_auth: auth::Validator::new(
            http.clone(),
            &config.management.issuer,
            &config.management.audience,
        ),
        store,
        http,
        config,
    });

    tracing::info!(
        public = %state.config.server.public_addr,
        internal = %state.config.server.internal_addr,
        trusted_orgs = ?state.config.github.trusted_orgs,
        "Starting symbols server"
    );

    tokio::spawn(retention::run(state.clone()));

    let public_state = state.clone();
    let public = HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(public_state.clone()))
            .app_data(web::Data::new(Plane::Public))
            .app_data(web::PayloadConfig::new(MAX_UPLOAD_BYTES))
            .configure(api::configure)
    })
    .bind(&state.config.server.public_addr)?
    .run();

    let internal_state = state.clone();
    let internal = HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(internal_state.clone()))
            .app_data(web::Data::new(Plane::Internal))
            .app_data(web::PayloadConfig::new(MAX_UPLOAD_BYTES))
            .configure(api::configure)
    })
    .bind(&state.config.server.internal_addr)?
    .run();

    let result = futures::try_join!(public, internal);

    telemetry.shutdown();
    result?;
    Ok(())
}
