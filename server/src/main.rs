use std::sync::Arc;

use actix_web::{App, HttpServer, web};
use clap::Parser;

mod api;
mod auth;
mod compression;
mod config;
mod errors;
mod formats;
mod retention;
mod storage;

use api::{AppState, Plane};

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

    if config.management.oidc.is_some() && config.management.session_secret.is_none() {
        tracing::warn!(
            "No management.session_secret configured; browser sessions will not survive restarts"
        );
    }

    let state = Arc::new(AppState::new(config, store, http));

    tracing::info!(
        public = %state.config.server.public_addr,
        internal = %state.config.server.internal_addr,
        trusted_orgs = ?state.config.github.trusted_orgs,
        ui_sign_in = state.oidc.is_some(),
        "Starting symbols server"
    );

    tokio::spawn(retention::run(state.clone()));

    let public_state = state.clone();
    let public = HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(public_state.clone()))
            .app_data(web::Data::new(Plane::Public))
            .configure(api::configure_public)
    })
    .bind(&state.config.server.public_addr)?
    .run();

    let internal_state = state.clone();
    let internal = HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(internal_state.clone()))
            .app_data(web::Data::new(Plane::Internal))
            .configure(api::configure_internal)
    })
    .bind(&state.config.server.internal_addr)?
    .run();

    let result = futures::try_join!(public, internal);

    telemetry.shutdown();
    result?;
    Ok(())
}
