use foltivo_backend::{
    auth::{Error, Result, Service},
    config::{connect, Config},
    http,
};
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .json()
        .with_target(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    if let Err(error) = run().await {
        tracing::error!(reason=%error,"api_failed");
        std::process::exit(1)
    }
}
async fn run() -> Result<()> {
    let config = Config::load()?;
    let address = if config.http_addr.starts_with(':') {
        format!("0.0.0.0{}", config.http_addr)
    } else {
        config.http_addr.clone()
    };
    let db = connect(&config.database_url).await?;
    let service = Service::new(db.clone(), config).await?;
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .map_err(|_| Error::validation("HTTP server failed to listen"))?;
    let stop = CancellationToken::new();
    let worker_stop = stop.clone();
    let signals = stop.clone();
    tokio::spawn(async move {
        shutdown_signal().await;
        signals.cancel();
    });
    let email_service = service.clone();
    let email_stop = worker_stop.clone();
    let email = tokio::spawn(async move { email_service.email_loop(email_stop).await });
    let closure_service = service.clone();
    let closure = tokio::spawn(async move { closure_service.closure_loop(worker_stop).await });
    tracing::info!("api_started");
    let app = http::router(service);
    let server_result = foltivo_backend::server::serve(listener, app, stop.clone()).await;
    stop.cancel();
    let _ = email.await;
    let _ = closure.await;
    let _ = db.close().await;
    server_result?;
    tracing::info!("api_stopped");
    Ok(())
}
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        if let Ok(mut term) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            tokio::select! {_ = tokio::signal::ctrl_c()=>{},_ = term.recv()=>{}}
        } else {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
