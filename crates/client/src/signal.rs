use tokio::signal;

/// Wait for shutdown signal (SIGINT or SIGTERM)
pub async fn shutdown_signal() {
    let ctrl_c = signal::ctrl_c();

    #[cfg(unix)]
    {
        let mut sigterm =
            signal::unix::signal(signal::unix::SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => log::info!("Received SIGINT (Ctrl+C)"),
            _ = sigterm.recv() => log::info!("Received SIGTERM"),
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await.ok();
        log::info!("Received shutdown signal");
    }
}
