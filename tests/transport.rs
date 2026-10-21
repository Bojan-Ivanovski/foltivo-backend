use axum::{
    body::{Body, Bytes},
    Router,
};
use foltivo_backend::server;
use std::time::{Duration, Instant};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn stalled_reader_hits_write_deadline_and_other_connections_remain_usable() {
    const LENGTH: usize = 32 * 1024 * 1024;
    let bytes = Bytes::from(vec![b'x'; LENGTH]);
    let app = Router::new()
        .route(
            "/large",
            axum::routing::get(move || {
                let bytes = bytes.clone();
                async move { Body::from(bytes) }
            }),
        )
        .route("/health", axum::routing::get(|| async { "ok" }));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let stop = CancellationToken::new();
    let shutdown = stop.clone();
    let task = tokio::spawn(async move { server::serve(listener, app, shutdown).await });
    let mut socket = TcpStream::connect(address).await.unwrap();
    socket
        .write_all(b"GET /large HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    // Withhold reads so the response cannot fit in TCP buffers. This uses the
    // actual transport writer, rather than a mocked Tokio timer or Router call.
    tokio::time::sleep(Duration::from_secs(12)).await;
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), socket.read_to_end(&mut response))
        .await
        .expect("write timeout closes response")
        .unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200"));
    assert!(
        response.len() < LENGTH,
        "stalled response unexpectedly completed"
    );
    assert_eq!(
        reqwest::get(format!("http://{address}/health"))
            .await
            .unwrap()
            .text()
            .await
            .unwrap(),
        "ok"
    );
    stop.cancel();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn idle_keepalive_connection_expires_without_stopping_the_server() {
    let app = Router::new().route("/health", axum::routing::get(|| async { "ok" }));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let stop = CancellationToken::new();
    let shutdown = stop.clone();
    let task = tokio::spawn(async move { server::serve(listener, app, shutdown).await });
    let mut socket = TcpStream::connect(address).await.unwrap();
    socket
        .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let mut response = [0; 1024];
    let count = socket.read(&mut response).await.unwrap();
    assert!(response[..count].starts_with(b"HTTP/1.1 200"));
    // Drain any split response bytes before measuring idle expiry.
    if !response[..count].ends_with(b"ok") {
        let mut rest = [0; 2];
        socket.read_exact(&mut rest).await.unwrap();
    }
    let start = Instant::now();
    let mut byte = [0];
    let read = tokio::time::timeout(Duration::from_secs(65), socket.read(&mut byte))
        .await
        .expect("idle deadline");
    assert!(matches!(read, Ok(0) | Err(_)));
    assert!(start.elapsed() >= Duration::from_secs(55));
    assert_eq!(
        reqwest::get(format!("http://{address}/health"))
            .await
            .unwrap()
            .status(),
        200
    );
    stop.cancel();
    task.await.unwrap().unwrap();
}
