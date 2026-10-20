mod common;
use common::{database, App, Smtp};
use foltivo_test_support::TestPostgres;
use sea_orm::ConnectionTrait;
use std::{
    process::Stdio,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    process::{Child, Command},
};

struct Api {
    child: Child,
    base: String,
}
impl Api {
    async fn start(url: &str, smtp: &str) -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let base = format!("http://{address}");
        let child = Command::new(env!("CARGO_BIN_EXE_api"))
            .env_clear()
            .env("APP_ENV", "test")
            .env("HTTP_ADDR", address.to_string())
            .env("DATABASE_URL", url)
            .env("APP_ORIGIN", format!("http://localhost:{}", address.port()))
            .env(
                "AUTH_ENCRYPTION_KEY",
                "KioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKio=",
            )
            .env("SMTP_ADDR", smtp)
            .env("SMTP_FROM", "tests@example.com")
            .env("SMTP_REQUIRE_TLS", "false")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut api = Self { child, base };
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if let Some(status) = api.child.try_wait().unwrap() {
                    panic!("api exited during startup: {status}");
                }
                if reqwest::get(format!("{}/health", api.base)).await.is_ok() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("API process startup");
        api
    }
    async fn stop(self) {
        let pid = self.child.id().unwrap();
        assert!(std::process::Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .status()
            .unwrap()
            .success());
        let output = tokio::time::timeout(Duration::from_secs(15), self.child.wait_with_output())
            .await
            .unwrap()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let log = String::from_utf8_lossy(&output.stdout);
        assert!(log.contains("api_shutdown_started"));
        assert!(log.contains("api_stopped"));
        assert!(!log.contains("postgres://") && !log.contains("Kioq"));
    }
}

#[tokio::test]
async fn api_process_serves_real_http_and_gracefully_stops_workers_and_idle_connections() {
    let app = App::new().await;
    let smtp = Smtp::start().await;
    let api = Api::start(app.postgres.connection_string(), &smtp.address).await;
    assert_eq!(
        reqwest::get(format!("{}/ready", api.base))
            .await
            .unwrap()
            .status(),
        200
    );
    let session: serde_json::Value = reqwest::get(format!("{}/api/v1/auth/session", api.base))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(session["state"], "anonymous");
    let address = api.base.strip_prefix("http://").unwrap();
    let mut idle = TcpStream::connect(address).await.unwrap();
    idle.write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let mut response = [0; 4096];
    assert!(idle.read(&mut response).await.unwrap() > 0);
    api.stop().await;
}

#[tokio::test]
async fn api_never_implicitly_migrates_a_fresh_database() {
    let postgres = TestPostgres::start().await.unwrap();
    let db = database(&postgres).await;
    let smtp = Smtp::start().await;
    let api = Api::start(postgres.connection_string(), &smtp.address).await;
    assert_eq!(
        reqwest::get(format!("{}/health", api.base))
            .await
            .unwrap()
            .status(),
        200
    );
    // Readiness proves connection availability, not installed schema parity.
    assert_eq!(
        reqwest::get(format!("{}/ready", api.base))
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        reqwest::get(format!("{}/api/v1/auth/session", api.base))
            .await
            .unwrap()
            .status(),
        503
    );
    let row = db
        .query_one(sea_orm::Statement::from_string(
            sea_orm::DbBackend::Postgres,
            "SELECT count(*)::bigint AS count FROM pg_tables WHERE schemaname='public'",
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.try_get::<i64>("", "count").unwrap(), 0);
    api.stop().await;
}

#[tokio::test]
async fn real_server_closes_stalled_request_headers_at_the_configured_deadline() {
    let app = App::new().await;
    let smtp = Smtp::start().await;
    let api = Api::start(app.postgres.connection_string(), &smtp.address).await;
    let mut socket = TcpStream::connect(api.base.strip_prefix("http://").unwrap())
        .await
        .unwrap();
    let start = Instant::now();
    socket
        .write_all(b"GET /health HTTP/1.1\r\nHost:")
        .await
        .unwrap();
    let mut buffer = [0; 128];
    let read = tokio::time::timeout(Duration::from_secs(8), socket.read(&mut buffer))
        .await
        .expect("header deadline must close stalled request");
    assert!(matches!(read, Ok(0) | Err(_)));
    assert!(start.elapsed() >= Duration::from_secs(4));
    api.stop().await;
}
