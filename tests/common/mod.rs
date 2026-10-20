#![allow(dead_code)]

use axum::{
    body::{to_bytes, Body},
    extract::ConnectInfo,
    http::Request,
    Router,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use foltivo_backend::{
    auth::{self, crypto, Service, Session},
    config::{connect, Config},
    http,
};
use foltivo_database::Migrator;
use foltivo_test_support::TestPostgres;
use sea_orm::{ConnectionTrait, DatabaseConnection};
use sea_orm_migration::MigratorTrait;
use serde_json::Value;
use std::{collections::HashMap, net::SocketAddr, time::Duration};
use tower::ServiceExt;

pub const PASSWORD: &str = "correct horse battery staple";
pub const NEXT_PASSWORD: &str = "a different correct long password";

pub struct App {
    pub service: Service,
    pub postgres: TestPostgres,
}

pub fn config(database_url: &str) -> Config {
    Config {
        http_addr: "127.0.0.1:0".into(),
        database_url: database_url.into(),
        environment: "test".into(),
        origin: "http://localhost:5173".into(),
        secure_cookies: false,
        trusted_proxies: vec![],
        encryption_key: STANDARD.encode([42; 32]),
        smtp_addr: "127.0.0.1:9".into(),
        smtp_from: "tests@example.com".into(),
        smtp_username: String::new(),
        smtp_password: String::new(),
        smtp_require_tls: false,
        providers: HashMap::new(),
    }
}

pub async fn database(postgres: &TestPostgres) -> DatabaseConnection {
    let db = connect(postgres.connection_string()).await.unwrap();
    // The fixture must be usable by SQL, not merely have emitted a startup log.
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if db.ping().await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("disposable PostgreSQL SQL readiness");
    db
}

impl App {
    pub async fn new() -> Self {
        let postgres = TestPostgres::start().await.expect("disposable PostgreSQL");
        let db = database(&postgres).await;
        Migrator::up(&db, None).await.unwrap();
        let service = Service::new(db, config(postgres.connection_string()))
            .await
            .unwrap();
        Self { service, postgres }
    }
    pub async fn sql(&self, sql: &str) {
        self.service.db.execute_unprepared(sql).await.unwrap();
    }
    pub async fn count(&self, sql: &str) -> i64 {
        auth::get(
            &auth::one(&self.service.db, sql, vec![]).await.unwrap(),
            "count",
        )
        .unwrap()
    }
    pub async fn anonymous(&self) -> Session {
        self.service.session("", "fixture", true).await.unwrap()
    }
    pub async fn login(&self, email: &str) -> Session {
        self.service
            .login(&self.anonymous().await, email, email, PASSWORD)
            .await
            .unwrap()
    }
    pub async fn register(&self, email: &str) {
        self.service
            .register(email, "Test Person", email, PASSWORD)
            .await
            .unwrap();
    }
    pub async fn verified(&self, email: &str) -> Session {
        self.register(email).await;
        let token = self.email_token(email, "verification").await;
        self.service
            .consume_email(&token, "verification", "")
            .await
            .unwrap();
        self.login(email).await
    }
    // Trusted fixture introspection: never exposed by the application API.
    pub async fn email_token(&self, email: &str, purpose: &str) -> String {
        let row = auth::one(&self.service.db,
            "SELECT o.payload FROM auth_email_outbox o JOIN auth_email_tokens t ON t.id=o.token_id JOIN users u ON u.id=t.user_id WHERE u.email=$1 AND t.purpose=$2 ORDER BY t.created_at DESC LIMIT 1",
            vec![email.into(), purpose.into()]).await.unwrap();
        let encrypted: Vec<u8> = auth::get(&row, "payload").unwrap();
        let bytes = self
            .service
            .secrets
            .open(&encrypted, "email-outbox/v1")
            .unwrap();
        let payload: Value = serde_json::from_slice(&bytes).unwrap();
        payload["Body"]
            .as_str()
            .unwrap()
            .split("#token=")
            .nth(1)
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap()
            .into()
    }
    pub fn browser(&self) -> Browser {
        Browser::new(self.service.clone())
    }
}

pub fn status<T>(result: auth::Result<T>, expected: u16) {
    match result {
        Ok(_) => panic!("expected error {expected}"),
        Err(e) => assert_eq!(e.status, expected, "{e:?}"),
    }
}

pub struct Browser {
    pub app: Router,
    pub cookie: String,
    pub csrf: String,
    pub remote: SocketAddr,
    pub origin: String,
}
pub struct Reply {
    pub status: u16,
    pub headers: axum::http::HeaderMap,
    pub body: Vec<u8>,
}
impl Reply {
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap()
    }
}
impl Browser {
    pub fn new(service: Service) -> Self {
        Self {
            app: http::router(service),
            cookie: String::new(),
            csrf: String::new(),
            remote: "127.0.0.1:12345".parse().unwrap(),
            origin: "http://localhost:5173".into(),
        }
    }
    pub fn use_session(&mut self, session: &Session) {
        self.cookie = format!("foltivo_session={}", session.token);
        self.csrf = crypto::csrf(&session.token);
    }
    pub async fn request(&mut self, method: &str, path: &str, body: &str) -> Reply {
        self.request_headers(method, path, body, &[]).await
    }
    pub async fn request_headers(
        &mut self,
        method: &str,
        path: &str,
        body: &str,
        headers: &[(&str, &str)],
    ) -> Reply {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json")
            .header("origin", &self.origin)
            .header("x-csrf-token", &self.csrf)
            .header("cookie", &self.cookie)
            .body(Body::from(body.to_owned()))
            .unwrap();
        for (name, value) in headers {
            request.headers_mut().insert(
                axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value.parse().unwrap(),
            );
        }
        request.extensions_mut().insert(ConnectInfo(self.remote));
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        if let Some(cookie) = headers.get("set-cookie") {
            self.cookie = cookie.to_str().unwrap().split(';').next().unwrap().into();
        }
        let body = to_bytes(response.into_body(), 1_000_000)
            .await
            .unwrap()
            .to_vec();
        if let Ok(json) = serde_json::from_slice::<Value>(&body) {
            if let Some(csrf) = json["csrfToken"].as_str() {
                self.csrf = csrf.into();
            }
        }
        Reply {
            status,
            headers,
            body,
        }
    }
}

use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpListener,
    task::{JoinHandle, JoinSet},
};

/// Minimal loopback SMTP peer. It implements protocol responses, not Mailer internals.
pub struct Smtp {
    pub address: String,
    pub messages: Arc<Mutex<Vec<String>>>,
    pub reject: Arc<AtomicBool>,
    pub stall: Arc<AtomicBool>,
    pub data_requests: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}
impl Smtp {
    pub async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let messages = Arc::new(Mutex::new(Vec::new()));
        let reject = Arc::new(AtomicBool::new(false));
        let output = messages.clone();
        let rejecting = reject.clone();
        let stall = Arc::new(AtomicBool::new(false));
        let stalling = stall.clone();
        let data_requests = Arc::new(AtomicUsize::new(0));
        let requested = data_requests.clone();
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    incoming=listener.accept()=> {
                        let Ok((socket,_))=incoming else {break};
                        connections.spawn(smtp_connection(socket,output.clone(),rejecting.clone(),stalling.clone(),requested.clone()));
                    },
                    Some(_)=connections.join_next(),if !connections.is_empty()=>{}
                }
            }
        });
        Self {
            address,
            messages,
            reject,
            stall,
            data_requests,
            task,
        }
    }
    pub fn install(&self, app: &mut App) {
        let mut cfg = (*app.service.config).clone();
        cfg.smtp_addr = self.address.clone();
        app.service.mailer = foltivo_backend::mailer::Mailer::new(&cfg).unwrap();
    }
}
async fn smtp_connection(
    socket: tokio::net::TcpStream,
    output: Arc<Mutex<Vec<String>>>,
    reject: Arc<AtomicBool>,
    stall: Arc<AtomicBool>,
    requests: Arc<AtomicUsize>,
) {
    let (reader, mut writer) = socket.into_split();
    let mut reader = BufReader::new(reader);
    if writer.write_all(b"220 localhost ESMTP\r\n").await.is_err() {
        return;
    }
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
            break;
        }
        let upper = line.to_ascii_uppercase();
        let reply: &[u8] = if upper.starts_with("EHLO") {
            b"250-localhost\r\n250 8BITMIME\r\n"
        } else if upper.starts_with("DATA") {
            requests.fetch_add(1, Ordering::SeqCst);
            if stall.load(Ordering::SeqCst) {
                std::future::pending::<()>().await;
            }
            if reject.load(Ordering::SeqCst) {
                b"451 temporary failure\r\n"
            } else {
                if writer.write_all(b"354 send message\r\n").await.is_err() {
                    break;
                }
                let mut body = String::new();
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                        return;
                    }
                    if line == ".\r\n" {
                        break;
                    }
                    body.push_str(&line);
                }
                output.lock().unwrap().push(body);
                b"250 accepted\r\n"
            }
        } else if upper.starts_with("QUIT") {
            let _ = writer.write_all(b"221 bye\r\n").await;
            break;
        } else {
            b"250 ok\r\n"
        };
        if writer.write_all(reply).await.is_err() {
            break;
        }
    }
}

impl Drop for Smtp {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub fn totp(secret: &str, step: i64) -> String {
    use hmac::{Hmac, Mac};
    let key = data_encoding::BASE32_NOPAD
        .decode(secret.as_bytes())
        .unwrap();
    let mut mac = <Hmac<sha1::Sha1> as Mac>::new_from_slice(&key).unwrap();
    mac.update(&(step as u64).to_be_bytes());
    let bytes = mac.finalize().into_bytes();
    let offset = (bytes[19] & 15) as usize;
    format!(
        "{:06}",
        (u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap()) & 0x7fffffff)
            % 1_000_000
    )
}
pub async fn enable_totp(app: &App, session: &Session) -> (Session, String, Vec<String>) {
    let enrollment = app.service.enroll_totp(session).await.unwrap();
    let secret = enrollment["secret"].as_str().unwrap().to_owned();
    let code = totp(&secret, chrono::Utc::now().timestamp() / 30);
    let codes = app
        .service
        .confirm_totp(session, "enroll", &code)
        .await
        .unwrap();
    let session = app.service.required_session(&session.token).await.unwrap();
    (session, secret, codes)
}

pub async fn wait_for_account_lock_waiters(app: &App, minimum: i64) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let count=app.count("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock'").await;
            if count>=minimum {break;}
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.expect("observe actual PostgreSQL lock contention");
}

pub struct Authenticator {
    child: tokio::process::Child,
    input: tokio::process::ChildStdin,
    output: tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
    pub origin: String,
}
impl Authenticator {
    pub async fn start() -> Self {
        let mut command = tokio::process::Command::new("node");
        command
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/authenticator.mjs"
            ))
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .kill_on_drop(true);
        #[cfg(unix)]
        command.process_group(0);
        let mut child = command
            .spawn()
            .expect("Node.js for Chromium virtual authenticator");
        let input = child.stdin.take().unwrap();
        let output = BufReader::new(child.stdout.take().unwrap()).lines();
        let mut authenticator = Self {
            child,
            input,
            output,
            origin: String::new(),
        };
        let hello = tokio::time::timeout(Duration::from_secs(20), authenticator.output.next_line())
            .await
            .unwrap()
            .unwrap()
            .expect("Chromium fixture startup");
        let hello: Value = serde_json::from_str(&hello).unwrap();
        authenticator.origin = hello["origin"].as_str().unwrap().into();
        authenticator
    }
    pub async fn command(&mut self, action: &str, options: Value) -> Value {
        let line = serde_json::json!({"action":action,"options":options}).to_string() + "\n";
        self.input.write_all(line.as_bytes()).await.unwrap();
        let output = tokio::time::timeout(Duration::from_secs(10), self.output.next_line())
            .await
            .unwrap()
            .unwrap()
            .expect("authenticator reply");
        let result: Value = serde_json::from_str(&output).unwrap();
        assert!(result.get("error").is_none(), "{result}");
        result
    }
    pub async fn close(mut self) {
        self.command("close", Value::Null).await;
        tokio::time::timeout(Duration::from_secs(10), self.child.wait())
            .await
            .expect("authenticator shutdown")
            .unwrap();
    }
}
impl Drop for Authenticator {
    fn drop(&mut self) {
        #[cfg(unix)]
        if let Some(pid) = self.child.id() {
            // The spawned fixture owns this process group, including Chromium.
            let _ = std::process::Command::new("kill")
                .args(["-TERM", "--", &format!("-{pid}")])
                .status();
        }
    }
}

pub struct TempDirectory(std::path::PathBuf);
impl TempDirectory {
    pub fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!("foltivo-{label}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    pub fn path(&self) -> &std::path::Path {
        &self.0
    }
}
impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[rstest::fixture]
pub async fn app() -> App {
    App::new().await
}
