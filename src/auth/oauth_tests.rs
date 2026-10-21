use super::*;
use crate::{
    config::Provider,
    test_common::{enable_totp, status, App},
};
use axum::{
    body::to_bytes,
    extract::{Request, State},
    http::StatusCode,
    response::IntoResponse,
    Router,
};
use openssl::rsa::Rsa;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

#[derive(Default)]
struct Peer {
    replies: Mutex<HashMap<String, (u16, Json)>>,
    requests: Mutex<Vec<(String, String)>>,
}
struct ProviderDouble {
    peer: Arc<Peer>,
    task: tokio::task::JoinHandle<()>,
    pem: Vec<u8>,
}
impl Drop for ProviderDouble {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn endpoint(State(peer): State<Arc<Peer>>, request: Request) -> impl IntoResponse {
    let path = request.uri().path().to_owned();
    let bytes = to_bytes(request.into_body(), 100_000).await.unwrap();
    peer.requests
        .lock()
        .unwrap()
        .push((path.clone(), String::from_utf8_lossy(&bytes).into()));
    let (status, body) = peer
        .replies
        .lock()
        .unwrap()
        .get(&path)
        .cloned()
        .unwrap_or((404, json!({})));
    (StatusCode::from_u16(status).unwrap(), axum::Json(body))
}
impl ProviderDouble {
    async fn install(app: &mut App) -> Self {
        let rsa = Rsa::generate(2048).unwrap();
        let pem = rsa.private_key_to_pem().unwrap();
        let peer = Arc::new(Peer::default());
        peer.replies.lock().unwrap().extend([
            ("/github/token".into(),(200,json!({"access_token":"fixture-access"}))),
            ("/github/user".into(),(200,json!({"id":12345,"login":"mutable-name","email":"untrusted@example.com"}))),
            ("/google/discovery".into(),(200,json!({"issuer":"https://accounts.google.com","jwks_uri":"https://accounts.google.com/fixture-jwks"}))),
            ("/google/jwks".into(),(200,json!({"keys":[{"kty":"RSA","kid":"fixture-key","alg":"RS256","use":"sig","n":URL_SAFE_NO_PAD.encode(rsa.n().to_vec()),"e":URL_SAFE_NO_PAD.encode(rsa.e().to_vec())}]}))),
        ]);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let router = Router::new().fallback(endpoint).with_state(peer.clone());
        let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        app.service.oauth_test_endpoints = Some(Arc::new(
            [
                (
                    "https://github.com/login/oauth/access_token",
                    "/github/token",
                ),
                ("https://api.github.com/user", "/github/user"),
                ("https://oauth2.googleapis.com/token", "/google/token"),
                (
                    "https://accounts.google.com/.well-known/openid-configuration",
                    "/google/discovery",
                ),
                ("https://accounts.google.com/fixture-jwks", "/google/jwks"),
            ]
            .into_iter()
            .map(|(url, path)| (url.into(), format!("{base}{path}")))
            .collect(),
        ));
        let cfg = Arc::make_mut(&mut app.service.config);
        for provider in ["github", "google"] {
            cfg.providers.insert(
                provider.into(),
                Provider {
                    client_id: "fixture-client".into(),
                    client_secret: "fixture-secret".into(),
                    redirect_url: format!(
                        "http://localhost:5173/api/v1/auth/providers/{provider}/callback"
                    ),
                },
            );
        }
        Self { peer, task, pem }
    }
    fn set(&self, path: &str, status: u16, body: Json) {
        self.peer
            .replies
            .lock()
            .unwrap()
            .insert(path.into(), (status, body));
    }
    fn google(&self, nonce: &str, mutate: impl FnOnce(&mut Json)) {
        let mut claims = json!({"sub":"google-immutable-subject","nonce":nonce,"aud":"fixture-client","iss":"https://accounts.google.com","exp":Utc::now().timestamp()+300});
        mutate(&mut claims);
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some("fixture-key".into());
        let token = jsonwebtoken::encode(
            &header,
            &claims,
            &jsonwebtoken::EncodingKey::from_rsa_pem(&self.pem).unwrap(),
        )
        .unwrap();
        self.set("/google/token", 200, json!({"id_token":token}));
    }
}
fn params(url: &str) -> HashMap<String, String> {
    url::Url::parse(url)
        .unwrap()
        .query_pairs()
        .into_owned()
        .collect()
}

#[tokio::test]
async fn github_link_login_coordinated_completion_pkce_immutable_subject_and_unlink() {
    let mut app = App::new().await;
    let double = ProviderDouble::install(&mut app).await;
    let alice = app.verified("alice@example.com").await;
    let url = app
        .service
        .begin_oauth(&alice, "provider", "github", "link")
        .await
        .unwrap();
    let p = params(&url);
    assert_eq!(p["code_challenge_method"], "S256");
    assert_eq!(p["response_type"], "code");
    let result = app
        .service
        .finish_oauth(&alice, "provider", "github", &p["state"], "fixture-code")
        .await
        .unwrap();
    assert_eq!(result.operation, "link");
    assert!(result.grant.is_empty());
    assert!(app.service.providers(&alice).await.unwrap()[0]["linked"]
        .as_bool()
        .unwrap());
    let requests = double.peer.requests.lock().unwrap().clone();
    let form: HashMap<_, _> = url::form_urlencoded::parse(
        requests
            .iter()
            .find(|(p, _)| p == "/github/token")
            .unwrap()
            .1
            .as_bytes(),
    )
    .into_owned()
    .collect();
    assert_eq!(
        URL_SAFE_NO_PAD.encode(crypto::hash(&form["code_verifier"])),
        p["code_challenge"]
    );
    assert_eq!(form["code"], "fixture-code");
    assert_eq!(
        form["redirect_uri"],
        "http://localhost:5173/api/v1/auth/providers/github/callback"
    );
    status(
        app.service
            .finish_oauth(&alice, "provider", "github", &p["state"], "fixture-code")
            .await,
        400,
    );
    double.set(
        "/github/user",
        200,
        json!({"id":12345,"login":"renamed","email":"different@example.com"}),
    );
    let anon = app.anonymous().await;
    let p = params(
        &app.service
            .begin_oauth(&anon, "provider", "github", "login")
            .await
            .unwrap(),
    );
    let grant = app
        .service
        .finish_oauth(&anon, "provider", "github", &p["state"], "fixture-code")
        .await
        .unwrap();
    assert_eq!(
        app.service
            .required_session(&anon.token)
            .await
            .unwrap()
            .state,
        "anonymous"
    );
    status(
        app.service
            .complete_oauth(&app.anonymous().await, "provider", &grant.grant)
            .await,
        400,
    );
    let current = app
        .service
        .complete_oauth(&anon, "provider", &grant.grant)
        .await
        .unwrap();
    assert_eq!(current.user_id().unwrap(), alice.user_id().unwrap());
    assert_eq!(current.state, "authenticated");
    status(
        app.service
            .complete_oauth(&anon, "provider", &grant.grant)
            .await,
        400,
    );
    status(
        app.service
            .complete_oauth(&current, "provider", &grant.grant)
            .await,
        409,
    );
    app.service.unlink_oauth(&current, "github").await.unwrap();
    assert_eq!(
        app.service.providers(&current).await.unwrap()[0]["linked"],
        false
    );
    assert_eq!(app.login("alice@example.com").await.state, "authenticated");
}

#[rstest::rstest]
#[case("nonce")]
#[case("issuer")]
#[case("audience")]
#[case("expiry")]
#[case("signature")]
#[case("subject")]
#[tokio::test]
async fn google_rejects_signed_or_tampered_identity_with_wrong_claims(#[case] invalid: &str) {
    let mut app = App::new().await;
    let double = ProviderDouble::install(&mut app).await;
    let alice = app.verified("alice@example.com").await;
    let p = params(
        &app.service
            .begin_oauth(&alice, "google", "google", "link")
            .await
            .unwrap(),
    );
    double.google(&p["nonce"], |claims| match invalid {
        "nonce" => claims["nonce"] = json!("other"),
        "issuer" => claims["iss"] = json!("https://evil.example"),
        "audience" => claims["aud"] = json!("different-client"),
        "expiry" => claims["exp"] = json!(Utc::now().timestamp() - 10),
        "subject" => claims["sub"] = json!(""),
        _ => {}
    });
    if invalid == "signature" {
        let mut replies = double.peer.replies.lock().unwrap();
        let (_, body) = replies.get_mut("/google/token").unwrap();
        let token = body["id_token"].as_str().unwrap();
        let mut pieces: Vec<_> = token.split('.').map(str::to_owned).collect();
        let mut signature = URL_SAFE_NO_PAD.decode(&pieces[2]).unwrap();
        signature[0] ^= 1;
        pieces[2] = URL_SAFE_NO_PAD.encode(signature);
        body["id_token"] = json!(pieces.join("."));
    }
    assert!(app
        .service
        .finish_oauth(&alice, "google", "google", &p["state"], "fixture-code")
        .await
        .is_err());
    assert_eq!(
        app.count("SELECT count(*) FROM auth_oauth_identities")
            .await,
        0
    );
    assert_eq!(
        app.count("SELECT count(*) FROM auth_oauth_states WHERE consumed_at IS NOT NULL")
            .await,
        1
    );
}

#[tokio::test]
async fn google_success_preserves_mfa_and_unlink_invalidates_pending_completion() {
    let mut app = App::new().await;
    let double = ProviderDouble::install(&mut app).await;
    let alice = app.verified("alice@example.com").await;
    let p = params(
        &app.service
            .begin_oauth(&alice, "google", "google", "link")
            .await
            .unwrap(),
    );
    double.google(&p["nonce"], |_| {});
    app.service
        .finish_oauth(&alice, "google", "google", &p["state"], "fixture-code")
        .await
        .unwrap();
    let (current, _, _) = enable_totp(&app, &alice).await;
    let anon = app.anonymous().await;
    let p = params(
        &app.service
            .begin_oauth(&anon, "google", "google", "login")
            .await
            .unwrap(),
    );
    double.google(&p["nonce"], |_| {});
    let grant = app
        .service
        .finish_oauth(&anon, "google", "google", &p["state"], "fixture-code")
        .await
        .unwrap();
    let pending = app
        .service
        .complete_oauth(&anon, "google", &grant.grant)
        .await
        .unwrap();
    assert_eq!(pending.state, "mfa_required");
    let anon = app.anonymous().await;
    let p = params(
        &app.service
            .begin_oauth(&anon, "google", "google", "login")
            .await
            .unwrap(),
    );
    double.google(&p["nonce"], |_| {});
    let grant = app
        .service
        .finish_oauth(&anon, "google", "google", &p["state"], "fixture-code")
        .await
        .unwrap();
    app.service.unlink_oauth(&current, "google").await.unwrap();
    status(
        app.service
            .complete_oauth(&anon, "google", &grant.grant)
            .await,
        400,
    );
}

#[tokio::test]
async fn state_browser_expiry_provider_failure_and_partial_visibility_fail_closed() {
    let mut app = App::new().await;
    let double = ProviderDouble::install(&mut app).await;
    app.register("partial@example.com").await;
    let partial = app.login("partial@example.com").await;
    status(app.service.providers(&partial).await, 403);
    let anon = app.anonymous().await;
    let wrong_browser = app.anonymous().await;
    assert!(app
        .service
        .providers(&anon)
        .await
        .unwrap()
        .iter()
        .all(|p| p["linked"] == false));
    let p = params(
        &app.service
            .begin_oauth(&anon, "provider", "github", "login")
            .await
            .unwrap(),
    );
    status(
        app.service
            .finish_oauth(
                &wrong_browser,
                "provider",
                "github",
                &p["state"],
                "fixture-code",
            )
            .await,
        400,
    );
    assert_eq!(
        app.count("SELECT count(*) FROM auth_oauth_states WHERE consumed_at IS NULL")
            .await,
        1
    );
    app.sql("UPDATE auth_oauth_states SET expires_at=now()-interval '1 second'")
        .await;
    status(
        app.service
            .finish_oauth(&anon, "provider", "github", &p["state"], "fixture-code")
            .await,
        400,
    );
    let p = params(
        &app.service
            .begin_oauth(&anon, "provider", "github", "login")
            .await
            .unwrap(),
    );
    double.set(
        "/github/token",
        500,
        json!({"sensitive":"provider failure details"}),
    );
    let error = app
        .service
        .finish_oauth(&anon, "provider", "github", &p["state"], "fixture-code")
        .await
        .err()
        .unwrap();
    assert!(!error.message.contains("sensitive"));
    assert_eq!(app.count("SELECT count(*) FROM auth_oauth_grants").await, 0);
    status(
        app.service
            .finish_oauth(&anon, "provider", "github", &p["state"], "fixture-code")
            .await,
        400,
    );
}

#[rstest::rstest]
#[case(200, "not json")]
#[case(200, "oversized")]
#[case(302, "{}")]
#[case(500, "{}")]
#[tokio::test]
async fn provider_transport_rejects_invalid_oversized_and_unsuccessful_responses(
    #[case] status: u16,
    #[case] body: &str,
) {
    let body = if body == "oversized" {
        "x".repeat(65537)
    } else {
        body.into()
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let route = Router::new().fallback(move || {
        let body = body.clone();
        async move { (StatusCode::from_u16(status).unwrap(), body) }
    });
    let server = tokio::spawn(async move { axum::serve(listener, route).await.unwrap() });
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let response = client
        .get(format!("http://{address}"))
        .send()
        .await
        .unwrap();
    assert!(bounded_json(response).await.is_err());
    server.abort();
}

#[tokio::test]
async fn identities_cannot_be_stolen_and_expired_or_stale_grants_cannot_rotate_the_browser() {
    let mut app = App::new().await;
    let _double = ProviderDouble::install(&mut app).await;
    let alice = app.verified("alice@example.com").await;
    let bob = app.verified("bob@example.com").await;
    let p = params(
        &app.service
            .begin_oauth(&alice, "identity", "github", "link")
            .await
            .unwrap(),
    );
    app.service
        .finish_oauth(&alice, "identity", "github", &p["state"], "code")
        .await
        .unwrap();
    let p = params(
        &app.service
            .begin_oauth(&bob, "identity", "github", "link")
            .await
            .unwrap(),
    );
    status(
        app.service
            .finish_oauth(&bob, "identity", "github", &p["state"], "code")
            .await,
        409,
    );
    for invalid in ["expired", "version"] {
        let anon = app.anonymous().await;
        let p = params(
            &app.service
                .begin_oauth(&anon, "identity", "github", "login")
                .await
                .unwrap(),
        );
        let grant = app
            .service
            .finish_oauth(&anon, "identity", "github", &p["state"], "code")
            .await
            .unwrap();
        if invalid == "expired" {
            app.sql("UPDATE auth_oauth_grants SET expires_at=now()-interval '1 second'")
                .await;
        } else {
            app.sql(&format!(
                "UPDATE users SET security_version=security_version+1 WHERE id='{}'",
                alice.user_id().unwrap()
            ))
            .await;
        }
        status(
            app.service
                .complete_oauth(&anon, "identity", &grant.grant)
                .await,
            400,
        );
        assert_eq!(
            app.service
                .required_session(&anon.token)
                .await
                .unwrap()
                .state,
            "anonymous"
        );
    }
}
