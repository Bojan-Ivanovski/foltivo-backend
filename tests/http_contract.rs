mod common;
use common::{App, PASSWORD};
use serde_json::json;

#[tokio::test]
async fn browser_contract_bootstrap_csrf_registration_partial_auth_and_logout() {
    let app = App::new().await;
    let mut browser = app.browser();
    assert_eq!(browser.request("GET", "/api/v1/me", "").await.status, 401);
    let boot = browser.request("GET", "/api/v1/auth/session", "").await;
    assert_eq!(boot.status, 200);
    assert_eq!(boot.json()["state"], "anonymous");
    assert_eq!(
        boot.json()["methods"],
        json!({"password":true,"totp":true,"passkey":true})
    );
    let cookie = boot.headers["set-cookie"].to_str().unwrap();
    assert!(
        cookie.contains("HttpOnly") && cookie.contains("SameSite=Lax") && cookie.contains("Path=/")
    );
    assert!(!cookie.contains("Domain=") && !cookie.contains("Secure"));
    assert!(browser
        .request("GET", "/api/v1/auth/session", "")
        .await
        .headers
        .get("set-cookie")
        .is_none());
    let csrf = browser.csrf.clone();
    browser.csrf = "invalid".into();
    assert_eq!(
        browser
            .request("POST", "/api/v1/auth/login", "{}")
            .await
            .status,
        403
    );
    browser.csrf = csrf;
    let registration =
        json!({"name":"Alice","email":"alice@example.com","password":PASSWORD}).to_string();
    let one = browser
        .request("POST", "/api/v1/auth/register", &registration)
        .await;
    let two = browser
        .request("POST", "/api/v1/auth/register", &registration)
        .await;
    assert_eq!(one.status, 202);
    assert_eq!(one.body, two.body);
    let login = json!({"email":"alice@example.com","password":PASSWORD}).to_string();
    let partial = browser.request("POST", "/api/v1/auth/login", &login).await;
    assert_eq!(partial.status, 200);
    assert_eq!(partial.json()["state"], "verification_required");
    assert_eq!(browser.request("GET", "/api/v1/me", "").await.status, 403);
    assert_eq!(
        browser
            .request("POST", "/api/v1/auth/register", &registration)
            .await
            .status,
        409
    );
    let token = app.email_token("alice@example.com", "verification").await;
    assert_eq!(
        browser
            .request(
                "POST",
                "/api/v1/auth/verification/confirm",
                &json!({"token":token}).to_string()
            )
            .await
            .status,
        200
    );
    assert_eq!(
        browser
            .request("GET", "/api/v1/auth/session", "")
            .await
            .json()["state"],
        "anonymous"
    );
    assert_eq!(
        browser
            .request("POST", "/api/v1/auth/login", &login)
            .await
            .json()["state"],
        "authenticated"
    );
    let me = browser.request("GET", "/api/v1/me", "").await;
    assert_eq!(me.status, 200);
    assert!(me.json()["user"]["libraryId"].is_string());
    assert!(me.json()["user"].get("passwordHash").is_none());
    let old_cookie = browser.cookie.clone();
    assert_eq!(
        browser
            .request("POST", "/api/v1/auth/logout", "{}")
            .await
            .json()["state"],
        "anonymous"
    );
    assert_ne!(old_cookie, browser.cookie);
    browser.cookie = old_cookie;
    assert_eq!(browser.request("GET", "/api/v1/me", "").await.status, 401);
}

#[tokio::test]
async fn strict_json_media_limits_methods_and_response_headers() {
    let app = App::new().await;
    let mut browser = app.browser();
    browser.request("GET", "/api/v1/auth/session", "").await;
    for body in [
        "",
        "null",
        "[]",
        "{} {}",
        "{\"email\":null}",
        "{\"email\":false}",
        "{\"email\":\"a\",\"email\":\"b\"}",
        "{\"unexpected\":\"field\"}",
        "{\"password\":{}}",
    ] {
        let r = browser.request("POST", "/api/v1/auth/register", body).await;
        assert_eq!(r.status, 400, "{body}");
        assert_eq!(r.headers["cache-control"], "no-store");
        assert_eq!(r.headers["x-content-type-options"], "nosniff");
        assert!(r.json()["error"]["code"].is_string());
    }
    let oversized = json!({"name":"a".repeat(16*1024)}).to_string();
    assert_eq!(
        browser
            .request("POST", "/api/v1/auth/register", &oversized)
            .await
            .status,
        400
    );
    assert_eq!(
        browser
            .request_headers(
                "POST",
                "/api/v1/auth/register",
                "{}",
                &[("content-type", "text/plain")]
            )
            .await
            .status,
        400
    );
    let method = browser.request("PUT", "/api/v1/auth/session", "").await;
    assert_eq!(method.status, 405);
    assert!(method.headers["allow"].to_str().unwrap().contains("HEAD"));
    assert_eq!(
        browser.request("GET", "/api/v1/unknown", "").await.status,
        404
    );
    let head = browser.request("HEAD", "/api/v1/auth/session", "").await;
    assert_eq!(head.status, 200);
    assert!(head.body.is_empty());
    for path in ["/health", "/ready"] {
        assert_eq!(browser.request("GET", path, "").await.status, 200);
        assert!(browser.request("HEAD", path, "").await.body.is_empty());
    }
}

#[tokio::test]
async fn origin_is_rejected_before_database_and_errors_are_safe() {
    let app = App::new().await;
    let mut browser = app.browser();
    app.service.db.clone().close().await.unwrap();
    browser.origin = "https://evil.example".into();
    let error = browser.request("POST", "/api/v1/auth/login", "{}").await;
    assert_eq!(error.status, 403);
    assert_eq!(error.json()["error"]["code"], "origin_rejected");
    assert_eq!(browser.request("GET", "/health", "").await.status, 200);
    assert_eq!(browser.request("GET", "/ready", "").await.status, 503);
    let error = browser.request("GET", "/api/v1/auth/session", "").await;
    assert_eq!(error.status, 503);
    let body = String::from_utf8(error.body).unwrap();
    for private in ["postgres://", "foltivo_test", "SELECT", "password", "sqlx"] {
        assert!(!body.contains(private));
    }
}

#[tokio::test]
async fn delete_operations_have_no_body_and_session_metadata_is_display_only() {
    let app = App::new().await;
    let alice = app.verified("alice@example.com").await;
    let other = app.login("alice@example.com").await;
    let mut browser = app.browser();
    browser.use_session(&alice);
    let reply = browser
        .request_headers(
            "GET",
            "/api/v1/auth/sessions",
            "",
            &[("user-agent", "Browser display metadata")],
        )
        .await;
    assert_eq!(reply.status, 200);
    assert!(reply.json()["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s["userAgent"] == "Browser display metadata"));
    assert_eq!(
        browser
            .request("DELETE", "/api/v1/auth/sessions/others", "")
            .await
            .json()["revokedCount"],
        1
    );
    assert_eq!(
        browser
            .request("DELETE", &format!("/api/v1/auth/sessions/{}", other.id), "")
            .await
            .status,
        404
    );
    let reply = browser
        .request("DELETE", &format!("/api/v1/auth/sessions/{}", alice.id), "")
        .await;
    assert_eq!(reply.status, 200);
    assert!(reply.headers["set-cookie"]
        .to_str()
        .unwrap()
        .contains("Max-Age=0"));
}

#[tokio::test]
async fn protected_route_matrix_rejects_anonymous_and_partially_verified_sessions() {
    let app = App::new().await;
    app.register("partial@example.com").await;
    let partial = app.login("partial@example.com").await;
    let routes = [
        ("GET", "/api/v1/me", ""),
        ("PATCH", "/api/v1/auth/profile", r#"{"name":"New"}"#),
        ("GET", "/api/v1/auth/sessions", ""),
        ("DELETE", "/api/v1/auth/sessions/others", ""),
        (
            "POST",
            "/api/v1/auth/reauthenticate",
            r#"{"password":"correct horse battery staple"}"#,
        ),
        (
            "POST",
            "/api/v1/auth/password/change",
            r#"{"currentPassword":"correct horse battery staple","password":"another sufficiently long password"}"#,
        ),
        ("POST", "/api/v1/auth/totp/enroll", "{}"),
        ("POST", "/api/v1/auth/totp/confirm", r#"{"code":"123456"}"#),
        (
            "POST",
            "/api/v1/auth/totp/remove",
            r#"{"password":"correct horse battery staple","code":"123456"}"#,
        ),
        (
            "POST",
            "/api/v1/auth/recovery-codes/regenerate",
            r#"{"password":"correct horse battery staple","code":"123456"}"#,
        ),
        ("GET", "/api/v1/auth/security", ""),
        (
            "POST",
            "/api/v1/auth/passkeys/register/begin",
            r#"{"name":"Device"}"#,
        ),
        (
            "DELETE",
            "/api/v1/auth/passkeys/96b7ebce-b93a-4c81-8d98-cc650679ddc5",
            "",
        ),
        ("GET", "/api/v1/auth/email-change", ""),
        (
            "POST",
            "/api/v1/auth/email-change",
            r#"{"email":"new@example.com"}"#,
        ),
        ("DELETE", "/api/v1/auth/email-change", ""),
        (
            "POST",
            "/api/v1/auth/email-change/confirm",
            r#"{"token":"invalid"}"#,
        ),
        ("GET", "/api/v1/auth/account-closure", ""),
        ("POST", "/api/v1/auth/account-closure", "{}"),
        ("DELETE", "/api/v1/auth/providers/github", ""),
    ];
    let mut anon = app.browser();
    anon.request("GET", "/api/v1/auth/session", "").await;
    let mut pending = app.browser();
    pending.use_session(&partial);
    for (method, path, body) in routes {
        assert_eq!(
            anon.request(method, path, body).await.status,
            401,
            "anonymous {method} {path}"
        );
        assert_eq!(
            pending.request(method, path, body).await.status,
            403,
            "partial {method} {path}"
        );
    }
}
