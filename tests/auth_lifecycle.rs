mod common;
use common::{app, status, App, NEXT_PASSWORD, PASSWORD};
use foltivo_backend::auth::{self, crypto, get, one};
use rstest::rstest;

#[rstest]
#[tokio::test]
async fn registration_verification_login_profile_and_session_lifecycle(#[future] app: App) {
    let app = app.await;
    app.register("Alice@EXAMPLE.com").await;
    app.register("alice@example.com").await;
    assert_eq!(app.count("SELECT count(*) FROM users").await, 1);
    assert_eq!(app.count("SELECT count(*) FROM libraries").await, 1);
    let anon = app.anonymous().await;
    assert_eq!(anon.state, "anonymous");
    let pending = app
        .service
        .login(&anon, "peer", "alice@example.com", PASSWORD)
        .await
        .unwrap();
    assert_eq!(pending.state, "verification_required");
    assert_ne!(anon.token, pending.token);
    status(pending.authenticated(), 403);
    status(app.service.profile(&pending, "Forged").await, 403);
    status(app.service.session(&anon.token, "test", false).await, 401);
    let stored: Vec<u8> = get(
        &one(
            &app.service.db,
            "SELECT token_hash FROM auth_sessions WHERE id=$1",
            vec![auth::uid(&pending.id)],
        )
        .await
        .unwrap(),
        "token_hash",
    )
    .unwrap();
    assert_eq!(stored, crypto::hash(&pending.token));
    assert_ne!(stored, pending.token.as_bytes());
    let token = app.email_token("alice@example.com", "verification").await;
    app.service
        .consume_email(&token, "verification", "")
        .await
        .unwrap();
    status(
        app.service.consume_email(&token, "verification", "").await,
        400,
    );
    status(
        app.service.session(&pending.token, "test", false).await,
        401,
    );
    let mut current = app.login("alice@example.com").await;
    assert_eq!(current.state, "authenticated");
    assert!(current.user.as_ref().unwrap().email_verified);
    let restarted = auth::Service::new(app.service.db.clone(), (*app.service.config).clone())
        .await
        .unwrap();
    assert_eq!(
        restarted.required_session(&current.token).await.unwrap().id,
        current.id
    );
    app.service
        .reauthenticate(&mut current, "peer", PASSWORD, "")
        .await
        .unwrap();
    current = app.service.required_session(&current.token).await.unwrap();
    current.recent().unwrap();
    assert_eq!(
        app.service
            .profile(&current, "  Updated name  ")
            .await
            .unwrap()
            .name,
        "Updated name"
    );
    let other = app.login("alice@example.com").await;
    app.service
        .observe_session(&other, "Browser α")
        .await
        .unwrap();
    let sessions = app.service.sessions(&current).await.unwrap();
    assert_eq!(sessions.len(), 2);
    assert!(sessions.iter().any(|s| s["current"] == true));
    assert!(sessions
        .iter()
        .any(|s| s["userAgent"] == "Browser α" && s["lastSeenAt"].is_string()));
    assert_eq!(app.service.revoke_others(&current).await.unwrap(), 1);
    status(app.service.session(&other.token, "test", false).await, 401);
    let other = app.login("alice@example.com").await;
    app.service.revoke(&current, &other.id).await.unwrap();
    status(app.service.session(&other.token, "test", false).await, 401);
    let next = app.service.rotate(&current, None).await.unwrap();
    assert_eq!(next.state, "anonymous");
    assert_ne!(next.token, current.token);
    status(app.service.profile(&current, "Stale").await, 409);
    status(app.service.revoke(&current, &current.id).await, 404);
}

#[tokio::test]
async fn independent_library_ownership_expiry_security_versions_and_recent_auth() {
    let app = App::new().await;
    let alice = app.verified("alice@example.com").await;
    let bob = app.verified("bob@example.com").await;
    assert_ne!(
        alice.user.as_ref().unwrap().library_id,
        bob.user.as_ref().unwrap().library_id
    );
    status(app.service.revoke(&alice, &bob.id).await, 404);
    assert_eq!(
        app.service.required_session(&bob.token).await.unwrap().id,
        bob.id
    );
    app.sql(&format!(
        "UPDATE auth_sessions SET recent_auth_at=now()-interval '6 minutes' WHERE id='{}'",
        alice.id
    ))
    .await;
    let old = app.service.required_session(&alice.token).await.unwrap();
    status(old.recent(), 403);
    status(app.service.enroll_totp(&old).await, 403);
    // A stale object must also fail the persisted under-lock assurance check.
    status(app.service.enroll_totp(&alice).await, 409);
    app.sql(&format!(
        "UPDATE users SET security_version=security_version+1 WHERE id='{}'",
        bob.user_id().unwrap()
    ))
    .await;
    status(app.service.session(&bob.token, "test", false).await, 401);
    status(app.service.profile(&bob, "Stale").await, 409);
    app.sql(&format!(
        "UPDATE auth_sessions SET expires_at=now()-interval '1 second' WHERE id='{}'",
        alice.id
    ))
    .await;
    status(app.service.session(&alice.token, "test", false).await, 401);
    let boot = app
        .service
        .session(&alice.token, "expiry", true)
        .await
        .unwrap();
    assert_eq!(boot.state, "anonymous");
    assert_ne!(boot.token, alice.token);
}

#[tokio::test]
async fn password_reset_and_change_are_single_use_and_revoke_all_sessions() {
    let app = App::new().await;
    let alice = app.verified("alice@example.com").await;
    app.service
        .request_email("reset", "alice@example.com", "reset")
        .await
        .unwrap();
    let old = app.email_token("alice@example.com", "reset").await;
    app.service
        .request_email("reset", "alice@example.com", "reset")
        .await
        .unwrap();
    let token = app.email_token("alice@example.com", "reset").await;
    status(
        app.service
            .consume_email(&old, "reset", NEXT_PASSWORD)
            .await,
        400,
    );
    status(
        app.service.consume_email(&token, "verification", "").await,
        400,
    );
    app.service
        .consume_email(&token, "reset", NEXT_PASSWORD)
        .await
        .unwrap();
    status(
        app.service
            .consume_email(&token, "reset", NEXT_PASSWORD)
            .await,
        400,
    );
    status(app.service.session(&alice.token, "test", false).await, 401);
    let anon = app.anonymous().await;
    status(
        app.service
            .login(&anon, "old", "alice@example.com", PASSWORD)
            .await,
        401,
    );
    let mut fresh = app
        .service
        .login(&anon, "new", "alice@example.com", NEXT_PASSWORD)
        .await
        .unwrap();
    app.service
        .change_password(&mut fresh, "change", NEXT_PASSWORD, PASSWORD, "")
        .await
        .unwrap();
    status(app.service.session(&fresh.token, "test", false).await, 401);
    assert_eq!(app.login("alice@example.com").await.state, "authenticated");
    app.service
        .request_email("expire", "alice@example.com", "reset")
        .await
        .unwrap();
    let token = app.email_token("alice@example.com", "reset").await;
    app.sql(
        "UPDATE auth_email_tokens SET expires_at=now()-interval '1 second' WHERE purpose='reset'",
    )
    .await;
    status(
        app.service
            .consume_email(&token, "reset", NEXT_PASSWORD)
            .await,
        400,
    );
}

#[tokio::test]
async fn throttle_is_persisted_and_expires_independently_of_service_restart() {
    let app = App::new().await;
    for _ in 0..3 {
        app.service.throttle("same-subject", 3).await.unwrap();
    }
    let restarted = auth::Service::new(app.service.db.clone(), (*app.service.config).clone())
        .await
        .unwrap();
    let error = restarted.throttle("same-subject", 3).await.unwrap_err();
    assert_eq!(error.status, 429);
    assert!(error.retry_after > 0 && error.retry_after <= 900);
    restarted.throttle("other-subject", 3).await.unwrap();
    app.sql("UPDATE auth_throttles SET resets_at=now()-interval '1 second'")
        .await;
    restarted.throttle("same-subject", 3).await.unwrap();
}

#[rstest]
#[case("verification")]
#[case("reset")]
#[tokio::test]
async fn email_requests_do_not_enumerate_unknown_accounts(#[case] purpose: &str) {
    let app = App::new().await;
    app.service
        .request_email("unknown", "unknown@example.com", purpose)
        .await
        .unwrap();
    assert_eq!(app.count("SELECT count(*) FROM auth_email_outbox").await, 0);
}
