mod common;
use common::{enable_totp, status, totp, App, NEXT_PASSWORD, PASSWORD};

#[tokio::test]
async fn totp_activation_replay_recovery_rotation_regeneration_and_removal() {
    let app = App::new().await;
    let alice = app.verified("alice@example.com").await;
    let other = app.login("alice@example.com").await;
    let (current, secret, codes) = enable_totp(&app, &alice).await;
    assert_eq!(codes.len(), 10);
    assert_eq!(
        app.service.security(&current).await.unwrap()["recoveryCodesRemaining"],
        10
    );
    status(app.service.session(&other.token, "test", false).await, 401);
    let pending = app.login("alice@example.com").await;
    assert_eq!(pending.state, "mfa_required");
    status(app.service.profile(&pending, "forged").await, 403);
    status(
        app.service
            .challenge(&pending, "factor", "000000", &codes[0])
            .await,
        400,
    );
    let replay = totp(&secret, chrono::Utc::now().timestamp() / 30);
    status(
        app.service.challenge(&pending, "factor", &replay, "").await,
        401,
    );
    let authenticated = app
        .service
        .challenge(&pending, "factor", "", &codes[0])
        .await
        .unwrap();
    assert_eq!(authenticated.state, "authenticated");
    assert_ne!(authenticated.token, pending.token);
    status(
        app.service.session(&pending.token, "test", false).await,
        401,
    );
    status(
        app.service.session(&current.token, "test", false).await,
        401,
    );
    let other = app.login("alice@example.com").await;
    status(
        app.service.challenge(&other, "factor", "", &codes[0]).await,
        401,
    );
    let regenerated = app
        .service
        .modify_totp(&authenticated, "factor", PASSWORD, &codes[1], false)
        .await
        .unwrap();
    assert_eq!(regenerated.len(), 10);
    assert_ne!(codes, regenerated);
    let authenticated = app
        .service
        .required_session(&authenticated.token)
        .await
        .unwrap();
    status(
        app.service.challenge(&other, "factor", "", &codes[2]).await,
        409,
    );
    let no_longer = app
        .service
        .modify_totp(&authenticated, "factor", PASSWORD, &regenerated[0], true)
        .await
        .unwrap();
    assert!(no_longer.is_empty());
    let current = app
        .service
        .required_session(&authenticated.token)
        .await
        .unwrap();
    assert_eq!(
        app.service.security(&current).await.unwrap()["totpEnabled"],
        false
    );
    assert_eq!(
        app.service.security(&current).await.unwrap()["recoveryCodesRemaining"],
        0
    );
    assert_eq!(app.login("alice@example.com").await.state, "authenticated");
}

#[tokio::test]
async fn pending_enrollment_expiry_and_fresh_totp_challenge_are_enforced() {
    let app = App::new().await;
    let alice = app.verified("alice@example.com").await;
    let enrollment = app.service.enroll_totp(&alice).await.unwrap();
    let secret = enrollment["secret"].as_str().unwrap();
    assert!(enrollment["uri"]
        .as_str()
        .unwrap()
        .starts_with("otpauth://totp/"));
    assert_eq!(
        app.service.security(&alice).await.unwrap()["totpEnabled"],
        false
    );
    app.sql("UPDATE auth_totp SET pending_expires_at=now()-interval '1 second'")
        .await;
    status(
        app.service
            .confirm_totp(
                &alice,
                "factor",
                &totp(secret, chrono::Utc::now().timestamp() / 30),
            )
            .await,
        401,
    );
    let (_, secret, _) = enable_totp(&app, &alice).await;
    let pending = app.login("alice@example.com").await;
    // The accepted look-ahead window is tested at exact timestamps by RFC unit cases.
    let next = totp(&secret, chrono::Utc::now().timestamp() / 30 + 1);
    let current = app
        .service
        .challenge(&pending, "factor", &next, "")
        .await
        .unwrap();
    assert_eq!(current.state, "authenticated");
    let pending = app.login("alice@example.com").await;
    status(
        app.service.challenge(&pending, "factor", &next, "").await,
        401,
    );
}

#[tokio::test]
async fn password_reset_and_closure_recovery_preserve_mfa_without_email_bypass() {
    let app = App::new().await;
    let alice = app.verified("alice@example.com").await;
    let (_, _, codes) = enable_totp(&app, &alice).await;
    app.service
        .request_email("reset", "alice@example.com", "reset")
        .await
        .unwrap();
    let reset = app.email_token("alice@example.com", "reset").await;
    app.service
        .consume_email(&reset, "reset", NEXT_PASSWORD)
        .await
        .unwrap();
    let pending = app
        .service
        .login(
            &app.anonymous().await,
            "reset-login",
            "alice@example.com",
            NEXT_PASSWORD,
        )
        .await
        .unwrap();
    assert_eq!(pending.state, "mfa_required");
    let current = app
        .service
        .challenge(&pending, "factor", "", &codes[0])
        .await
        .unwrap();
    app.service.schedule_closure(&current).await.unwrap();
    let recover = app
        .email_token("alice@example.com", "closure_recovery")
        .await;
    status(
        app.service
            .confirm_closure_recovery("recover", &recover, NEXT_PASSWORD, "")
            .await,
        401,
    );
    app.service
        .confirm_closure_recovery("recover", &recover, NEXT_PASSWORD, &codes[1])
        .await
        .unwrap();
    let pending = app
        .service
        .login(
            &app.anonymous().await,
            "recovered-login",
            "alice@example.com",
            NEXT_PASSWORD,
        )
        .await
        .unwrap();
    assert_eq!(pending.state, "mfa_required");
    status(
        app.service.session(&current.token, "test", false).await,
        401,
    );
    // The pre-reset object has never regained authority.
    status(app.service.profile(&alice, "stale").await, 409);
}
