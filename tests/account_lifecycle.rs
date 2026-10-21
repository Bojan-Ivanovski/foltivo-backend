mod common;
use common::{status, App, Smtp, PASSWORD};
use foltivo_backend::auth::{self, get, one};
use std::sync::atomic::Ordering;

#[tokio::test]
async fn verified_email_changes_are_account_bound_cancelable_and_revoke_access() {
    let app = App::new().await;
    let alice = app.verified("alice@example.com").await;
    let bob = app.verified("bob@example.com").await;
    app.service
        .request_email_change(&alice, "change", "first@example.com")
        .await
        .unwrap();
    let replaced = app.email_token("alice@example.com", "email_change").await;
    assert_eq!(
        app.service.pending_email(&alice).await.unwrap().unwrap()["email"],
        "first@example.com"
    );
    assert_eq!(
        app.service
            .account("alice@example.com")
            .await
            .unwrap()
            .unwrap()
            .user
            .email,
        "alice@example.com"
    );
    app.service
        .request_email_change(&alice, "change", "second@example.com")
        .await
        .unwrap();
    status(
        app.service
            .confirm_email_change(&alice, "change", &replaced)
            .await,
        400,
    );
    app.service.cancel_email_change(&alice).await.unwrap();
    assert!(app.service.pending_email(&alice).await.unwrap().is_none());
    let canceled = app.email_token("alice@example.com", "email_change").await;
    status(
        app.service
            .confirm_email_change(&alice, "change", &canceled)
            .await,
        400,
    );
    app.service
        .request_email_change(&alice, "change", "final@example.com")
        .await
        .unwrap();
    let token = app.email_token("alice@example.com", "email_change").await;
    status(
        app.service
            .confirm_email_change(&bob, "wrong-account", &token)
            .await,
        400,
    );
    app.service
        .confirm_email_change(&alice, "change", &token)
        .await
        .unwrap();
    assert!(app
        .service
        .account("alice@example.com")
        .await
        .unwrap()
        .is_none());
    status(app.service.session(&alice.token, "test", false).await, 401);
    assert_eq!(app.login("final@example.com").await.state, "authenticated");
    let notices = app
        .count("SELECT count(*) FROM auth_email_tokens WHERE purpose='security_notice'")
        .await;
    assert_eq!(notices, 1);
}

#[tokio::test]
async fn email_change_conflicts_and_expiry_leave_old_address_and_token_atomic() {
    let app = App::new().await;
    let alice = app.verified("alice@example.com").await;
    app.service
        .request_email_change(&alice, "change", "later@example.com")
        .await
        .unwrap();
    let token = app.email_token("alice@example.com", "email_change").await;
    app.verified("later@example.com").await;
    status(
        app.service
            .confirm_email_change(&alice, "change", &token)
            .await,
        409,
    );
    assert_eq!(app.count("SELECT count(*) FROM auth_email_tokens WHERE purpose='email_change' AND consumed_at IS NULL").await,1);
    app.sql("UPDATE auth_email_tokens SET expires_at=now()-interval '1 second' WHERE purpose='email_change'").await;
    status(
        app.service
            .confirm_email_change(&alice, "change", &token)
            .await,
        400,
    );
    assert_eq!(
        app.service
            .account("alice@example.com")
            .await
            .unwrap()
            .unwrap()
            .user
            .email,
        "alice@example.com"
    );
    app.service
        .request_email_change(&alice, "change", "later@example.com")
        .await
        .unwrap();
    assert!(app.service.pending_email(&alice).await.unwrap().is_none());
}

#[tokio::test]
async fn closure_blockers_recovery_proofs_fixed_deadline_and_final_cleanup() {
    let app = App::new().await;
    let alice = app.verified("alice@example.com").await;
    let id = alice.user_id().unwrap();
    app.sql(&format!("INSERT INTO account_closure_blockers(user_id,code,message) VALUES('{id}','ownership','Transfer ownership')")).await;
    assert_eq!(
        app.service.account_closure(&alice).await.unwrap()["blockers"][0]["code"],
        "ownership"
    );
    status(app.service.schedule_closure(&alice).await, 409);
    app.sql("DELETE FROM account_closure_blockers").await;
    let deadline = app.service.schedule_closure(&alice).await.unwrap();
    let days = (deadline - chrono::Utc::now()).num_days();
    assert!((29..=30).contains(&days));
    status(app.service.session(&alice.token, "test", false).await, 401);
    status(
        app.service
            .login(
                &app.anonymous().await,
                "closing",
                "alice@example.com",
                PASSWORD,
            )
            .await,
        401,
    );
    let replaced = app
        .email_token("alice@example.com", "closure_recovery")
        .await;
    app.service
        .request_closure_recovery("recover", "alice@example.com")
        .await
        .unwrap();
    let token = app
        .email_token("alice@example.com", "closure_recovery")
        .await;
    status(
        app.service
            .confirm_closure_recovery("recover", &replaced, PASSWORD, "")
            .await,
        400,
    );
    status(
        app.service
            .confirm_closure_recovery("recover", &token, "wrong password that is long", "")
            .await,
        401,
    );
    let current: chrono::DateTime<chrono::Utc> = get(
        &one(
            &app.service.db,
            "SELECT closure_expires_at FROM users WHERE id=$1",
            vec![auth::uid(id)],
        )
        .await
        .unwrap(),
        "closure_expires_at",
    )
    .unwrap();
    assert_eq!(deadline, current);
    app.service
        .confirm_closure_recovery("recover", &token, PASSWORD, "")
        .await
        .unwrap();
    assert_eq!(
        app.count(
            "SELECT count(*) FROM auth_sessions WHERE user_id IS NOT NULL AND revoked_at IS NULL"
        )
        .await,
        0
    );
    status(
        app.service
            .confirm_closure_recovery("recover", &token, PASSWORD, "")
            .await,
        400,
    );
    let recovered = app.login("alice@example.com").await;
    app.service.schedule_closure(&recovered).await.unwrap();
    app.sql("UPDATE users SET closure_requested_at=now()-interval '31 days',closure_expires_at=now()-interval '1 day'").await;
    app.sql(&format!("INSERT INTO account_closure_blockers(user_id,code,message) VALUES('{id}','retention','Retain')")).await;
    assert!(!app.service.delete_expired_account().await.unwrap());
    let token = app
        .email_token("alice@example.com", "closure_recovery")
        .await;
    status(
        app.service
            .confirm_closure_recovery("recover", &token, PASSWORD, "")
            .await,
        409,
    );
    app.sql("DELETE FROM account_closure_blockers").await;
    assert!(app.service.delete_expired_account().await.unwrap());
    assert!(!app.service.delete_expired_account().await.unwrap());
    for table in [
        "users",
        "libraries",
        "auth_email_tokens",
        "auth_email_outbox",
        "auth_totp",
        "auth_recovery_codes",
        "auth_passkeys",
        "auth_oauth_identities",
    ] {
        assert_eq!(
            app.count(&format!("SELECT count(*) FROM {table}")).await,
            0,
            "{table}"
        );
    }
}

#[tokio::test]
async fn smtp_retry_obsolescence_payload_erasure_and_encrypted_go_shape() {
    let mut app = App::new().await;
    let smtp = Smtp::start().await;
    smtp.install(&mut app);
    app.register("mail@example.com").await;
    let row = one(
        &app.service.db,
        "SELECT payload FROM auth_email_outbox",
        vec![],
    )
    .await
    .unwrap();
    let payload: Vec<u8> = get(&row, "payload").unwrap();
    assert!(!String::from_utf8_lossy(&payload).contains("#token="));
    let plain = app
        .service
        .secrets
        .open(&payload, "email-outbox/v1")
        .unwrap();
    let go: serde_json::Value = serde_json::from_slice(&plain).unwrap();
    assert_eq!(go["To"], "mail@example.com");
    assert!(go["Body"]
        .as_str()
        .unwrap()
        .contains("http://localhost:5173/verify-email#token="));
    smtp.reject.store(true, Ordering::SeqCst);
    status(app.service.deliver_email().await, 503);
    assert_eq!(app.count("SELECT count(*) FROM auth_email_outbox WHERE attempts=1 AND completed_at IS NULL AND next_attempt_at>now()").await,1);
    assert!(smtp.messages.lock().unwrap().is_empty());
    assert!(!app.service.deliver_email().await.unwrap());
    app.sql("UPDATE auth_email_outbox SET next_attempt_at=now()-interval '1 second'")
        .await;
    smtp.reject.store(false, Ordering::SeqCst);
    assert!(app.service.deliver_email().await.unwrap());
    assert_eq!(smtp.messages.lock().unwrap().len(), 1);
    assert_eq!(app.count("SELECT count(*) FROM auth_email_outbox WHERE completed_at IS NOT NULL AND octet_length(payload)=0").await,1);
    app.service
        .request_email("mail", "mail@example.com", "verification")
        .await
        .unwrap();
    app.sql("UPDATE auth_email_tokens SET consumed_at=now() WHERE purpose='verification'")
        .await;
    assert!(app.service.deliver_email().await.unwrap());
    assert_eq!(smtp.messages.lock().unwrap().len(), 1);
    assert_eq!(
        app.count("SELECT count(*) FROM auth_email_outbox WHERE completed_at IS NULL")
            .await,
        0
    );
}

#[tokio::test]
async fn smtp_timeout_is_bounded_and_background_workers_cancel_without_committing_partial_delivery()
{
    use std::time::{Duration, Instant};
    use tokio_util::sync::CancellationToken;
    let mut app = App::new().await;
    let smtp = Smtp::start().await;
    smtp.install(&mut app);
    smtp.stall.store(true, Ordering::SeqCst);
    app.register("stalled@example.com").await;
    let start = Instant::now();
    status(
        tokio::time::timeout(Duration::from_secs(7), app.service.deliver_email())
            .await
            .expect("bounded SMTP delivery"),
        503,
    );
    assert!(start.elapsed() < Duration::from_secs(7));
    assert_eq!(
        app.count(
            "SELECT count(*) FROM auth_email_outbox WHERE attempts=1 AND completed_at IS NULL"
        )
        .await,
        1
    );
    app.sql("UPDATE auth_email_outbox SET next_attempt_at=now()-interval '1 second'")
        .await;
    let stop = CancellationToken::new();
    let worker_stop = stop.clone();
    let service = app.service.clone();
    let worker = tokio::spawn(async move { service.email_loop(worker_stop).await });
    tokio::time::timeout(Duration::from_secs(3), async {
        while smtp.data_requests.load(Ordering::SeqCst) < 2 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("observe the worker blocked in SMTP DATA before cancelling");
    stop.cancel();
    tokio::time::timeout(Duration::from_secs(2), worker)
        .await
        .expect("worker cancellation")
        .unwrap();
    assert!(smtp.messages.lock().unwrap().is_empty());
    assert_eq!(
        app.count("SELECT count(*) FROM auth_email_outbox WHERE completed_at IS NULL")
            .await,
        1
    );
}
