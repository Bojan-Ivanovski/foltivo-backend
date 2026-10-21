mod common;
use common::{enable_totp, wait_for_account_lock_waiters, App};
use foltivo_backend::auth::{self, one};
use sea_orm::{ConnectionTrait, TransactionTrait};
use std::time::Duration;

#[tokio::test]
async fn competing_rotations_have_one_winner_after_observed_account_lock_contention() {
    let app = App::new().await;
    let alice = app.verified("alice@example.com").await;
    let account = app
        .service
        .account("alice@example.com")
        .await
        .unwrap()
        .unwrap();
    let anon = app.anonymous().await;
    let tx = app.service.db.begin().await.unwrap();
    one(
        &tx,
        "SELECT id FROM users WHERE id=$1 FOR UPDATE",
        vec![auth::uid(alice.user_id().unwrap())],
    )
    .await
    .unwrap();
    let mut jobs = Vec::new();
    for _ in 0..2 {
        let service = app.service.clone();
        let old = anon.clone();
        let a = account.clone();
        jobs.push(tokio::spawn(
            async move { service.rotate(&old, Some(a)).await },
        ));
    }
    wait_for_account_lock_waiters(&app, 2).await;
    tx.commit().await.unwrap();
    let mut winners = 0;
    let mut conflicts = 0;
    for job in jobs {
        match tokio::time::timeout(Duration::from_secs(10), job)
            .await
            .unwrap()
            .unwrap()
        {
            Ok(session) => {
                winners += 1;
                assert_eq!(session.state, "authenticated");
            }
            Err(error) => {
                assert_eq!(error.status, 409);
                conflicts += 1;
            }
        }
    }
    assert_eq!((winners, conflicts), (1, 1));
    assert_eq!(
        app.count(
            "SELECT count(*) FROM auth_sessions WHERE user_id IS NOT NULL AND revoked_at IS NULL"
        )
        .await,
        2
    );
}

#[tokio::test]
async fn recovery_code_is_consumed_once_under_competing_browser_challenges() {
    let app = App::new().await;
    let alice = app.verified("alice@example.com").await;
    let (_, _, codes) = enable_totp(&app, &alice).await;
    let left = app.login("alice@example.com").await;
    let right = app.login("alice@example.com").await;
    let tx = app.service.db.begin().await.unwrap();
    one(
        &tx,
        "SELECT id FROM users WHERE id=$1 FOR UPDATE",
        vec![auth::uid(alice.user_id().unwrap())],
    )
    .await
    .unwrap();
    let mut jobs = Vec::new();
    for session in [left, right] {
        let service = app.service.clone();
        let code = codes[0].clone();
        jobs.push(tokio::spawn(async move {
            service
                .challenge(&session, "concurrent-factor", "", &code)
                .await
        }));
    }
    wait_for_account_lock_waiters(&app, 2).await;
    tx.commit().await.unwrap();
    let mut winners = 0;
    for job in jobs {
        match tokio::time::timeout(Duration::from_secs(10), job)
            .await
            .unwrap()
            .unwrap()
        {
            Ok(session) => {
                winners += 1;
                assert_eq!(session.state, "authenticated");
            }
            Err(error) => assert!([401, 409].contains(&error.status), "{error:?}"),
        }
    }
    assert_eq!(winners, 1);
    assert_eq!(
        app.count("SELECT count(*) FROM auth_recovery_codes WHERE consumed_at IS NOT NULL")
            .await,
        1
    );
    assert_eq!(
        app.count(
            "SELECT count(*) FROM auth_sessions WHERE user_id IS NOT NULL AND revoked_at IS NULL"
        )
        .await,
        1
    );
}

#[tokio::test]
async fn cleanup_skips_a_locked_expired_account_then_deletes_after_lock_release() {
    let app = App::new().await;
    let alice = app.verified("alice@example.com").await;
    app.service.schedule_closure(&alice).await.unwrap();
    app.sql("UPDATE users SET closure_requested_at=now()-interval '31 days',closure_expires_at=now()-interval '1 day'").await;
    let tx = app.service.db.begin().await.unwrap();
    tx.execute_unprepared("SELECT id FROM users FOR UPDATE")
        .await
        .unwrap();
    assert!(
        !tokio::time::timeout(Duration::from_secs(2), app.service.delete_expired_account())
            .await
            .unwrap()
            .unwrap()
    );
    tx.rollback().await.unwrap();
    assert!(app.service.delete_expired_account().await.unwrap());
}

#[tokio::test]
async fn recovery_cannot_resurrect_an_account_when_deadline_expires_while_waiting_for_lock() {
    let app = App::new().await;
    let alice = app.verified("alice@example.com").await;
    app.service.schedule_closure(&alice).await.unwrap();
    let token = app
        .email_token("alice@example.com", "closure_recovery")
        .await;
    let tx = app.service.db.begin().await.unwrap();
    tx.execute_unprepared("SELECT id FROM users FOR UPDATE")
        .await
        .unwrap();
    let service = app.service.clone();
    let recovery = tokio::spawn(async move {
        service
            .confirm_closure_recovery("race-recovery", &token, common::PASSWORD, "")
            .await
    });
    wait_for_account_lock_waiters(&app, 1).await;
    // The worker must skip the held account, and recovery must recheck its deadline.
    assert!(!app.service.delete_expired_account().await.unwrap());
    tx.execute_unprepared("UPDATE users SET closure_requested_at=now()-interval '31 days',closure_expires_at=now()-interval '1 day'").await.unwrap();
    tx.commit().await.unwrap();
    let error = tokio::time::timeout(Duration::from_secs(10), recovery)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert_eq!(error.status, 409);
    assert!(app.service.delete_expired_account().await.unwrap());
    assert_eq!(app.count("SELECT count(*) FROM users").await, 0);
}

#[tokio::test]
async fn verification_token_has_one_winner_after_observed_lock_contention() {
    let app = App::new().await;
    app.register("race@example.com").await;
    let pending = app.login("race@example.com").await;
    let token = app.email_token("race@example.com", "verification").await;
    let tx = app.service.db.begin().await.unwrap();
    tx.execute_unprepared("SELECT id FROM users FOR UPDATE")
        .await
        .unwrap();
    let mut jobs = Vec::new();
    for _ in 0..2 {
        let service = app.service.clone();
        let token = token.clone();
        jobs.push(tokio::spawn(async move {
            service.consume_email(&token, "verification", "").await
        }));
    }
    wait_for_account_lock_waiters(&app, 2).await;
    tx.commit().await.unwrap();
    let mut wins = 0;
    for job in jobs {
        match tokio::time::timeout(Duration::from_secs(10), job)
            .await
            .unwrap()
            .unwrap()
        {
            Ok(()) => wins += 1,
            Err(e) => assert_eq!(e.status, 400),
        }
    }
    assert_eq!(wins, 1);
    assert_eq!(app.count("SELECT count(*) FROM auth_email_tokens WHERE purpose='verification' AND consumed_at IS NOT NULL").await,1);
    common::status(
        app.service.session(&pending.token, "test", false).await,
        401,
    );
}

#[tokio::test]
async fn password_login_rotation_rechecks_security_version_after_waiting_for_account_lock() {
    let app = App::new().await;
    let alice = app.verified("alice@example.com").await;
    let account = app
        .service
        .account("alice@example.com")
        .await
        .unwrap()
        .unwrap();
    let anon = app.anonymous().await;
    let tx = app.service.db.begin().await.unwrap();
    tx.execute_unprepared("SELECT id FROM users FOR UPDATE")
        .await
        .unwrap();
    let service = app.service.clone();
    let rotation = tokio::spawn(async move { service.rotate(&anon, Some(account)).await });
    wait_for_account_lock_waiters(&app, 1).await;
    tx.execute_unprepared("UPDATE users SET security_version=security_version+1")
        .await
        .unwrap();
    tx.commit().await.unwrap();
    common::status(
        tokio::time::timeout(Duration::from_secs(10), rotation)
            .await
            .unwrap()
            .unwrap(),
        409,
    );
    common::status(app.service.session(&alice.token, "test", false).await, 401);
    assert_eq!(app.count("SELECT count(*) FROM auth_sessions s JOIN users u ON u.id=s.user_id WHERE s.user_version=u.security_version AND s.revoked_at IS NULL").await,0);
}

#[tokio::test]
async fn outbox_workers_skip_locked_rows_without_duplicate_claims() {
    let mut app = App::new().await;
    let smtp = common::Smtp::start().await;
    smtp.install(&mut app);
    app.register("first@example.com").await;
    app.register("second@example.com").await;
    let tx = app.service.db.begin().await.unwrap();
    tx.execute_unprepared(
        "SELECT id FROM auth_email_outbox ORDER BY created_at LIMIT 1 FOR UPDATE",
    )
    .await
    .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(3), app.service.deliver_email())
            .await
            .unwrap()
            .unwrap()
    );
    assert_eq!(smtp.messages.lock().unwrap().len(), 1);
    assert_eq!(
        app.count("SELECT count(*) FROM auth_email_outbox WHERE completed_at IS NULL")
            .await,
        1
    );
    tx.rollback().await.unwrap();
    let (left, right) = tokio::join!(app.service.deliver_email(), app.service.deliver_email());
    assert_ne!(left.unwrap(), right.unwrap());
    assert_eq!(smtp.messages.lock().unwrap().len(), 2);
    assert_eq!(
        app.count("SELECT count(*) FROM auth_email_outbox WHERE completed_at IS NULL")
            .await,
        0
    );
}
