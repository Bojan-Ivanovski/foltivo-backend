mod common;
use common::{status, App, Authenticator};
use foltivo_backend::auth::Service;
use serde_json::json;

async fn fixture() -> (App, Authenticator) {
    let mut app = App::new().await;
    let browser = Authenticator::start().await;
    let mut config = (*app.service.config).clone();
    config.origin = browser.origin.clone();
    app.service = Service::new(app.service.db.clone(), config).await.unwrap();
    (app, browser)
}

#[tokio::test]
async fn real_ctap2_registration_discoverable_assertion_signature_failure_and_removal() {
    let (app, mut browser) = fixture().await;
    let alice = app.verified("alice@example.com").await;
    let options = app
        .service
        .begin_passkey(&alice, "passkey", "registration", "Chromium CTAP2")
        .await
        .unwrap();
    assert_eq!(
        options["publicKey"]["authenticatorSelection"]["userVerification"],
        "required"
    );
    assert_eq!(
        options["publicKey"]["authenticatorSelection"]["requireResidentKey"],
        true
    );
    let response = browser.command("register", options).await;
    assert!(app
        .service
        .finish_passkey(&alice, "passkey", "registration", response)
        .await
        .unwrap()
        .is_none());
    let current = app.service.required_session(&alice.token).await.unwrap();
    let security = app.service.security(&current).await.unwrap();
    assert_eq!(security["passkeys"].as_array().unwrap().len(), 1);
    app.verified("password-only@example.com").await;
    let mut shape = None;
    for email in [
        "unknown@example.com",
        "password-only@example.com",
        "alice@example.com",
    ] {
        let anon = app.anonymous().await;
        let mut options = app
            .service
            .begin_passkey(&anon, "passkey", "login", email)
            .await
            .unwrap();
        assert!(options["publicKey"].get("allowCredentials").is_none());
        options["publicKey"]
            .as_object_mut()
            .unwrap()
            .remove("challenge");
        if let Some(expected) = &shape {
            assert_eq!(&options, expected);
        } else {
            shape = Some(options);
        }
    }
    let anon = app.anonymous().await;
    let options = app
        .service
        .begin_passkey(&anon, "passkey", "login", "alice@example.com")
        .await
        .unwrap();
    let response = browser.command("assert", options).await;
    let authenticated = app
        .service
        .finish_passkey(&anon, "passkey", "login", response.clone())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(authenticated.state, "authenticated");
    assert_ne!(authenticated.token, anon.token);
    assert_eq!(authenticated.user_id().unwrap(), alice.user_id().unwrap());
    status(
        app.service
            .finish_passkey(&anon, "passkey", "login", response)
            .await,
        401,
    );
    let anon = app.anonymous().await;
    let options = app
        .service
        .begin_passkey(&anon, "passkey", "login", "alice@example.com")
        .await
        .unwrap();
    let mut response = browser.command("assert", options).await;
    response["response"]["signature"] = json!("AA");
    status(
        app.service
            .finish_passkey(&anon, "passkey", "login", response.clone())
            .await,
        401,
    );
    status(
        app.service
            .finish_passkey(&anon, "passkey", "login", response)
            .await,
        401,
    );
    app.service
        .remove_passkey(
            &authenticated,
            security["passkeys"][0]["id"].as_str().unwrap(),
        )
        .await
        .unwrap();
    let current = app
        .service
        .required_session(&authenticated.token)
        .await
        .unwrap();
    assert_eq!(
        app.service.security(&current).await.unwrap()["passkeys"],
        json!([])
    );
    assert_eq!(app.login("alice@example.com").await.state, "authenticated");
    browser.close().await;
}

#[tokio::test]
async fn ceremonies_are_browser_bound_expiring_single_use_and_do_not_upgrade_stale_versions() {
    let (app, mut browser) = fixture().await;
    let alice = app.verified("alice@example.com").await;
    let other = app.login("alice@example.com").await;
    let options = app
        .service
        .begin_passkey(&alice, "passkey", "registration", "Key")
        .await
        .unwrap();
    let response = browser.command("register", options).await;
    status(
        app.service
            .finish_passkey(&other, "passkey", "registration", response.clone())
            .await,
        401,
    );
    assert_eq!(app.count("SELECT count(*) FROM auth_ceremonies").await, 1);
    app.sql("UPDATE auth_ceremonies SET expires_at=now()-interval '1 second'")
        .await;
    status(
        app.service
            .finish_passkey(&alice, "passkey", "registration", response)
            .await,
        401,
    );
    let options = app
        .service
        .begin_passkey(&alice, "passkey", "registration", "Second")
        .await
        .unwrap();
    let response = browser.command("register", options).await;
    app.sql(&format!(
        "UPDATE users SET security_version=security_version+1 WHERE id='{}'",
        alice.user_id().unwrap()
    ))
    .await;
    status(
        app.service
            .finish_passkey(&alice, "passkey", "registration", response)
            .await,
        409,
    );
    assert_eq!(app.count("SELECT count(*) FROM auth_passkeys").await, 0);
    browser.close().await;
}

#[tokio::test]
async fn go_credential_and_unexpired_go_ceremony_verify_real_signatures_and_preserve_metadata() {
    use base64::{
        engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
        Engine,
    };
    use foltivo_backend::auth::{exec, get, one, uid};
    let (app, mut browser) = fixture().await;
    let alice = app.verified("alice@example.com").await;
    let vector: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/go-passkey.json")).unwrap();
    let credential = &vector["credential"];
    let kid = STANDARD.decode(credential["id"].as_str().unwrap()).unwrap();
    let purpose = format!(
        "passkey/{}/{}",
        alice.user_id().unwrap(),
        URL_SAFE_NO_PAD.encode(&kid)
    );
    let encrypted = app
        .service
        .secrets
        .seal(&serde_json::to_vec(credential).unwrap(), &purpose)
        .unwrap();
    exec(&app.service.db,"INSERT INTO auth_passkeys(user_id,credential_id,credential,name) VALUES($1,$2,$3,'Go baseline')",vec![uid(alice.user_id().unwrap()),kid.clone().into(),encrypted.into()]).await.unwrap();
    browser.command("add",json!({"credentialId":STANDARD.encode(&kid),"isResidentCredential":true,"rpId":"localhost","privateKey":vector["privateKey"],"userHandle":STANDARD.encode(alice.user_id().unwrap().as_bytes()),"signCount":1})).await;
    let anon = app.anonymous().await;
    let mut options = app
        .service
        .begin_passkey(&anon, "legacy", "login", "alice@example.com")
        .await
        .unwrap();
    let mut ceremony = vector["ceremony"].clone();
    ceremony["origin"] = json!(browser.origin);
    ceremony["user_id"] = json!(STANDARD.encode(alice.user_id().unwrap().as_bytes()));
    options["publicKey"]["challenge"] = ceremony["challenge"].clone();
    exec(
        &app.service.db,
        "UPDATE auth_ceremonies SET data=$1 WHERE session_id=$2",
        vec![ceremony.into(), uid(&anon.id)],
    )
    .await
    .unwrap();
    let response = browser.command("assert", options).await;
    let session = app
        .service
        .finish_passkey(&anon, "legacy", "login", response)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(session.state, "authenticated");
    let row = one(
        &app.service.db,
        "SELECT credential FROM auth_passkeys WHERE credential_id=$1",
        vec![kid.clone().into()],
    )
    .await
    .unwrap();
    let cipher: Vec<u8> = get(&row, "credential").unwrap();
    let hybrid: serde_json::Value =
        serde_json::from_slice(&app.service.secrets.open(&cipher, &purpose).unwrap()).unwrap();
    assert_eq!(hybrid["attestation"], credential["attestation"]);
    assert_eq!(hybrid["publicKey"], credential["publicKey"]);
    assert!(hybrid["authenticator"]["signCount"].as_u64().unwrap() > 1);
    assert_eq!(hybrid["flags"]["userVerified"], true);
    assert!(hybrid.get("rustCredential").is_some());
    // The additive hybrid record remains usable on the next Rust ceremony.
    let anon = app.anonymous().await;
    let options = app
        .service
        .begin_passkey(&anon, "hybrid", "login", "alice@example.com")
        .await
        .unwrap();
    let response = browser.command("assert", options).await;
    assert_eq!(
        app.service
            .finish_passkey(&anon, "hybrid", "login", response)
            .await
            .unwrap()
            .unwrap()
            .state,
        "authenticated"
    );
    // A signed assertion with a regressed counter cannot update the credential
    // or upgrade the browser, including after conversion to the hybrid record.
    let row = one(
        &app.service.db,
        "SELECT credential FROM auth_passkeys WHERE credential_id=$1",
        vec![kid.clone().into()],
    )
    .await
    .unwrap();
    let cipher: Vec<u8> = get(&row, "credential").unwrap();
    let mut record: serde_json::Value =
        serde_json::from_slice(&app.service.secrets.open(&cipher, &purpose).unwrap()).unwrap();
    record["rustCredential"]["counter"] = json!(100000);
    record["authenticator"]["signCount"] = json!(100000);
    let encrypted = app
        .service
        .secrets
        .seal(&serde_json::to_vec(&record).unwrap(), &purpose)
        .unwrap();
    exec(
        &app.service.db,
        "UPDATE auth_passkeys SET credential=$1 WHERE credential_id=$2",
        vec![encrypted.into(), kid.into()],
    )
    .await
    .unwrap();
    let anon = app.anonymous().await;
    let options = app
        .service
        .begin_passkey(&anon, "counter-regression", "login", "alice@example.com")
        .await
        .unwrap();
    let response = browser.command("assert", options).await;
    status(
        app.service
            .finish_passkey(&anon, "counter-regression", "login", response)
            .await,
        401,
    );
    assert_eq!(
        app.service
            .required_session(&anon.token)
            .await
            .unwrap()
            .state,
        "anonymous"
    );
    browser.close().await;
}

#[tokio::test]
async fn registration_begun_with_go_session_data_finishes_through_real_verifier() {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use foltivo_backend::auth::{exec, uid};
    let (app, mut browser) = fixture().await;
    let alice = app.verified("alice@example.com").await;
    let options = app
        .service
        .begin_passkey(&alice, "legacy-register", "registration", "Go pending key")
        .await
        .unwrap();
    let vector: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/go-passkey.json")).unwrap();
    let mut ceremony = vector["ceremony"].clone();
    ceremony["challenge"] = options["publicKey"]["challenge"].clone();
    ceremony["user_id"] = json!(STANDARD.encode(alice.user_id().unwrap().as_bytes()));
    ceremony["origin"] = json!(browser.origin);
    ceremony["credParams"] = options["publicKey"]["pubKeyCredParams"].clone();
    exec(
        &app.service.db,
        "UPDATE auth_ceremonies SET data=$1 WHERE session_id=$2",
        vec![ceremony.into(), uid(&alice.id)],
    )
    .await
    .unwrap();
    let response = browser.command("register", options).await;
    app.service
        .finish_passkey(&alice, "legacy-register", "registration", response)
        .await
        .unwrap();
    assert_eq!(app.count("SELECT count(*) FROM auth_passkeys").await, 1);
    browser.close().await;
}

#[tokio::test]
async fn authenticator_bad_uv_up_origin_challenge_and_user_handle_never_grant_a_session() {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let (app, mut browser) = fixture().await;
    let alice = app.verified("alice@example.com").await;
    let options = app
        .service
        .begin_passkey(&alice, "negative-register", "registration", "Key")
        .await
        .unwrap();
    let response = browser.command("register", options).await;
    app.service
        .finish_passkey(&alice, "negative-register", "registration", response)
        .await
        .unwrap();
    for failure in ["uv", "up", "origin", "challenge", "handle"] {
        let anon = app.anonymous().await;
        let options = app
            .service
            .begin_passkey(&anon, "negative-login", "login", "alice@example.com")
            .await
            .unwrap();
        browser
            .command(
                "override",
                match failure {
                    "uv" => json!({"isBadUV":true}),
                    "up" => json!({"isBadUP":true}),
                    _ => json!({}),
                },
            )
            .await;
        let mut response = browser.command("assert", options).await;
        if ["origin", "challenge"].contains(&failure) {
            let bytes = URL_SAFE_NO_PAD
                .decode(response["response"]["clientDataJSON"].as_str().unwrap())
                .unwrap();
            let mut client: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            client[failure] = json!(if failure == "origin" {
                "https://evil.example"
            } else {
                "wrong-challenge"
            });
            response["response"]["clientDataJSON"] =
                json!(URL_SAFE_NO_PAD.encode(serde_json::to_vec(&client).unwrap()));
        }
        if failure == "handle" {
            response["response"]["userHandle"] =
                json!(URL_SAFE_NO_PAD.encode(b"another-account-uuid"));
        }
        status(
            app.service
                .finish_passkey(&anon, "negative-login", "login", response)
                .await,
            401,
        );
        assert_eq!(
            app.service
                .required_session(&anon.token)
                .await
                .unwrap()
                .state,
            "anonymous",
            "{failure}"
        );
    }
    browser.command("override", json!({})).await;
    browser.close().await;
}
