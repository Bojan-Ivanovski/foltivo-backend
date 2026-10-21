mod common;
use common::config;
use foltivo_backend::{config::connect, mailer::Mailer};

#[test]
fn smtp_rejects_unsafe_transport_sender_and_partial_credentials() {
    let base = config("postgres://127.0.0.1/test");
    assert!(Mailer::new(&base).is_ok());
    let mut invalid = base.clone();
    invalid.environment = "production".into();
    assert!(Mailer::new(&invalid).is_err());
    let mut invalid = base.clone();
    invalid.smtp_addr = "remote.invalid:25".into();
    assert!(Mailer::new(&invalid).is_err());
    let mut invalid = base.clone();
    invalid.smtp_username = "username".into();
    assert!(Mailer::new(&invalid).is_err());
    for from in [
        "Name <mail@example.com>",
        "mail@example.com\r\nBcc: other@example.com",
        "invalid",
    ] {
        let mut invalid = base.clone();
        invalid.smtp_from = from.into();
        assert!(Mailer::new(&invalid).is_err());
    }
    for address in ["missing-port", "127.0.0.1:not-a-port"] {
        let mut invalid = base.clone();
        invalid.smtp_addr = address.into();
        assert!(Mailer::new(&invalid).is_err());
    }
}

#[tokio::test]
async fn database_connection_is_lazy_and_malformed_urls_are_redacted() {
    let database = connect("postgres://fixture:synthetic@127.0.0.1:1/unavailable?sslmode=disable")
        .await
        .unwrap();
    database.close().await.unwrap();
    for url in [
        "postgres://secret-user:secret-password@host:invalid/database",
        "not-a-database-url",
    ] {
        let error = connect(url).await.err().expect("invalid database URL");
        assert!(!error.to_string().contains("secret"));
    }
}
