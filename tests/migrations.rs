mod common;

use common::database;
use foltivo_backend::auth::{get, one};
use foltivo_test_support::TestPostgres;
use rstest::rstest;
use sea_orm::{ConnectionTrait, DatabaseConnection, TransactionTrait};
use std::{process::Output, time::Duration};
use tokio::process::Command;

const SQL: [&str; 6] = [
    include_str!("../database/migrations/00001_bootstrap.up.sql"),
    include_str!("../database/migrations/00002_auth_foundation.up.sql"),
    include_str!("../database/migrations/00003_account_lifecycle.up.sql"),
    include_str!("../database/migrations/00004_auth_factors.up.sql"),
    include_str!("../database/migrations/00005_account_management.up.sql"),
    include_str!("../database/migrations/00006_oauth.up.sql"),
];
fn command(pg: &TestPostgres) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_migrate"));
    command
        .env_clear()
        .env("APP_ENV", "test")
        .env("DATABASE_URL", pg.connection_string())
        .kill_on_drop(true);
    command
}
async fn run(pg: &TestPostgres, args: &[&str]) -> Output {
    tokio::time::timeout(Duration::from_secs(45), command(pg).args(args).output())
        .await
        .unwrap()
        .unwrap()
}
fn success(output: Output) -> String {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}
async fn scalar(db: &DatabaseConnection, sql: &str) -> i64 {
    get(&one(db, sql, vec![]).await.unwrap(), "count").unwrap()
}
async fn goose(db: &DatabaseConnection, prefix: usize) {
    db.execute_unprepared("CREATE TABLE goose_db_version(id bigserial PRIMARY KEY,version_id bigint NOT NULL,is_applied boolean NOT NULL,tstamp timestamp DEFAULT now()); INSERT INTO goose_db_version(version_id,is_applied) VALUES(0,true)").await.unwrap();
    for (i, sql) in SQL.iter().take(prefix).enumerate() {
        db.execute_unprepared(sql).await.unwrap();
        db.execute_unprepared(&format!(
            "INSERT INTO goose_db_version(version_id,is_applied) VALUES({},true)",
            i + 1
        ))
        .await
        .unwrap();
    }
}

#[rstest]
#[case(0)]
#[case(1)]
#[case(2)]
#[case(3)]
#[case(4)]
#[case(5)]
#[case(6)]
#[tokio::test]
async fn adopts_every_goose_prefix_without_ddl_or_data_loss(#[case] prefix: usize) {
    let pg = TestPostgres::start().await.unwrap();
    let db = database(&pg).await;
    goose(&db, prefix).await;
    if prefix >= 2 {
        db.execute_unprepared("INSERT INTO users(email,name,password_hash) VALUES('retained@example.com','Retained','historical-phc'); INSERT INTO libraries(user_owner_id) SELECT id FROM users").await.unwrap();
    }
    let tables_before = scalar(
        &db,
        "SELECT count(*) FROM pg_tables WHERE schemaname='public'",
    )
    .await;
    assert!(!run(&pg, &["up"]).await.status.success());
    assert!(success(run(&pg, &["adopt-goose"]).await).contains(&format!("Adopted {prefix}")));
    assert_eq!(
        scalar(&db, "SELECT count(*) FROM seaql_migrations").await,
        prefix as i64
    );
    assert_eq!(
        scalar(&db, "SELECT count(*) FROM goose_db_version").await,
        prefix as i64 + 1
    );
    assert_eq!(
        scalar(
            &db,
            "SELECT count(*) FROM pg_tables WHERE schemaname='public'"
        )
        .await,
        tables_before + 2
    );
    assert_eq!(
        scalar(
            &db,
            "SELECT goose_version AS count FROM foltivo_migration_transition"
        )
        .await,
        prefix as i64
    );
    assert!(!run(&pg, &["adopt-goose"]).await.status.success());
    success(run(&pg, &["up"]).await);
    assert_eq!(success(run(&pg, &["version"]).await).trim(), "6");
    assert_eq!(
        scalar(&db, "SELECT count(*) FROM seaql_migrations").await,
        6
    );
    if prefix >= 2 {
        assert_eq!(scalar(&db,"SELECT count(*) FROM users WHERE email='retained@example.com' AND password_hash='historical-phc'").await,1);
    }
    success(run(&pg, &["--allow-unsafe", "reset"]).await);
    assert_eq!(
        scalar(&db, "SELECT count(*) FROM seaql_migrations").await,
        0
    );
    assert_eq!(
        scalar(&db, "SELECT count(*) FROM goose_db_version").await,
        prefix as i64 + 1
    );
    success(run(&pg, &["up"]).await);
    assert_eq!(
        scalar(&db, "SELECT count(*) FROM seaql_migrations").await,
        6
    );
    db.close().await.unwrap();
}

#[rstest]
#[case("INSERT INTO goose_db_version(version_id,is_applied) VALUES(2,true)")]
#[case("INSERT INTO goose_db_version(version_id,is_applied) VALUES(7,true)")]
#[case("INSERT INTO goose_db_version(version_id,is_applied) VALUES(7,false)")]
#[tokio::test]
async fn adoption_rejects_invalid_history_atomically(#[case] history: &str) {
    let pg = TestPostgres::start().await.unwrap();
    let db = database(&pg).await;
    goose(&db, 0).await;
    db.execute_unprepared(history).await.unwrap();
    assert!(!run(&pg, &["adopt-goose"]).await.status.success());
    assert_eq!(scalar(&db,"SELECT count(*) FROM pg_tables WHERE schemaname='public' AND tablename IN ('seaql_migrations','foltivo_migration_transition')").await,0);
}

#[tokio::test]
async fn adoption_uses_latest_reverted_and_reapplied_history() {
    let pg = TestPostgres::start().await.unwrap();
    let db = database(&pg).await;
    goose(&db, 2).await;
    db.execute_unprepared("INSERT INTO goose_db_version(version_id,is_applied) VALUES(2,false),(2,true),(3,true),(3,false)").await.unwrap();
    success(run(&pg, &["adopt-goose"]).await);
    assert_eq!(
        scalar(&db, "SELECT count(*) FROM seaql_migrations").await,
        2
    );
}

#[tokio::test]
async fn fresh_lifecycle_guards_and_schema_mappings() {
    let pg = TestPostgres::start().await.unwrap();
    let db = database(&pg).await;
    assert!(!run(&pg, &["adopt-goose"]).await.status.success());
    assert!(success(run(&pg, &["status"]).await).contains("Pending"));
    success(run(&pg, &["up"]).await);
    success(run(&pg, &["up"]).await);
    assert_eq!(
        scalar(&db, "SELECT count(*) FROM seaql_migrations").await,
        6
    );
    assert_eq!(scalar(&db,"SELECT count(*) FROM pg_tables WHERE schemaname='public' AND tablename<>'seaql_migrations'").await,14);
    for table in [
        "users",
        "libraries",
        "auth_sessions",
        "auth_throttles",
        "auth_email_tokens",
        "auth_email_outbox",
        "auth_totp",
        "auth_recovery_codes",
        "auth_passkeys",
        "auth_ceremonies",
        "account_closure_blockers",
        "auth_oauth_identities",
        "auth_oauth_states",
        "auth_oauth_grants",
    ] {
        db.execute_unprepared(&format!("SELECT * FROM {table} LIMIT 0"))
            .await
            .unwrap();
    }
    for cmd in ["down", "reset"] {
        assert!(!run(&pg, &[cmd]).await.status.success());
        let output = command(&pg)
            .env("APP_ENV", "production")
            .args(["--allow-unsafe", cmd])
            .output()
            .await
            .unwrap();
        assert!(!output.status.success());
        assert_eq!(
            scalar(&db, "SELECT count(*) FROM seaql_migrations").await,
            6
        );
    }
    success(run(&pg, &["--allow-unsafe", "down"]).await);
    assert_eq!(success(run(&pg, &["version"]).await).trim(), "5");
    success(run(&pg, &["up"]).await);
    success(run(&pg, &["--allow-unsafe", "reset"]).await);
    success(run(&pg, &["up"]).await);
}

#[tokio::test]
async fn ddl_failure_rolls_back_all_schema_and_ledger_changes() {
    let pg = TestPostgres::start().await.unwrap();
    let db = database(&pg).await;
    // Deliberately conflict with a later baseline table, after bootstrap has run.
    db.execute_unprepared("CREATE TABLE users(existing integer)")
        .await
        .unwrap();
    assert!(!run(&pg, &["up"]).await.status.success());
    assert_eq!(
        scalar(
            &db,
            "SELECT count(*) FROM pg_tables WHERE schemaname='public'"
        )
        .await,
        1
    );
    assert_eq!(scalar(&db,"SELECT count(*) FROM information_schema.columns WHERE table_name='users' AND column_name='existing'").await,1);
}

#[tokio::test]
async fn advisory_lock_contention_times_out_then_releases_on_completion() {
    let pg = TestPostgres::start().await.unwrap();
    let db = database(&pg).await;
    let tx = db.begin().await.unwrap();
    tx.execute_unprepared("SELECT pg_advisory_xact_lock(4097083626)")
        .await
        .unwrap();
    let output = run(&pg, &["--timeout", "300ms", "up"]).await;
    assert!(!output.status.success());
    assert_eq!(
        scalar(
            &db,
            "SELECT count(*) FROM pg_tables WHERE schemaname='public'"
        )
        .await,
        0
    );
    tx.commit().await.unwrap();
    success(run(&pg, &["up"]).await);
    success(run(&pg, &["status"]).await);
}

#[test]
fn cli_rejects_invalid_arguments_without_database_and_redacts_credentials() {
    for args in [
        vec![],
        vec!["unknown"],
        vec!["up", "extra"],
        vec!["--timeout", "0s", "up"],
        vec!["--timeout", "invalid", "up"],
        vec!["create", "UpperCase"],
    ] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_migrate"))
            .env_clear()
            .args(args)
            .output()
            .unwrap();
        assert!(!output.status.success());
    }
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_migrate"))
        .env_clear()
        .env("APP_ENV", "production")
        .env(
            "DATABASE_URL",
            "postgres://secret-user:secret-password@invalid/db",
        )
        .args(["--allow-unsafe", "reset"])
        .output()
        .unwrap();
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(error.contains("rollback requires"));
    assert!(!error.contains("secret"));
}

#[tokio::test]
async fn cancelled_lock_wait_leaves_no_schema_and_releases_connection() {
    let pg = TestPostgres::start().await.unwrap();
    let db = database(&pg).await;
    let tx = db.begin().await.unwrap();
    tx.execute_unprepared("SELECT pg_advisory_xact_lock(4097083626)")
        .await
        .unwrap();
    let mut child = command(&pg)
        .arg("up")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5),async{loop{
        if scalar(&db,"SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock'").await>0{break;}
        tokio::time::sleep(Duration::from_millis(10)).await;
    }}).await.unwrap();
    assert!(std::process::Command::new("kill")
        .args(["-TERM", &child.id().unwrap().to_string()])
        .status()
        .unwrap()
        .success());
    assert!(!tokio::time::timeout(Duration::from_secs(5), child.wait())
        .await
        .unwrap()
        .unwrap()
        .success());
    assert_eq!(
        scalar(
            &db,
            "SELECT count(*) FROM pg_tables WHERE schemaname='public'"
        )
        .await,
        0
    );
    tx.rollback().await.unwrap();
    success(run(&pg, &["up"]).await);
}

#[test]
fn create_only_writes_new_valid_named_migrations_in_a_temporary_directory() {
    let temporary = common::TempDirectory::new("migrate-create");
    let directory = temporary.path();
    std::fs::create_dir_all(directory.join("database/migrations")).unwrap();
    std::fs::write(
        directory.join("database/migrations/00001_bootstrap.up.sql"),
        SQL[0],
    )
    .unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_migrate"))
        .env_clear()
        .current_dir(&directory)
        .args(["create", "test_probe"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let files: Vec<_> = std::fs::read_dir(directory.join("database/migrations"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.file_name().unwrap() != "00001_bootstrap.up.sql")
        .collect();
    assert_eq!(files.len(), 2);
    assert!(files.iter().all(|f| f
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .contains("_test_probe.")));
    for name in ["../escape", "UPPER", "contains-dash", ""] {
        assert!(!std::process::Command::new(env!("CARGO_BIN_EXE_migrate"))
            .env_clear()
            .current_dir(&directory)
            .args(["create", name])
            .output()
            .unwrap()
            .status
            .success());
    }
    assert_eq!(
        std::fs::read_dir(directory.join("database/migrations"))
            .unwrap()
            .count(),
        3
    );
}
