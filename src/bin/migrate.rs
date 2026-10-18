use foltivo_backend::{
    auth::{all, exec, get, one, optional, Error, Result},
    config::{connect, Config},
};
use foltivo_database::Migrator;
use sea_orm::{ConnectionTrait, TransactionTrait};
use sea_orm_migration::MigratorTrait;
use std::{path::Path, time::Duration};

const LOCK: i64 = 4097083626;
#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("{error}");
        std::process::exit(1)
    }
}
async fn run() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let mut unsafe_allowed = false;
    let mut timeout = Duration::from_secs(300);
    let mut positional = vec![];
    while let Some(a) = args.next() {
        match a.as_str() {
            "--allow-unsafe" => unsafe_allowed = true,
            "--timeout" => {
                timeout = humantime::parse_duration(&args.next().ok_or_else(usage)?)
                    .map_err(|_| usage())?;
            }
            "--help" | "-h" => {
                println!("migrate [--allow-unsafe] [--timeout 5m] up|status|version|adopt-goose|create NAME|down|reset");
                return Ok(());
            }
            _ if a.starts_with("--timeout=") => {
                timeout = humantime::parse_duration(&a[10..]).map_err(|_| usage())?;
            }
            _ => positional.push(a),
        }
    }
    if timeout.is_zero() {
        return Err(Error::validation("timeout must be positive"));
    }
    let command = positional.first().ok_or_else(usage)?;
    if command == "create" {
        if positional.len() != 2 {
            return Err(usage());
        }
        return create(&positional[1]);
    }
    if positional.len() != 1
        || !["up", "status", "version", "adopt-goose", "down", "reset"].contains(&command.as_str())
    {
        return Err(usage());
    }
    let (url, environment) = Config::database()?;
    if ["down", "reset"].contains(&command.as_str())
        && (!unsafe_allowed || !["development", "test"].contains(&environment.as_str()))
    {
        return Err(Error::validation("rollback requires APP_ENV=development or test and --allow-unsafe; verify the target and backup first"));
    }
    let db = connect(&url).await?;
    let result = tokio::select! {r=tokio::time::timeout(timeout,operation(&db,command))=>r.map_err(|_|migration_error())?,_ = shutdown_signal()=>Err(migration_error())};
    let _ = db.close().await;
    result
}
fn usage() -> Error {
    Error::validation("usage: migrate [--allow-unsafe] [--timeout 5m] up|status|version|adopt-goose|create NAME|down|reset")
}
fn migration_error() -> Error {
    Error::validation("migration command failed; check database availability, lock contention and reviewed migration SQL (connection details suppressed)")
}
async fn operation(db: &sea_orm::DatabaseConnection, command: &str) -> Result<()> {
    let tx = db.begin().await.map_err(|_| migration_error())?;
    // One transaction holds the advisory lock and contains history changes/DDL.
    // A bounded lock timeout avoids waiting forever behind another deploy.
    tx.execute_unprepared("SET LOCAL lock_timeout='30s'")
        .await
        .map_err(|_| migration_error())?;
    one(&tx, "SELECT pg_advisory_xact_lock($1)", vec![LOCK.into()])
        .await
        .map_err(|_| migration_error())?;
    Migrator::install(&tx)
        .await
        .map_err(|_| migration_error())?;
    let exists = one(
        &tx,
        "SELECT to_regclass('goose_db_version') IS NOT NULL AS exists",
        vec![],
    )
    .await?;
    let goose = get::<bool>(&exists, "exists")?;
    let transition_exists = one(
        &tx,
        "SELECT to_regclass('foltivo_migration_transition') IS NOT NULL AS exists",
        vec![],
    )
    .await?;
    let adopted = if get::<bool>(&transition_exists, "exists")? {
        optional(
            &tx,
            "SELECT id FROM foltivo_migration_transition WHERE id=1",
            vec![],
        )
        .await?
        .is_some()
    } else {
        false
    };
    let names: Vec<String> = Migrator::migrations()
        .iter()
        .map(|m| m.name().to_owned())
        .collect();
    let applied = Migrator::get_applied_migrations(&tx)
        .await
        .map_err(|_| migration_error())?;
    if command == "adopt-goose" {
        if !goose {
            return Err(Error::validation(
                "Goose history is absent; use up for a fresh database",
            ));
        }
        if !applied.is_empty() || adopted {
            return Err(Error::validation(
                "SeaORM history already exists; adoption requires an empty SeaORM ledger",
            ));
        }
        let rows=all(&tx,"SELECT version_id,is_applied FROM (SELECT DISTINCT ON(version_id) version_id,is_applied FROM goose_db_version ORDER BY version_id,id DESC) latest WHERE version_id>0 ORDER BY version_id",vec![]).await?;
        let mut versions = vec![];
        for r in rows {
            let v: i64 = get(&r, "version_id")?;
            if v < 1 || v > 6 {
                return Err(Error::validation(
                    "Goose history is outside the six preserved baseline migrations",
                ));
            }
            if get::<bool>(&r, "is_applied")? {
                versions.push(v);
            }
        }
        for (index, v) in versions.iter().enumerate() {
            if *v != index as i64 + 1 {
                return Err(Error::validation(
                    "Goose history must be a contiguous applied baseline before adoption",
                ));
            }
        }
        for v in &versions {
            exec(&tx,"INSERT INTO seaql_migrations(version,applied_at) VALUES($1,extract(epoch FROM now())::bigint)",vec![names[*v as usize-1].clone().into()]).await?;
        }
        // A separate metadata marker survives reset. An empty SeaORM ledger can
        // mean a deliberately reset, already-adopted database, not only an
        // unadopted Goose database. Application tables remain unchanged.
        tx.execute_unprepared("CREATE TABLE IF NOT EXISTS foltivo_migration_transition (id smallint PRIMARY KEY CHECK(id=1), adopted_at timestamptz NOT NULL DEFAULT now(), goose_version bigint NOT NULL)").await.map_err(|_|migration_error())?;
        exec(
            &tx,
            "INSERT INTO foltivo_migration_transition(id,goose_version) VALUES(1,$1)",
            vec![versions.last().copied().unwrap_or(0).into()],
        )
        .await?;
        // Preserve the old ledger as immutable evidence; only SeaORM runs after cutover.
        println!(
            "Adopted {} existing migration(s); no application DDL executed",
            versions.len()
        );
    } else {
        if goose && applied.is_empty() && !adopted {
            return Err(Error::validation(
                "Existing Goose history requires explicit adopt-goose before SeaORM commands",
            ));
        }
        match command {
            "up" => {
                let pending = Migrator::get_pending_migrations(&tx)
                    .await
                    .map_err(|_| migration_error())?
                    .len();
                Migrator::up(&tx, None)
                    .await
                    .map_err(|_| migration_error())?;
                println!("Applied {pending} migration(s)");
            }
            "down" => {
                Migrator::down(&tx, Some(1))
                    .await
                    .map_err(|_| migration_error())?;
            }
            "reset" => {
                Migrator::down(&tx, None)
                    .await
                    .map_err(|_| migration_error())?;
            }
            "status" => {
                for migration in Migrator::get_migration_with_status(&tx)
                    .await
                    .map_err(|_| migration_error())?
                {
                    println!("{} {:?}", migration.name(), migration.status());
                }
            }
            "version" => {
                let version = applied
                    .last()
                    .and_then(|m| m.name().split('_').next())
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(0);
                println!("{version}");
            }
            _ => return Err(usage()),
        }
    }
    tx.commit().await.map_err(|_| migration_error())?;
    Ok(())
}
fn create(name: &str) -> Result<()> {
    if name.is_empty()
        || !name.as_bytes()[0].is_ascii_lowercase()
        || !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    {
        return Err(Error::validation(
            "create requires a lowercase snake_case migration name",
        ));
    }
    if !Path::new("database/migrations/00001_bootstrap.up.sql").exists() {
        return Err(Error::validation(
            "create must run from the backend repository root",
        ));
    }
    let prefix = format!("{}_{}", chrono::Utc::now().format("%Y%m%d%H%M%S"), name);
    for direction in ["up", "down"] {
        use std::io::Write;
        let path = format!("database/migrations/{prefix}.{direction}.sql");
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|_| {
                Error::validation(
                    "cannot create migration; check permissions and duplicate timestamp/name",
                )
            })?;
        f.write_all(b"-- Add reviewed PostgreSQL statements here.\n")
            .map_err(|_| migration_error())?;
    }
    println!(
        "Created {prefix}.up.sql and .down.sql; register both in database/src/lib.rs before use"
    );
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        if let Ok(mut term) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            tokio::select! {_ = tokio::signal::ctrl_c()=>{},_ = term.recv()=>{}}
        } else {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
