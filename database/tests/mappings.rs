use foltivo_database::{entities::*, Migrator};
use foltivo_test_support::postgres;
use sea_orm::{Database, EntityTrait};
use sea_orm_migration::MigratorTrait;

#[rstest::rstest]
#[tokio::test]
async fn every_seaorm_mapping_matches_the_migrated_postgresql_columns(
    #[future] postgres: foltivo_test_support::TestPostgres,
) {
    let postgres = postgres.await;
    let db = Database::connect(postgres.connection_string())
        .await
        .unwrap();
    Migrator::up(&db, None).await.unwrap();
    macro_rules! mapping {
        ($($entity:ident),+)=>{$(
            assert!($entity::Entity::find().all(&db).await.unwrap().is_empty(),stringify!($entity));
        )+};
    }
    mapping!(
        users,
        libraries,
        auth_sessions,
        auth_throttles,
        auth_email_tokens,
        auth_email_outbox,
        auth_totp,
        auth_recovery_codes,
        auth_passkeys,
        auth_ceremonies,
        account_closure_blockers,
        auth_oauth_identities,
        auth_oauth_states,
        auth_oauth_grants
    );
    db.close().await.unwrap();
}
