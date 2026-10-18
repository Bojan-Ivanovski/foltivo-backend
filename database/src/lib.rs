use sea_orm_migration::prelude::*;
pub mod entities;

pub struct Migrator;
struct SqlMigration {
    name: &'static str,
    up: &'static str,
    down: &'static str,
}
impl MigrationName for SqlMigration {
    fn name(&self) -> &str {
        self.name
    }
}
#[async_trait::async_trait]
impl MigrationTrait for SqlMigration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.get_connection().execute_unprepared(self.up).await?;
        Ok(())
    }
    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(self.down)
            .await?;
        Ok(())
    }
}
#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(SqlMigration {
                name: "00001_bootstrap",
                up: include_str!("../migrations/00001_bootstrap.up.sql"),
                down: include_str!("../migrations/00001_bootstrap.down.sql"),
            }),
            Box::new(SqlMigration {
                name: "00002_auth_foundation",
                up: include_str!("../migrations/00002_auth_foundation.up.sql"),
                down: include_str!("../migrations/00002_auth_foundation.down.sql"),
            }),
            Box::new(SqlMigration {
                name: "00003_account_lifecycle",
                up: include_str!("../migrations/00003_account_lifecycle.up.sql"),
                down: include_str!("../migrations/00003_account_lifecycle.down.sql"),
            }),
            Box::new(SqlMigration {
                name: "00004_auth_factors",
                up: include_str!("../migrations/00004_auth_factors.up.sql"),
                down: include_str!("../migrations/00004_auth_factors.down.sql"),
            }),
            Box::new(SqlMigration {
                name: "00005_account_management",
                up: include_str!("../migrations/00005_account_management.up.sql"),
                down: include_str!("../migrations/00005_account_management.down.sql"),
            }),
            Box::new(SqlMigration {
                name: "00006_oauth",
                up: include_str!("../migrations/00006_oauth.up.sql"),
                down: include_str!("../migrations/00006_oauth.down.sql"),
            }),
        ]
    }
}
