use std::error::Error;

use testcontainers::{
    core::{IntoContainerPort, WaitFor},
    runners::AsyncRunner,
    ContainerAsync, GenericImage, ImageExt,
};

const POSTGRES_IMAGE: &str = "postgres";
const POSTGRES_TAG: &str =
    "18.6-bookworm@sha256:afc7e2d441324c0388fa80c3d24f733b4194a4eb7f47dd8ee2b08eb1a24a647c";
const POSTGRES_USER: &str = "foltivo_test";
const POSTGRES_PASSWORD: &str = "foltivo_test";
const POSTGRES_DATABASE: &str = "foltivo_test";

/// A PostgreSQL server created for one test and removed when this value drops.
pub struct TestPostgres {
    container: ContainerAsync<GenericImage>,
    connection_string: String,
}

impl TestPostgres {
    /// Starts an isolated PostgreSQL 18.6 container with test-only credentials.
    pub async fn start() -> Result<Self, Box<dyn Error + Send + Sync>> {
        let container = GenericImage::new(POSTGRES_IMAGE, POSTGRES_TAG)
            .with_exposed_port(5432.tcp())
            .with_env_var("POSTGRES_USER", POSTGRES_USER)
            .with_env_var("POSTGRES_PASSWORD", POSTGRES_PASSWORD)
            .with_env_var("POSTGRES_DB", POSTGRES_DATABASE)
            .with_ready_conditions(vec![
                WaitFor::message_on_stdout("database system is ready to accept connections"),
                WaitFor::millis(2_000),
            ])
            .start()
            .await?;

        let host = container.get_host().await?;
        let port = container.get_host_port_ipv4(5432).await?;
        let connection_string = format!(
            "postgres://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{host}:{port}/{POSTGRES_DATABASE}?sslmode=disable"
        );

        Ok(Self {
            container,
            connection_string,
        })
    }

    /// Returns the connection string for this disposable container.
    pub fn connection_string(&self) -> &str {
        &self.connection_string
    }

    /// Returns the container identifier for diagnostics.
    pub fn container_id(&self) -> &str {
        self.container.id()
    }
}

/// Starts a fresh PostgreSQL instance for an rstest fixture.
#[rstest::fixture]
pub async fn postgres() -> TestPostgres {
    TestPostgres::start()
        .await
        .expect("start isolated PostgreSQL test container")
}
