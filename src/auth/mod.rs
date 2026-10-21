mod account;
pub mod crypto;
mod email;
pub mod error;
mod factors;
mod oauth;
mod passkeys;
mod store;

use crate::{config::Config, mailer::Mailer};
use chrono::{DateTime, Duration, Utc};
pub use error::{Error, Result};
use sea_orm::{
    ConnectionTrait, DatabaseConnection, DatabaseTransaction, DbBackend, QueryResult, Statement,
    TryGetable, Value,
};
use serde::Serialize;
use std::sync::Arc;
pub use store::*;
use webauthn_rs_core::WebauthnCore;

pub async fn exec(db: &impl ConnectionTrait, sql: &str, args: Vec<Value>) -> Result<u64> {
    Ok(db
        .execute(Statement::from_sql_and_values(
            DbBackend::Postgres,
            sql,
            args,
        ))
        .await?
        .rows_affected())
}
pub async fn optional(
    db: &impl ConnectionTrait,
    sql: &str,
    args: Vec<Value>,
) -> Result<Option<QueryResult>> {
    Ok(db
        .query_one(Statement::from_sql_and_values(
            DbBackend::Postgres,
            sql,
            args,
        ))
        .await?)
}
pub async fn one(db: &impl ConnectionTrait, sql: &str, args: Vec<Value>) -> Result<QueryResult> {
    optional(db, sql, args).await?.ok_or_else(Error::conflict)
}
pub async fn all(
    db: &impl ConnectionTrait,
    sql: &str,
    args: Vec<Value>,
) -> Result<Vec<QueryResult>> {
    Ok(db
        .query_all(Statement::from_sql_and_values(
            DbBackend::Postgres,
            sql,
            args,
        ))
        .await?)
}
pub fn get<T: TryGetable>(r: &QueryResult, name: &str) -> Result<T> {
    Ok(r.try_get("", name)?)
}
pub fn uid(id: &str) -> Value {
    uuid::Uuid::parse_str(id).ok().into()
}
pub fn bytes(v: Vec<u8>) -> Value {
    v.into()
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct User {
    pub id: String,
    pub email: String,
    pub name: String,
    pub email_verified: bool,
    pub library_id: String,
}
#[derive(Clone, Serialize)]
pub struct Methods {
    password: bool,
    totp: bool,
    passkey: bool,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    pub user: Option<User>,
    pub state: String,
    pub csrf_token: String,
    pub methods: Methods,
    #[serde(skip)]
    pub id: String,
    #[serde(skip)]
    pub token: String,
    #[serde(skip)]
    pub created_at: DateTime<Utc>,
    #[serde(skip)]
    pub expires_at: DateTime<Utc>,
    #[serde(skip)]
    pub recent_auth_at: Option<DateTime<Utc>>,
    #[serde(skip)]
    pub user_version: i64,
    #[serde(skip)]
    pub mfa: bool,
    #[serde(skip)]
    pub totp_enabled: bool,
}
impl Session {
    pub fn derive(&mut self) {
        self.methods = Methods {
            password: true,
            totp: true,
            passkey: true,
        };
        self.state = match &self.user {
            None => "anonymous",
            Some(u) if !u.email_verified => "verification_required",
            Some(_) if self.totp_enabled && !self.mfa => "mfa_required",
            _ => "authenticated",
        }
        .into();
        self.csrf_token = crypto::csrf(&self.token)
    }
    pub fn authenticated(&self) -> Result<()> {
        if self.user.is_none() {
            return Err(Error::unauthenticated());
        }
        if self.state != "authenticated" {
            return Err(Error::new(
                403,
                &self.state,
                "Complete email verification and required authentication factors to continue.",
            ));
        }
        Ok(())
    }
    pub fn recent(&self) -> Result<()> {
        self.recent_at(Utc::now())
    }
    fn recent_at(&self, now: DateTime<Utc>) -> Result<()> {
        self.authenticated()?;
        if self
            .recent_auth_at
            .is_none_or(|t| now - t > Duration::minutes(5))
        {
            return Err(Error::new(
                403,
                "reauthentication_required",
                "Confirm your identity again to continue.",
            ));
        }
        Ok(())
    }
    pub fn anonymous(&self) -> Result<()> {
        if self.state != "anonymous" {
            return Err(Error::new(
                409,
                "session_exists",
                "Sign out before signing in to another account.",
            ));
        }
        Ok(())
    }
    pub fn user_id(&self) -> Result<&str> {
        self.user
            .as_ref()
            .map(|u| u.id.as_str())
            .ok_or_else(Error::unauthenticated)
    }
}
#[derive(Clone)]
pub struct Service {
    pub db: DatabaseConnection,
    pub config: Arc<Config>,
    pub passwords: crypto::Passwords,
    pub secrets: crypto::Secrets,
    pub mailer: Mailer,
    pub webauthn: Arc<WebauthnCore>,
    pub client: reqwest::Client,
    #[cfg(test)]
    oauth_test_endpoints: Option<Arc<std::collections::HashMap<String, String>>>,
}
impl Service {
    pub async fn new(db: DatabaseConnection, config: Config) -> Result<Self> {
        let secrets = crypto::Secrets::new(&config.encryption_key)?;
        let mailer = Mailer::new(&config)?;
        let origin = url::Url::parse(&config.origin).map_err(|_| Error::unavailable())?;
        let webauthn = WebauthnCore::new_unsafe_experts_only(
            "Foltivo",
            origin.host_str().ok_or_else(Error::unavailable)?,
            vec![origin.clone()],
            std::time::Duration::from_secs(300),
            Some(false),
            Some(false),
        );
        Ok(Self {
            db,
            #[cfg(test)]
            oauth_test_endpoints: None,
            config: Arc::new(config),
            passwords: crypto::Passwords::new().await?,
            secrets,
            mailer,
            webauthn: Arc::new(webauthn),
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .map_err(|_| Error::unavailable())?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn assurance_precedence_and_recent_auth_five_minute_boundary() {
        let now = DateTime::parse_from_rfc3339("2026-10-20T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let mut session = Session {
            user: None,
            state: String::new(),
            csrf_token: String::new(),
            methods: Methods {
                password: false,
                totp: false,
                passkey: false,
            },
            id: String::new(),
            token: crypto::token(),
            created_at: now,
            expires_at: now + Duration::hours(1),
            recent_auth_at: Some(now - Duration::minutes(5)),
            user_version: 1,
            mfa: false,
            totp_enabled: true,
        };
        session.derive();
        assert_eq!(session.state, "anonymous");
        assert!(session.recent_at(now).is_err());
        session.user = Some(User {
            id: "fixture".into(),
            email: "fixture@example.com".into(),
            name: "Fixture".into(),
            email_verified: false,
            library_id: "library".into(),
        });
        session.derive();
        assert_eq!(session.state, "verification_required");
        assert!(session.recent_at(now).is_err());
        session.user.as_mut().unwrap().email_verified = true;
        session.derive();
        assert_eq!(session.state, "mfa_required");
        assert!(session.recent_at(now).is_err());
        session.mfa = true;
        session.derive();
        assert_eq!(session.state, "authenticated");
        session.recent_at(now).unwrap();
        assert!(session.recent_at(now + Duration::nanoseconds(1)).is_err());
        let public = serde_json::to_value(&session).unwrap();
        for hidden in [
            "token",
            "id",
            "userVersion",
            "mfa",
            "recentAuthAt",
            "expiresAt",
        ] {
            assert!(public.get(hidden).is_none(), "{hidden}");
        }
    }
}
