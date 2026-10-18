use super::*;
use foltivo_database::entities::{libraries, users};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set, TransactionTrait};

#[derive(Clone)]
pub struct Account {
    pub user: User,
    pub hash: String,
    pub version: i64,
    pub totp_enabled: bool,
    pub closure_at: Option<DateTime<Utc>>,
}
pub const ACCOUNT_COLUMNS:&str="u.id::text AS id,u.email,u.name,u.email_verified,l.id::text AS library_id,u.password_hash,u.security_version,u.totp_enabled,u.closure_requested_at";
pub fn read_account(r: QueryResult) -> Result<Account> {
    Ok(Account {
        user: User {
            id: get(&r, "id")?,
            email: get(&r, "email")?,
            name: get(&r, "name")?,
            email_verified: get(&r, "email_verified")?,
            library_id: get(&r, "library_id")?,
        },
        hash: get(&r, "password_hash")?,
        version: get(&r, "security_version")?,
        totp_enabled: get(&r, "totp_enabled")?,
        closure_at: get(&r, "closure_requested_at")?,
    })
}
pub async fn account_query(
    db: &impl ConnectionTrait,
    tail: &str,
    args: Vec<Value>,
) -> Result<Option<Account>> {
    optional(
        db,
        &format!(
            "SELECT {ACCOUNT_COLUMNS} FROM users u JOIN libraries l ON l.user_owner_id=u.id {tail}"
        ),
        args,
    )
    .await?
    .map(read_account)
    .transpose()
}
pub async fn lock_account(tx: &DatabaseTransaction, id: &str) -> Result<Account> {
    account_query(tx, "WHERE u.id=$1 FOR UPDATE OF u", vec![uid(id)])
        .await?
        .ok_or_else(Error::conflict)
}
pub async fn insert_session(
    tx: &DatabaseTransaction,
    token: &str,
    a: Option<&Account>,
    mfa: bool,
    mut recent: Option<DateTime<Utc>>,
) -> Result<()> {
    let (user, version, lifetime) = match a {
        None => (None, None, 30 * 60),
        Some(a) => {
            if a.closure_at.is_some() {
                return Err(Error::invalid_credentials());
            }
            let partial = !a.user.email_verified || (a.totp_enabled && !mfa);
            if partial {
                recent = None
            }
            (
                Some(uuid::Uuid::parse_str(&a.user.id).map_err(|_| Error::unavailable())?),
                Some(a.version),
                if partial { 15 * 60 } else { 7 * 24 * 60 * 60 },
            )
        }
    };
    // Security deadlines use the database clock, as they did in Go. This
    // conditional persistence path deliberately retains explicit PostgreSQL
    // through SeaORM instead of computing expiry on an application host clock.
    exec(tx,
        "INSERT INTO auth_sessions(token_hash,user_id,user_version,mfa_verified,recent_auth_at,expires_at) VALUES($1,$2,$3,$4,$5,now()+($6::bigint * interval '1 second'))",
        vec![crypto::hash(token).into(),user.into(),version.into(),mfa.into(),recent.into(),(lifetime as i64).into()]
    ).await?;
    Ok(())
}
impl Service {
    // Ordinary identity reads use ORM models; explicit SQL is retained for atomic
    // transitions and PostgreSQL lock semantics rather than splitting transactions.
    pub async fn account(&self, email: &str) -> Result<Option<Account>> {
        let Some(u) = users::Entity::find()
            .filter(users::Column::Email.eq(email))
            .one(&self.db)
            .await?
        else {
            return Ok(None);
        };
        let Some(l) = libraries::Entity::find()
            .filter(libraries::Column::UserOwnerId.eq(u.id))
            .one(&self.db)
            .await?
        else {
            return Ok(None);
        };
        Ok(Some(Account {
            user: User {
                id: u.id.to_string(),
                email: u.email,
                name: u.name,
                email_verified: u.email_verified,
                library_id: l.id.to_string(),
            },
            hash: u.password_hash,
            version: u.security_version,
            totp_enabled: u.totp_enabled,
            closure_at: u.closure_requested_at,
        }))
    }
    pub async fn throttle(&self, key: &str, limit: i32) -> Result<()> {
        let r=one(&self.db,"INSERT INTO auth_throttles(key_hash,attempts,resets_at) VALUES($1,1,now()+interval '15 minutes') ON CONFLICT(key_hash) DO UPDATE SET attempts=CASE WHEN auth_throttles.resets_at<=now() THEN 1 ELSE LEAST(auth_throttles.attempts+1,100000) END,resets_at=CASE WHEN auth_throttles.resets_at<=now() THEN now()+interval '15 minutes' ELSE auth_throttles.resets_at END RETURNING attempts,GREATEST(1,ceil(extract(epoch FROM resets_at-now()))::int) AS retry",vec![crypto::hash(key).into()]).await?;
        if get::<i32>(&r, "attempts")? > limit {
            let mut e = Error::new(429, "rate_limited", "Too many attempts. Try again later.");
            e.retry_after = get::<i32>(&r, "retry")? as u64;
            return Err(e);
        }
        Ok(())
    }
    async fn find_session(&self, token: &str) -> Result<Option<Session>> {
        if !crypto::valid_token(token) {
            return Ok(None);
        }
        let Some(row)=optional(&self.db,
            "SELECT s.id::text AS id,s.created_at,s.expires_at,s.recent_auth_at,s.user_version,s.mfa_verified,u.id::text AS user_id,u.email,u.name,u.email_verified,l.id::text AS library_id,u.totp_enabled FROM auth_sessions s LEFT JOIN users u ON u.id=s.user_id LEFT JOIN libraries l ON l.user_owner_id=u.id WHERE s.token_hash=$1 AND s.revoked_at IS NULL AND s.expires_at>now() AND (s.user_id IS NULL OR (s.user_version=u.security_version AND l.id IS NOT NULL AND u.closure_requested_at IS NULL))",
            vec![crypto::hash(token).into()]).await? else {return Ok(None)};
        let user = if let Some(id) = get::<Option<String>>(&row, "user_id")? {
            Some(User {
                id,
                email: get(&row, "email")?,
                name: get(&row, "name")?,
                email_verified: get(&row, "email_verified")?,
                library_id: get(&row, "library_id")?,
            })
        } else {
            None
        };
        let mut session = Session {
            id: get(&row, "id")?,
            token: token.into(),
            user,
            state: String::new(),
            csrf_token: String::new(),
            methods: Methods {
                password: true,
                totp: true,
                passkey: true,
            },
            created_at: get(&row, "created_at")?,
            expires_at: get(&row, "expires_at")?,
            recent_auth_at: get(&row, "recent_auth_at")?,
            user_version: get::<Option<i64>>(&row, "user_version")?.unwrap_or(0),
            mfa: get(&row, "mfa_verified")?,
            totp_enabled: get::<Option<bool>>(&row, "totp_enabled")?.unwrap_or(false),
        };
        session.derive();
        Ok(Some(session))
    }
    pub async fn session(&self, token: &str, peer: &str, bootstrap: bool) -> Result<Session> {
        if let Some(session) = self.find_session(token).await? {
            return Ok(session);
        }
        if !bootstrap {
            return Err(Error::unauthenticated());
        }
        self.throttle(&format!("bootstrap/ip/{peer}"), 60).await?;
        let token = crypto::token();
        let tx = self.db.begin().await?;
        insert_session(&tx, &token, None, false, None).await?;
        tx.commit().await?;
        self.required_session(&token).await
    }
    pub async fn required_session(&self, token: &str) -> Result<Session> {
        self.find_session(token).await?.ok_or_else(Error::conflict)
    }
    pub async fn observe_session(&self, s: &Session, agent: &str) -> Result<()> {
        if s.user.is_none() {
            return Ok(());
        }
        let mut agent: String = agent.chars().filter(|c| !c.is_control()).collect();
        while agent.len() > 512 {
            agent.pop();
        }
        exec(&self.db,"UPDATE auth_sessions SET user_agent=COALESCE(user_agent,NULLIF($2,'')),last_seen_at=now() WHERE id=$1 AND revoked_at IS NULL AND (last_seen_at IS NULL OR last_seen_at<now()-interval '5 minutes')",vec![uid(&s.id),agent.into()]).await?;
        Ok(())
    }
    pub async fn register(
        &self,
        peer: &str,
        name: &str,
        email: &str,
        password: &str,
    ) -> Result<()> {
        let name = crypto::name(name)?;
        let email = crypto::email(email)?;
        crypto::password(password)?;
        self.throttle(&format!("register/ip/{peer}"), 5).await?;
        let hash = self.passwords.password_hash(password).await?;
        let tx = self.db.begin().await?;
        if let Some(r)=optional(&tx,"INSERT INTO users(name,email,password_hash) VALUES($1,$2,$3) ON CONFLICT(email) DO NOTHING RETURNING id",vec![name.into(),email.clone().into(),hash.into()]).await?{let id:uuid::Uuid=get(&r,"id")?;libraries::ActiveModel{user_owner_id:Set(id),..Default::default()}.insert(&tx).await?;tx.commit().await?;}else{tx.rollback().await?;}
        self.request_email(peer, &email, "verification").await
    }
    pub async fn login(
        &self,
        s: &Session,
        peer: &str,
        email: &str,
        password: &str,
    ) -> Result<Session> {
        let email = crypto::email(email).map_err(|_| Error::invalid_credentials())?;
        crypto::password(password).map_err(|_| Error::invalid_credentials())?;
        self.throttle(&format!("login/ip/{peer}"), 30).await?;
        self.throttle(&format!("login/email/{email}"), 10).await?;
        let a = self.account(&email).await?;
        let matched = self
            .passwords
            .compare(password, a.as_ref().map(|a| a.hash.as_str()).unwrap_or(""))
            .await?;
        let a = a
            .filter(|a| matched && a.closure_at.is_none())
            .ok_or_else(Error::invalid_credentials)?;
        self.rotate(s, Some(a)).await
    }
    pub async fn rotate(&self, old: &Session, a: Option<Account>) -> Result<Session> {
        let token = crypto::token();
        let tx = self.db.begin().await?;
        let a = if let Some(a) = a {
            let live = lock_account(&tx, &a.user.id).await?;
            if live.closure_at.is_some() || live.hash != a.hash || live.version != a.version {
                return Err(Error::conflict());
            }
            Some(live)
        } else {
            None
        };
        if exec(&tx,"UPDATE auth_sessions SET revoked_at=now() WHERE id=$1 AND token_hash=$2 AND revoked_at IS NULL AND expires_at>now()",vec![uid(&old.id),crypto::hash(&old.token).into()]).await?!=1{return Err(Error::conflict())}
        insert_session(&tx, &token, a.as_ref(), false, Some(Utc::now())).await?;
        tx.commit().await?;
        self.required_session(&token).await
    }
    pub async fn anonymous_active(&self, tx: &DatabaseTransaction, s: &Session) -> Result<()> {
        one(tx,"SELECT id FROM auth_sessions WHERE id=$1 AND token_hash=$2 AND user_id IS NULL AND revoked_at IS NULL AND expires_at>now() FOR UPDATE",vec![uid(&s.id),crypto::hash(&s.token).into()]).await?;
        Ok(())
    }
}
