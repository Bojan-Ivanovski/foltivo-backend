use super::email::invalidate_access;
use super::*;
use foltivo_database::entities::{auth_email_tokens, auth_passkeys};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder, TransactionTrait};
use serde_json::{json, Value as Json};
use tokio_util::sync::CancellationToken;

async fn blockers(tx: &DatabaseTransaction, id: &str) -> Result<Vec<Json>> {
    let mut result = vec![];
    for r in all(
        tx,
        "SELECT code,message FROM account_closure_blockers WHERE user_id=$1 ORDER BY code",
        vec![uid(id)],
    )
    .await?
    {
        result
            .push(json!({"code":get::<String>(&r,"code")?,"message":get::<String>(&r,"message")?}))
    }
    Ok(result)
}
impl Service {
    pub async fn profile(&self, s: &Session, name: &str) -> Result<User> {
        s.authenticated()?;
        let name = crypto::name(name)?;
        if exec(&self.db,"UPDATE users u SET name=$1,updated_at=now() WHERE u.id=$2 AND u.email_verified=true AND u.security_version=$3 AND EXISTS(SELECT 1 FROM auth_sessions s WHERE s.id=$4 AND s.revoked_at IS NULL AND s.expires_at>now() AND (NOT u.totp_enabled OR s.mfa_verified))",vec![name.clone().into(),uid(s.user_id()?),s.user_version.into(),uid(&s.id)]).await?!=1{return Err(Error::conflict())}
        let mut user = s.user.clone().ok_or_else(Error::unauthenticated)?;
        user.name = name;
        Ok(user)
    }
    pub async fn sessions(&self, s: &Session) -> Result<Vec<Json>> {
        s.authenticated()?;
        let rows=all(&self.db,"SELECT id::text AS id,created_at,expires_at,user_agent,last_seen_at FROM auth_sessions WHERE user_id=$1 AND user_version=$2 AND revoked_at IS NULL AND expires_at>now() AND EXISTS(SELECT 1 FROM auth_sessions active JOIN users u ON u.id=active.user_id WHERE active.id=$3 AND active.revoked_at IS NULL AND active.expires_at>now() AND active.user_version=u.security_version AND u.email_verified AND (NOT u.totp_enabled OR active.mfa_verified)) ORDER BY created_at DESC",vec![uid(s.user_id()?),s.user_version.into(),uid(&s.id)]).await?;
        let mut result = vec![];
        for r in rows {
            let id: String = get(&r, "id")?;
            result.push(json!({"id":id,"current":id==s.id,"createdAt":get::<DateTime<Utc>>(&r,"created_at")?,"expiresAt":get::<DateTime<Utc>>(&r,"expires_at")?,"userAgent":get::<Option<String>>(&r,"user_agent")?,"lastSeenAt":get::<Option<DateTime<Utc>>>(&r,"last_seen_at")?}))
        }
        Ok(result)
    }
    pub async fn revoke(&self, s: &Session, id: &str) -> Result<()> {
        s.authenticated()?;
        if !crypto::identifier(id) {
            return Err(Error::validation("Enter a valid session identifier."));
        }
        if exec(&self.db,"UPDATE auth_sessions SET revoked_at=now() WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL AND EXISTS(SELECT 1 FROM auth_sessions active JOIN users u ON u.id=active.user_id WHERE active.id=$3 AND active.revoked_at IS NULL AND active.expires_at>now() AND active.user_version=u.security_version AND u.email_verified AND (NOT u.totp_enabled OR active.mfa_verified))",vec![uid(id),uid(s.user_id()?),uid(&s.id)]).await?!=1{return Err(Error::new(404,"not_found","Session was not found."))}
        Ok(())
    }
    pub async fn revoke_others(&self, s: &Session) -> Result<u64> {
        s.authenticated()?;
        let tx = self.db.begin().await?;
        let a = self.factor_account(&tx, s, false, false).await?;
        for table in ["auth_ceremonies", "auth_oauth_states", "auth_oauth_grants"] {
            exec(&tx,&format!("DELETE FROM {table} WHERE session_id IN(SELECT id FROM auth_sessions WHERE user_id=$1 AND id<>$2)"),vec![uid(&a.user.id),uid(&s.id)]).await?;
        }
        let count=exec(&tx,"UPDATE auth_sessions SET revoked_at=now() WHERE user_id=$1 AND id<>$2 AND revoked_at IS NULL",vec![uid(&a.user.id),uid(&s.id)]).await?;
        tx.commit().await?;
        Ok(count)
    }
    pub async fn pending_email(&self, s: &Session) -> Result<Option<Json>> {
        s.authenticated()?;
        let row = auth_email_tokens::Entity::find()
            .filter(
                auth_email_tokens::Column::UserId
                    .eq(uuid::Uuid::parse_str(s.user_id()?).map_err(|_| Error::unavailable())?),
            )
            .filter(auth_email_tokens::Column::Purpose.eq("email_change"))
            .filter(auth_email_tokens::Column::UserVersion.eq(s.user_version))
            .filter(auth_email_tokens::Column::ConsumedAt.is_null())
            .filter(auth_email_tokens::Column::ExpiresAt.gt(Utc::now()))
            .order_by_desc(auth_email_tokens::Column::CreatedAt)
            .one(&self.db)
            .await?;
        Ok(row.map(|r| json!({"email":r.target_email,"expiresAt":r.expires_at})))
    }
    pub async fn request_email_change(&self, s: &Session, peer: &str, email: &str) -> Result<()> {
        s.recent()?;
        let email = crypto::email(email)?;
        if s.user.as_ref().is_some_and(|u| u.email == email) {
            return Err(Error::validation("Enter a different email address."));
        }
        self.throttle(&format!("email-change/user/{}", s.user_id()?), 5)
            .await?;
        self.throttle(&format!("email-change/ip/{peer}"), 10)
            .await?;
        let tx = self.db.begin().await?;
        let a = self.factor_account(&tx, s, true, false).await?;
        let r = one(
            &tx,
            "SELECT EXISTS(SELECT 1 FROM users WHERE email=$1) AS occupied",
            vec![email.clone().into()],
        )
        .await?;
        if get::<bool>(&r, "occupied")? {
            return Ok(());
        }
        exec(&tx,"UPDATE auth_email_tokens SET consumed_at=now() WHERE user_id=$1 AND purpose='email_change' AND consumed_at IS NULL",vec![uid(&a.user.id)]).await?;
        self.issue_email(
            &tx,
            &a,
            "email_change",
            &email,
            "/confirm-email-change",
            "Confirm your new Foltivo email",
            1800,
            true,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }
    pub async fn cancel_email_change(&self, s: &Session) -> Result<()> {
        s.authenticated()?;
        let tx = self.db.begin().await?;
        let a = self.factor_account(&tx, s, false, false).await?;
        exec(&tx,"UPDATE auth_email_tokens SET consumed_at=now() WHERE user_id=$1 AND purpose='email_change' AND consumed_at IS NULL",vec![uid(&a.user.id)]).await?;
        tx.commit().await?;
        Ok(())
    }
    pub async fn confirm_email_change(&self, s: &Session, peer: &str, token: &str) -> Result<()> {
        s.authenticated()?;
        if !crypto::valid_token(token) {
            return Err(Error::link());
        }
        self.throttle(&format!("email-consume/ip/{peer}"), 20)
            .await?;
        let tx = self.db.begin().await?;
        let a = self.factor_account(&tx, s, false, false).await?;
        let r=optional(&tx,"UPDATE auth_email_tokens SET consumed_at=now() WHERE user_id=$1 AND token_hash=$2 AND purpose='email_change' AND user_version=$3 AND consumed_at IS NULL AND expires_at>now() RETURNING target_email",vec![uid(&a.user.id),crypto::hash(token).into(),a.version.into()]).await?.ok_or_else(Error::link)?;
        let target: String = get(&r, "target_email")?;
        exec(&tx,"UPDATE users SET email=$2,email_verified=true,security_version=security_version+1,updated_at=now() WHERE id=$1",vec![uid(&a.user.id),target.into()]).await.map_err(|_|Error::conflict())?;
        invalidate_access(&tx, &a.user.id).await?;
        self.account_notice(&tx,&a,"Your Foltivo email changed","Your Foltivo sign-in email was changed. If you did not authorize this, secure your email and contact Foltivo support. Existing sessions have been signed out.").await?;
        tx.commit().await?;
        Ok(())
    }
    pub async fn security(&self, s: &Session) -> Result<Json> {
        s.authenticated()?;
        let tx = self.db.begin().await?;
        let a = self.factor_account(&tx, s, false, false).await?;
        let id = uuid::Uuid::parse_str(&a.user.id).map_err(|_| Error::unavailable())?;
        let count=one(&tx,"SELECT count(*) AS remaining FROM auth_recovery_codes WHERE user_id=$1 AND consumed_at IS NULL",vec![id.into()]).await?;
        let keys = auth_passkeys::Entity::find()
            .filter(auth_passkeys::Column::UserId.eq(id))
            .order_by_asc(auth_passkeys::Column::CreatedAt)
            .all(&tx)
            .await?;
        let keys: Vec<Json> = keys
            .into_iter()
            .map(|k| json!({"id":k.id,"name":k.name,"createdAt":k.created_at}))
            .collect();
        let result = json!({"totpEnabled":a.totp_enabled,"recoveryCodesRemaining":get::<i64>(&count,"remaining")?,"passkeys":keys});
        tx.commit().await?;
        Ok(result)
    }
    pub async fn remove_passkey(&self, s: &Session, id: &str) -> Result<()> {
        s.recent()?;
        if !crypto::identifier(id) {
            return Err(Error::validation("Invalid passkey identifier."));
        }
        let tx = self.db.begin().await?;
        let a = self.factor_account(&tx, s, true, false).await?;
        if exec(
            &tx,
            "DELETE FROM auth_passkeys WHERE id=$1 AND user_id=$2",
            vec![uid(id), uid(&a.user.id)],
        )
        .await?
            != 1
        {
            return Err(Error::new(404, "not_found", "Passkey was not found."));
        }
        super::factors::factor_change(&tx, &a, s).await?;
        tx.commit().await?;
        Ok(())
    }
    pub async fn account_closure(&self, s: &Session) -> Result<Json> {
        s.authenticated()?;
        let tx = self.db.begin().await?;
        let a = self.factor_account(&tx, s, false, false).await?;
        Ok(json!({"pending":null,"blockers":blockers(&tx,&a.user.id).await?,"recoveryDays":30}))
    }
    pub async fn schedule_closure(&self, s: &Session) -> Result<DateTime<Utc>> {
        s.recent()?;
        let tx = self.db.begin().await?;
        let mut a = self.factor_account(&tx, s, true, false).await?;
        if !blockers(&tx, &a.user.id).await?.is_empty() {
            return Err(Error::new(
                409,
                "closure_blocked",
                "Resolve account ownership and retention blockers before closing this account.",
            ));
        }
        let r=one(&tx,"UPDATE users SET closure_requested_at=now(),closure_expires_at=now()+interval '30 days',security_version=security_version+1,updated_at=now() WHERE id=$1 RETURNING closure_expires_at",vec![uid(&a.user.id)]).await?;
        invalidate_access(&tx, &a.user.id).await?;
        a.version += 1;
        self.issue_email(
            &tx,
            &a,
            "closure_recovery",
            &a.user.email,
            "/recover-account",
            "Recover your Foltivo account",
            1800,
            true,
        )
        .await?;
        tx.commit().await?;
        get(&r, "closure_expires_at")
    }
    pub async fn request_closure_recovery(&self, peer: &str, email: &str) -> Result<()> {
        let email = crypto::email(email)?;
        self.throttle(&format!("closure-recovery/ip/{peer}"), 10)
            .await?;
        self.throttle(&format!("closure-recovery/email/{email}"), 5)
            .await?;
        let tx = self.db.begin().await?;
        let Some(a) = account_query(
            &tx,
            "WHERE u.email=$1 AND u.closure_expires_at>now() FOR UPDATE OF u",
            vec![email.clone().into()],
        )
        .await?
        else {
            return Ok(());
        };
        exec(&tx,"UPDATE auth_email_tokens SET consumed_at=now() WHERE user_id=$1 AND purpose='closure_recovery' AND consumed_at IS NULL",vec![uid(&a.user.id)]).await?;
        self.issue_email(
            &tx,
            &a,
            "closure_recovery",
            &email,
            "/recover-account",
            "Recover your Foltivo account",
            1800,
            true,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }
    pub async fn confirm_closure_recovery(
        &self,
        peer: &str,
        token: &str,
        password: &str,
        code: &str,
    ) -> Result<()> {
        let invalid = || Error::validation("This recovery link is invalid or has expired.");
        if !crypto::valid_token(token) {
            return Err(invalid());
        }
        self.throttle(&format!("closure-confirm/ip/{peer}"), 20)
            .await?;
        let r=optional(&self.db,"SELECT user_id::text AS user_id FROM auth_email_tokens WHERE token_hash=$1 AND purpose='closure_recovery' AND consumed_at IS NULL AND expires_at>now()",vec![crypto::hash(token).into()]).await?.ok_or_else(invalid)?;
        let id: String = get(&r, "user_id")?;
        self.throttle(&format!("closure-confirm/user/{id}"), 10)
            .await?;
        let a = account_query(&self.db, "WHERE u.id=$1", vec![uid(&id)]).await?;
        crypto::password(password).map_err(|_| Error::invalid_credentials())?;
        let matched = self
            .passwords
            .compare(password, a.as_ref().map(|a| a.hash.as_str()).unwrap_or(""))
            .await?;
        let a = a
            .filter(|_| matched)
            .ok_or_else(Error::invalid_credentials)?;
        let tx = self.db.begin().await?;
        let locked = account_query(
            &tx,
            "WHERE u.id=$1 AND u.closure_expires_at>now() FOR UPDATE OF u",
            vec![uid(&id)],
        )
        .await?
        .ok_or_else(Error::conflict)?;
        if locked.closure_at.is_none() || locked.hash != a.hash || locked.version != a.version {
            return Err(Error::conflict());
        }
        optional(&tx,"SELECT id FROM auth_email_tokens WHERE user_id=$1 AND token_hash=$2 AND purpose='closure_recovery' AND consumed_at IS NULL AND expires_at>now() AND user_version=$3 FOR UPDATE",vec![uid(&id),crypto::hash(token).into(),locked.version.into()]).await?.ok_or_else(invalid)?;
        if locked.totp_enabled {
            self.consume_security_proof(&tx, &id, code).await?;
        } else if !code.is_empty() {
            return Err(Error::validation("Unexpected authentication code."));
        }
        exec(&tx,"UPDATE users SET closure_requested_at=NULL,closure_expires_at=NULL,security_version=security_version+1,updated_at=now() WHERE id=$1",vec![uid(&id)]).await?;
        invalidate_access(&tx, &id).await?;
        tx.commit().await?;
        Ok(())
    }
    pub async fn delete_expired_account(&self) -> Result<bool> {
        let tx = self.db.begin().await?;
        let Some(r)=optional(&tx,"SELECT u.id::text AS id FROM users u WHERE u.closure_expires_at<=now() AND NOT EXISTS(SELECT 1 FROM account_closure_blockers b WHERE b.user_id=u.id) ORDER BY u.closure_expires_at LIMIT 1 FOR UPDATE OF u SKIP LOCKED",vec![]).await? else{return Ok(false)};
        let id: String = get(&r, "id")?;
        if !blockers(&tx, &id).await?.is_empty() {
            return Ok(false);
        }
        for q in ["DELETE FROM auth_email_outbox WHERE token_id IN(SELECT id FROM auth_email_tokens WHERE user_id=$1)","DELETE FROM auth_email_tokens WHERE user_id=$1","DELETE FROM auth_sessions WHERE user_id=$1","DELETE FROM libraries WHERE user_owner_id=$1","DELETE FROM users WHERE id=$1"]{exec(&tx,q,vec![uid(&id)]).await?;}
        tx.commit().await?;
        Ok(true)
    }
    pub async fn closure_loop(&self, stop: CancellationToken) {
        loop {
            for _ in 0..20 {
                let result = tokio::select! {_ = stop.cancelled()=>return,r=tokio::time::timeout(std::time::Duration::from_secs(7),self.delete_expired_account())=>r};
                match result {
                    Ok(Ok(true)) => {}
                    Ok(Ok(false)) => break,
                    _ => {
                        tracing::warn!("account_closure_cleanup_retry");
                        break;
                    }
                }
            }
            tokio::select! {_ = stop.cancelled()=>return,_ = tokio::time::sleep(std::time::Duration::from_secs(60))=>{}}
        }
    }
}
