use super::*;
use sea_orm::TransactionTrait;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

// Capitalized names preserve the encrypted Go emailPayload JSON format.
#[derive(Serialize, Deserialize)]
pub struct EmailPayload {
    #[serde(rename = "To")]
    pub to: String,
    #[serde(rename = "Subject")]
    pub subject: String,
    #[serde(rename = "Body")]
    pub body: String,
}
impl Service {
    pub async fn request_email(&self, peer: &str, email: &str, purpose: &str) -> Result<()> {
        let email = crypto::email(email)?;
        if purpose != "verification" && purpose != "reset" {
            return Err(Error::validation("Invalid email operation."));
        }
        self.throttle(&format!("email/ip/{peer}"), 10).await?;
        self.throttle(&format!("email/{purpose}/{email}"), 5)
            .await?;
        let Some(a) = self.account(&email).await? else {
            return Ok(());
        };
        if a.closure_at.is_some() || (purpose == "verification" && a.user.email_verified) {
            return Ok(());
        }
        let (route, subject, lifetime) = if purpose == "reset" {
            ("/reset-password", "Reset your Foltivo password", 1800)
        } else {
            ("/verify-email", "Verify your Foltivo email", 86400)
        };
        let tx = self.db.begin().await?;
        let a = lock_account(&tx, &a.user.id).await?;
        if a.user.email != email
            || a.closure_at.is_some()
            || (purpose == "verification" && a.user.email_verified)
        {
            return Ok(());
        }
        exec(&tx,"UPDATE auth_email_tokens SET consumed_at=now() WHERE user_id=$1 AND purpose=$2 AND consumed_at IS NULL",vec![uid(&a.user.id),purpose.into()]).await?;
        self.issue_email(&tx, &a, purpose, &email, route, subject, lifetime, false)
            .await?;
        tx.commit().await?;
        Ok(())
    }
    pub async fn issue_email(
        &self,
        tx: &DatabaseTransaction,
        a: &Account,
        purpose: &str,
        target: &str,
        route: &str,
        subject: &str,
        lifetime: i64,
        account_bound: bool,
    ) -> Result<()> {
        let token = crypto::token();
        let body=format!("Open this link to continue:\n\n{}{}#token={}\n\nIf you did not request this, ignore this message. This link expires and can be used once.\n",self.config.origin,route,token);
        let payload = serde_json::to_vec(&EmailPayload {
            to: target.into(),
            subject: subject.into(),
            body,
        })
        .map_err(|_| Error::unavailable())?;
        let payload = self.secrets.seal(&payload, "email-outbox/v1")?;
        let r=one(tx,"INSERT INTO auth_email_tokens(user_id,purpose,token_hash,expires_at,target_email,user_version) VALUES($1,$2,$3,now()+($4::bigint * interval '1 second'),$5,$6) RETURNING id",vec![uid(&a.user.id),purpose.into(),crypto::hash(&token).into(),lifetime.into(),if account_bound{Some(target.to_string())}else{None}.into(),if account_bound{Some(a.version)}else{None}.into()]).await?;
        let id: uuid::Uuid = get(&r, "id")?;
        exec(
            tx,
            "INSERT INTO auth_email_outbox(token_id,payload) VALUES($1,$2)",
            vec![id.into(), payload.into()],
        )
        .await?;
        Ok(())
    }
    pub async fn account_notice(
        &self,
        tx: &DatabaseTransaction,
        a: &Account,
        subject: &str,
        body: &str,
    ) -> Result<()> {
        let data = serde_json::to_vec(&EmailPayload {
            to: a.user.email.clone(),
            subject: subject.into(),
            body: body.into(),
        })
        .map_err(|_| Error::unavailable())?;
        let encrypted = self.secrets.seal(&data, "email-outbox/v1")?;
        let r=one(tx,"INSERT INTO auth_email_tokens(user_id,purpose,token_hash,expires_at) VALUES($1,'security_notice',$2,now()+interval '7 days') RETURNING id",vec![uid(&a.user.id),crypto::hash(&crypto::token()).into()]).await?;
        exec(
            tx,
            "INSERT INTO auth_email_outbox(token_id,payload) VALUES($1,$2)",
            vec![get::<uuid::Uuid>(&r, "id")?.into(), encrypted.into()],
        )
        .await?;
        Ok(())
    }
    pub async fn deliver_email(&self) -> Result<bool> {
        let tx = self.db.begin().await?;
        let Some(r)=optional(&tx,"SELECT o.id,o.payload,(t.consumed_at IS NULL AND t.expires_at>now()) AS usable,o.attempts FROM auth_email_outbox o JOIN auth_email_tokens t ON t.id=o.token_id WHERE o.completed_at IS NULL AND o.next_attempt_at<=now() ORDER BY o.created_at LIMIT 1 FOR UPDATE OF o SKIP LOCKED",vec![]).await? else{return Ok(false)};
        let id: uuid::Uuid = get(&r, "id")?;
        if get::<bool>(&r, "usable")? {
            let plain = self
                .secrets
                .open(&get::<Vec<u8>>(&r, "payload")?, "email-outbox/v1")?;
            let message: EmailPayload =
                serde_json::from_slice(&plain).map_err(|_| Error::unavailable())?;
            let delivered = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                self.mailer
                    .send(&message.to, &message.subject, &message.body),
            )
            .await;
            if !matches!(delivered, Ok(Ok(()))) {
                let attempts: i32 = get(&r, "attempts")?;
                let delay = 1_i64 << attempts.clamp(0, 8);
                exec(&tx,"UPDATE auth_email_outbox SET attempts=attempts+1,next_attempt_at=now()+($2::bigint * interval '1 second') WHERE id=$1",vec![id.into(),delay.into()]).await?;
                tx.commit().await?;
                return Err(Error::unavailable());
            }
        }
        exec(
            &tx,
            "UPDATE auth_email_outbox SET completed_at=now(),payload=''::bytea WHERE id=$1",
            vec![id.into()],
        )
        .await?;
        tx.commit().await?;
        Ok(true)
    }
    pub async fn email_loop(&self, stop: CancellationToken) {
        loop {
            for _ in 0..20 {
                let result = tokio::select! {_ = stop.cancelled()=>return,r=tokio::time::timeout(std::time::Duration::from_secs(7),self.deliver_email())=>r};
                match result {
                    Ok(Ok(true)) => {}
                    Ok(Ok(false)) => break,
                    _ => {
                        tracing::warn!("auth_email_delivery_retry");
                        break;
                    }
                }
            }
            tokio::select! {_ = stop.cancelled()=>return,_ = tokio::time::sleep(std::time::Duration::from_secs(2))=>{}}
        }
    }
    pub async fn consume_email(&self, token: &str, purpose: &str, password: &str) -> Result<()> {
        if !crypto::valid_token(token) {
            return Err(Error::link());
        }
        let password_hash = if purpose == "reset" {
            crypto::password(password)?;
            self.passwords.password_hash(password).await?
        } else {
            String::new()
        };
        let tx = self.db.begin().await?;
        let r = optional(
            &tx,
            "SELECT user_id FROM auth_email_tokens WHERE token_hash=$1 AND purpose=$2",
            vec![crypto::hash(token).into(), purpose.into()],
        )
        .await?
        .ok_or_else(Error::link)?;
        let id: uuid::Uuid = get(&r, "user_id")?;
        let r = one(
            &tx,
            "SELECT closure_requested_at IS NOT NULL AS closing FROM users WHERE id=$1 FOR UPDATE",
            vec![id.into()],
        )
        .await?;
        if get::<bool>(&r, "closing")? {
            return Err(Error::link());
        }
        if exec(&tx,"UPDATE auth_email_tokens SET consumed_at=now() WHERE token_hash=$1 AND purpose=$2 AND consumed_at IS NULL AND expires_at>now()",vec![crypto::hash(token).into(),purpose.into()]).await?!=1{return Err(Error::link())}
        match purpose {
            "verification" => {
                exec(
                    &tx,
                    "UPDATE users SET email_verified=true,updated_at=now() WHERE id=$1",
                    vec![id.into()],
                )
                .await?;
                exec(&tx,"UPDATE auth_sessions SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL",vec![id.into()]).await?;
            }
            "reset" => {
                exec(&tx,"UPDATE users SET password_hash=$2,security_version=security_version+1,updated_at=now() WHERE id=$1",vec![id.into(),password_hash.into()]).await?;
                exec(&tx,"UPDATE auth_sessions SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL",vec![id.into()]).await?;
                exec(&tx,"UPDATE auth_email_tokens SET consumed_at=now() WHERE user_id=$1 AND purpose<>'security_notice' AND consumed_at IS NULL",vec![id.into()]).await?;
            }
            _ => return Err(Error::validation("Invalid email operation.")),
        }
        tx.commit().await?;
        Ok(())
    }
    pub async fn change_password(
        &self,
        s: &mut Session,
        peer: &str,
        old: &str,
        password: &str,
        code: &str,
    ) -> Result<()> {
        self.reauthenticate(s, peer, old, code).await?;
        crypto::password(password)?;
        let hash = self.passwords.password_hash(password).await?;
        let tx = self.db.begin().await?;
        let a = lock_account(&tx, s.user_id()?).await?;
        if a.version != s.user_version {
            return Err(Error::conflict());
        }
        one(&tx,"SELECT id FROM auth_sessions WHERE id=$1 AND revoked_at IS NULL AND expires_at>now() AND recent_auth_at>now()-interval '5 minutes' FOR UPDATE",vec![uid(&s.id)]).await?;
        exec(&tx,"UPDATE users SET password_hash=$2,security_version=security_version+1,updated_at=now() WHERE id=$1",vec![uid(&a.user.id),hash.into()]).await?;
        exec(
            &tx,
            "UPDATE auth_sessions SET revoked_at=now() WHERE user_id=$1",
            vec![uid(&a.user.id)],
        )
        .await?;
        exec(&tx,"UPDATE auth_email_tokens SET consumed_at=now() WHERE user_id=$1 AND purpose<>'security_notice' AND consumed_at IS NULL",vec![uid(&a.user.id)]).await?;
        tx.commit().await?;
        Ok(())
    }
}
pub async fn invalidate_access(tx: &DatabaseTransaction, id: &str) -> Result<()> {
    for q in ["UPDATE auth_sessions SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL","UPDATE auth_email_tokens SET consumed_at=now() WHERE user_id=$1 AND purpose<>'security_notice' AND consumed_at IS NULL","DELETE FROM auth_ceremonies WHERE user_id=$1","DELETE FROM auth_oauth_states WHERE user_id=$1 OR session_id IN(SELECT id FROM auth_sessions WHERE user_id=$1)","DELETE FROM auth_oauth_grants WHERE user_id=$1 OR session_id IN(SELECT id FROM auth_sessions WHERE user_id=$1)"]{exec(tx,q,vec![uid(id)]).await?;}
    Ok(())
}
