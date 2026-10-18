use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
use sea_orm::TransactionTrait;
use sha1::Sha1;
use subtle::ConstantTimeEq;

impl Service {
    pub async fn factor_account(
        &self,
        tx: &DatabaseTransaction,
        s: &Session,
        recent: bool,
        partial: bool,
    ) -> Result<Account> {
        let a = lock_account(tx, s.user_id()?).await?;
        if a.closure_at.is_some() || a.version != s.user_version || !a.user.email_verified {
            return Err(Error::conflict());
        }
        one(tx,"SELECT id FROM auth_sessions WHERE id=$1 AND token_hash=$2 AND revoked_at IS NULL AND expires_at>now() AND user_version=$3 AND ($4 OR NOT $5 OR mfa_verified) AND (NOT $6 OR recent_auth_at>now()-interval '5 minutes') FOR UPDATE",vec![uid(&s.id),crypto::hash(&s.token).into(),a.version.into(),partial.into(),a.totp_enabled.into(),recent.into()]).await?;
        Ok(a)
    }
    pub async fn factor_limit(&self, s: &Session, peer: &str) -> Result<()> {
        let id = s.user_id()?;
        self.throttle(&format!("factor/ip/{peer}"), 30).await?;
        self.throttle(&format!("factor/user/{id}"), 10).await
    }
    pub async fn enroll_totp(&self, s: &Session) -> Result<serde_json::Value> {
        s.recent()?;
        let secret = data_encoding::BASE32_NOPAD.encode(&crypto::random_bytes(20));
        let encrypted = self
            .secrets
            .seal(secret.as_bytes(), &format!("totp/{}", s.user_id()?))?;
        let tx = self.db.begin().await?;
        let a = self.factor_account(&tx, s, true, false).await?;
        if a.totp_enabled {
            return Err(Error::validation("An authenticator is already enrolled."));
        }
        exec(&tx,"INSERT INTO auth_totp(user_id,secret) VALUES($1,$2) ON CONFLICT(user_id) DO UPDATE SET secret=excluded.secret,enabled=false,pending_expires_at=now()+interval '10 minutes',last_step=-1",vec![uid(&a.user.id),encrypted.into()]).await?;
        tx.commit().await?;
        let label = format!("Foltivo:{}", a.user.email);
        let mut uri = url::Url::parse("otpauth://totp/").map_err(|_| Error::unavailable())?;
        uri.set_path(&label);
        uri.query_pairs_mut()
            .append_pair("issuer", "Foltivo")
            .append_pair("secret", &secret)
            .append_pair("algorithm", "SHA1")
            .append_pair("digits", "6")
            .append_pair("period", "30");
        Ok(serde_json::json!({"secret":secret,"uri":uri.as_str()}))
    }
    pub async fn consume_totp(
        &self,
        tx: &DatabaseTransaction,
        id: &str,
        code: &str,
        pending: bool,
    ) -> Result<()> {
        if code.len() != 6 || !code.bytes().all(|c| c.is_ascii_digit()) {
            return Err(Error::factor());
        }
        let r=optional(tx,"SELECT secret,last_step FROM auth_totp WHERE user_id=$1 AND enabled=$2 AND (enabled OR pending_expires_at>now()) FOR UPDATE",vec![uid(id),(!pending).into()]).await?.ok_or_else(Error::factor)?;
        let secret = self
            .secrets
            .open(&get::<Vec<u8>>(&r, "secret")?, &format!("totp/{id}"))?;
        let secret = data_encoding::BASE32_NOPAD
            .decode(&secret)
            .map_err(|_| Error::unavailable())?;
        let last: i64 = get(&r, "last_step")?;
        let step = Utc::now().timestamp() / 30;
        let mut accepted = None;
        for candidate in [step, step - 1, step + 1] {
            let mut mac =
                <Hmac<Sha1> as Mac>::new_from_slice(&secret).map_err(|_| Error::unavailable())?;
            mac.update(&(candidate as u64).to_be_bytes());
            let digest = mac.finalize().into_bytes();
            let offset = (digest[19] & 15) as usize;
            let number = u32::from_be_bytes(
                digest[offset..offset + 4]
                    .try_into()
                    .map_err(|_| Error::unavailable())?,
            ) & 0x7fffffff;
            let expected = format!("{:06}", number % 1_000_000);
            if bool::from(expected.as_bytes().ct_eq(code.as_bytes())) && candidate > last {
                accepted = Some(candidate);
                break;
            }
        }
        exec(
            tx,
            "UPDATE auth_totp SET last_step=$2 WHERE user_id=$1",
            vec![uid(id), accepted.ok_or_else(Error::factor)?.into()],
        )
        .await?;
        Ok(())
    }
    pub async fn consume_security_proof(
        &self,
        tx: &DatabaseTransaction,
        id: &str,
        code: &str,
    ) -> Result<()> {
        if code.len() == 6 {
            return self.consume_totp(tx, id, code, false).await;
        }
        let valid = URL_SAFE_NO_PAD
            .decode(code)
            .is_ok_and(|b| b.len() == 16 && URL_SAFE_NO_PAD.encode(b) == code);
        if !valid {
            return Err(Error::factor());
        }
        if exec(tx,"UPDATE auth_recovery_codes SET consumed_at=now() WHERE user_id=$1 AND code_hash=$2 AND consumed_at IS NULL",vec![uid(id),crypto::hash(code).into()]).await?!=1{return Err(Error::factor())}
        Ok(())
    }
    pub async fn confirm_totp(&self, s: &Session, peer: &str, code: &str) -> Result<Vec<String>> {
        s.recent()?;
        self.factor_limit(s, peer).await?;
        let tx = self.db.begin().await?;
        let a = self.factor_account(&tx, s, true, false).await?;
        if a.totp_enabled {
            return Err(Error::conflict());
        }
        self.consume_totp(&tx, &a.user.id, code, true).await?;
        exec(
            &tx,
            "UPDATE auth_totp SET enabled=true WHERE user_id=$1",
            vec![uid(&a.user.id)],
        )
        .await?;
        exec(
            &tx,
            "UPDATE users SET totp_enabled=true WHERE id=$1",
            vec![uid(&a.user.id)],
        )
        .await?;
        let codes = recovery_codes(&tx, &a.user.id).await?;
        factor_change(&tx, &a, s).await?;
        tx.commit().await?;
        Ok(codes)
    }
    pub async fn challenge(
        &self,
        s: &Session,
        peer: &str,
        code: &str,
        recovery: &str,
    ) -> Result<Session> {
        if s.state != "mfa_required" {
            return Err(Error::conflict());
        }
        if code.is_empty() == recovery.is_empty() {
            return Err(Error::validation(
                "Provide one authentication code or recovery code.",
            ));
        }
        self.factor_limit(s, peer).await?;
        let tx = self.db.begin().await?;
        let a = self.factor_account(&tx, s, false, true).await?;
        if !a.totp_enabled {
            return Err(Error::conflict());
        }
        if !recovery.is_empty() {
            if exec(&tx,"UPDATE auth_recovery_codes SET consumed_at=now() WHERE user_id=$1 AND code_hash=$2 AND consumed_at IS NULL",vec![uid(&a.user.id),crypto::hash(recovery).into()]).await?!=1{return Err(Error::factor())}
            exec(
                &tx,
                "UPDATE auth_sessions SET revoked_at=now() WHERE user_id=$1",
                vec![uid(&a.user.id)],
            )
            .await?;
        } else {
            self.consume_totp(&tx, &a.user.id, code, false).await?;
        }
        exec(
            &tx,
            "UPDATE auth_sessions SET revoked_at=now() WHERE id=$1",
            vec![uid(&s.id)],
        )
        .await?;
        let token = crypto::token();
        insert_session(&tx, &token, Some(&a), true, Some(Utc::now())).await?;
        tx.commit().await?;
        self.required_session(&token).await
    }
    pub async fn modify_totp(
        &self,
        s: &Session,
        peer: &str,
        password: &str,
        code: &str,
        remove: bool,
    ) -> Result<Vec<String>> {
        s.authenticated()?;
        self.factor_limit(s, peer).await?;
        crypto::password(password).map_err(|_| Error::invalid_credentials())?;
        let a = self
            .account(&s.user.as_ref().ok_or_else(Error::unauthenticated)?.email)
            .await?
            .ok_or_else(Error::unauthenticated)?;
        if !self.passwords.compare(password, &a.hash).await? {
            return Err(Error::invalid_credentials());
        }
        let tx = self.db.begin().await?;
        let locked = self.factor_account(&tx, s, false, false).await?;
        if a.hash != locked.hash || !locked.totp_enabled {
            return Err(Error::conflict());
        }
        self.consume_security_proof(&tx, &a.user.id, code).await?;
        let codes = if remove {
            exec(
                &tx,
                "UPDATE users SET totp_enabled=false WHERE id=$1",
                vec![uid(&a.user.id)],
            )
            .await?;
            exec(
                &tx,
                "DELETE FROM auth_totp WHERE user_id=$1",
                vec![uid(&a.user.id)],
            )
            .await?;
            exec(
                &tx,
                "DELETE FROM auth_recovery_codes WHERE user_id=$1",
                vec![uid(&a.user.id)],
            )
            .await?;
            vec![]
        } else {
            recovery_codes(&tx, &a.user.id).await?
        };
        factor_change(&tx, &locked, s).await?;
        tx.commit().await?;
        Ok(codes)
    }
    pub async fn reauthenticate(
        &self,
        s: &mut Session,
        peer: &str,
        password: &str,
        code: &str,
    ) -> Result<()> {
        s.authenticated()?;
        if !s.totp_enabled && !code.is_empty() {
            return Err(Error::validation("Unexpected authentication code."));
        }
        crypto::password(password).map_err(|_| Error::invalid_credentials())?;
        self.throttle(&format!("reauth/ip/{peer}"), 30).await?;
        self.throttle(&format!("reauth/user/{}", s.user_id()?), 10)
            .await?;
        let a = self
            .account(&s.user.as_ref().ok_or_else(Error::unauthenticated)?.email)
            .await?
            .ok_or_else(Error::unauthenticated)?;
        if !self.passwords.compare(password, &a.hash).await? {
            return Err(Error::invalid_credentials());
        }
        let tx = self.db.begin().await?;
        let locked = self.factor_account(&tx, s, false, false).await?;
        if locked.hash != a.hash {
            return Err(Error::conflict());
        }
        if locked.totp_enabled {
            self.consume_security_proof(&tx, &a.user.id, code).await?;
            if code.len() != 6 {
                factor_change(&tx, &locked, s).await?;
                s.user_version = locked.version + 1;
            }
        }
        exec(
            &tx,
            "UPDATE auth_sessions SET recent_auth_at=now() WHERE id=$1",
            vec![uid(&s.id)],
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }
}
pub async fn recovery_codes(tx: &DatabaseTransaction, id: &str) -> Result<Vec<String>> {
    exec(
        tx,
        "DELETE FROM auth_recovery_codes WHERE user_id=$1",
        vec![uid(id)],
    )
    .await?;
    let mut codes = vec![];
    for _ in 0..10 {
        let code = URL_SAFE_NO_PAD.encode(crypto::random_bytes(16));
        exec(
            tx,
            "INSERT INTO auth_recovery_codes(user_id,code_hash) VALUES($1,$2)",
            vec![uid(id), crypto::hash(&code).into()],
        )
        .await?;
        codes.push(code)
    }
    Ok(codes)
}
pub async fn factor_change(tx: &DatabaseTransaction, a: &Account, s: &Session) -> Result<()> {
    exec(
        tx,
        "UPDATE users SET security_version=security_version+1,updated_at=now() WHERE id=$1",
        vec![uid(&a.user.id)],
    )
    .await?;
    exec(tx,"UPDATE auth_sessions SET revoked_at=now() WHERE user_id=$1 AND id<>$2 AND revoked_at IS NULL",vec![uid(&a.user.id),uid(&s.id)]).await?;
    exec(tx,"UPDATE auth_sessions SET user_version=$2,mfa_verified=true,recent_auth_at=now() WHERE id=$1",vec![uid(&s.id),(a.version+1).into()]).await?;
    exec(
        tx,
        "DELETE FROM auth_ceremonies WHERE user_id=$1",
        vec![uid(&a.user.id)],
    )
    .await?;
    Ok(())
}
