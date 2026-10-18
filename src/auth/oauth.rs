use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use foltivo_database::entities::auth_oauth_identities;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, TransactionTrait};
use serde::Deserialize;
use serde_json::{json, Value as Json};

pub struct OAuthCallback {
    pub operation: String,
    pub grant: String,
}
impl Service {
    pub async fn providers(&self, s: &Session) -> Result<Vec<Json>> {
        let mut result = vec![];
        for provider in ["github", "google"] {
            let mut item = json!({"provider":provider,"configured":self.config.providers.contains_key(provider),"linked":false});
            if s.user.is_some() {
                s.authenticated()?;
                let id = uuid::Uuid::parse_str(s.user_id()?).map_err(|_| Error::unavailable())?;
                if let Some(row) = auth_oauth_identities::Entity::find()
                    .filter(auth_oauth_identities::Column::UserId.eq(id))
                    .filter(auth_oauth_identities::Column::Provider.eq(provider))
                    .one(&self.db)
                    .await?
                {
                    item["linked"] = json!(true);
                    item["linkedAt"] = json!(row.created_at);
                }
            }
            result.push(item)
        }
        Ok(result)
    }
    pub async fn begin_oauth(
        &self,
        s: &Session,
        peer: &str,
        provider: &str,
        operation: &str,
    ) -> Result<String> {
        let cfg = self
            .config
            .providers
            .get(provider)
            .ok_or_else(Error::unavailable)?;
        if operation != "login" && operation != "link" {
            return Err(Error::validation("Invalid provider operation."));
        }
        if operation == "link" {
            s.recent()?;
        } else if s.user.is_some() {
            return Err(Error::conflict());
        }
        self.throttle(&format!("oauth/start/{peer}"), 30).await?;
        let state = crypto::token();
        let verifier = crypto::token();
        let nonce = crypto::token();
        let encrypted = self.secrets.seal(verifier.as_bytes(), "oauth-pkce/v1")?;
        let tx = self.db.begin().await?;
        let (user, version) = if operation == "link" {
            let a = self.factor_account(&tx, s, true, false).await?;
            (
                Some(uuid::Uuid::parse_str(&a.user.id).map_err(|_| Error::unavailable())?),
                Some(a.version),
            )
        } else {
            self.anonymous_active(&tx, s).await?;
            (None, None)
        };
        exec(
            &tx,
            "DELETE FROM auth_oauth_states WHERE session_id=$1 AND provider=$2",
            vec![uid(&s.id), provider.into()],
        )
        .await?;
        exec(&tx,"INSERT INTO auth_oauth_states(state_hash,session_id,user_id,user_version,provider,operation,pkce_verifier,nonce,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,now()+interval '5 minutes')",vec![crypto::hash(&state).into(),uid(&s.id),user.into(),version.into(),provider.into(),operation.into(),encrypted.into(),nonce.clone().into()]).await?;
        tx.commit().await?;
        let mut url = url::Url::parse(if provider == "github" {
            "https://github.com/login/oauth/authorize"
        } else {
            "https://accounts.google.com/o/oauth2/v2/auth"
        })
        .map_err(|_| Error::unavailable())?;
        url.query_pairs_mut()
            .append_pair("client_id", &cfg.client_id)
            .append_pair("redirect_uri", &cfg.redirect_url)
            .append_pair("response_type", "code")
            .append_pair("state", &state)
            .append_pair(
                "code_challenge",
                &URL_SAFE_NO_PAD.encode(crypto::hash(&verifier)),
            )
            .append_pair("code_challenge_method", "S256")
            .append_pair("nonce", &nonce)
            .append_pair("prompt", "select_account");
        if provider == "google" {
            url.query_pairs_mut().append_pair("scope", "openid");
        }
        Ok(url.into())
    }
    pub async fn finish_oauth(
        &self,
        s: &Session,
        peer: &str,
        provider: &str,
        state: &str,
        code: &str,
    ) -> Result<OAuthCallback> {
        let cfg = self
            .config
            .providers
            .get(provider)
            .ok_or_else(Error::unavailable)?;
        let invalid = || Error::validation("Provider confirmation is invalid or expired.");
        if !crypto::valid_token(state) || code.len() > 4096 {
            return Err(invalid());
        }
        self.throttle(&format!("oauth/callback/{peer}"), 30).await?;
        let r=optional(&self.db,"UPDATE auth_oauth_states o SET consumed_at=now() FROM auth_sessions s WHERE o.state_hash=$1 AND o.provider=$2 AND o.session_id=$3 AND s.id=o.session_id AND s.token_hash=$4 AND s.revoked_at IS NULL AND s.expires_at>now() AND o.expires_at>now() AND o.consumed_at IS NULL AND (o.user_id IS NULL OR (o.user_id=s.user_id AND o.user_version=s.user_version)) RETURNING o.operation,o.pkce_verifier,o.nonce,o.user_id::text AS user_id,o.user_version",vec![crypto::hash(state).into(),provider.into(),uid(&s.id),crypto::hash(&s.token).into()]).await?.ok_or_else(invalid)?;
        if code.is_empty() {
            return Err(Error::validation(
                "Provider confirmation was cancelled. Start again.",
            ));
        }
        let operation: String = get(&r, "operation")?;
        let user: Option<String> = get(&r, "user_id")?;
        let version: Option<i64> = get(&r, "user_version")?;
        if operation == "link"
            && (s.user.is_none()
                || user.as_deref() != Some(s.user_id()?)
                || version != Some(s.user_version))
        {
            return Err(Error::conflict());
        }
        if operation == "login" && s.user.is_some() {
            return Err(Error::conflict());
        }
        let verifier = String::from_utf8(
            self.secrets
                .open(&get::<Vec<u8>>(&r, "pkce_verifier")?, "oauth-pkce/v1")?,
        )
        .map_err(|_| Error::unavailable())?;
        let response = self
            .client
            .post(if provider == "github" {
                "https://github.com/login/oauth/access_token"
            } else {
                "https://oauth2.googleapis.com/token"
            })
            .header("Accept", "application/json")
            .form(&[
                ("client_id", cfg.client_id.as_str()),
                ("client_secret", cfg.client_secret.as_str()),
                ("redirect_uri", cfg.redirect_url.as_str()),
                ("grant_type", "authorization_code"),
                ("code", code),
                ("code_verifier", verifier.as_str()),
            ])
            .send()
            .await
            .map_err(|_| Error::validation("Provider confirmation failed. Start again."))?;
        let token = bounded_json(response)
            .await
            .map_err(|_| Error::validation("Provider confirmation failed. Start again."))?;
        let nonce: String = get(&r, "nonce")?;
        let subject = self
            .oauth_subject(provider, &cfg.client_id, &nonce, &token)
            .await?;
        let tx = self.db.begin().await?;
        if operation == "link" {
            let a = self.factor_account(&tx, s, true, false).await?;
            exec(
                &tx,
                "INSERT INTO auth_oauth_identities(user_id,provider,subject) VALUES($1,$2,$3)",
                vec![uid(&a.user.id), provider.into(), subject.into()],
            )
            .await
            .map_err(|_| {
                Error::new(
                    409,
                    "provider_conflict",
                    "This provider is already linked to an account.",
                )
            })?;
            tx.commit().await?;
            return Ok(OAuthCallback {
                operation,
                grant: String::new(),
            });
        }
        let a=account_query(&tx,"JOIN auth_oauth_identities i ON i.user_id=u.id WHERE i.provider=$1 AND i.subject=$2 FOR UPDATE OF u",vec![provider.into(),subject.clone().into()]).await?.filter(|a|a.user.email_verified && a.closure_at.is_none()).ok_or_else(Error::invalid_credentials)?;
        let linked=one(&tx,"SELECT EXISTS(SELECT 1 FROM auth_oauth_identities WHERE user_id=$1 AND provider=$2 AND subject=$3) AS linked",vec![uid(&a.user.id),provider.into(),subject.clone().into()]).await?;
        if !get::<bool>(&linked, "linked")? {
            return Err(Error::invalid_credentials());
        }
        self.anonymous_active(&tx, s).await?;
        let grant = crypto::token();
        exec(&tx,"INSERT INTO auth_oauth_grants(token_hash,session_id,user_id,user_version,provider,subject,expires_at) VALUES($1,$2,$3,$4,$5,$6,now()+interval '2 minutes')",vec![crypto::hash(&grant).into(),uid(&s.id),uid(&a.user.id),a.version.into(),provider.into(),subject.into()]).await?;
        tx.commit().await?;
        Ok(OAuthCallback { operation, grant })
    }
    async fn oauth_subject(
        &self,
        provider: &str,
        client_id: &str,
        nonce: &str,
        token: &Json,
    ) -> Result<String> {
        let invalid = || Error::validation("Provider identity could not be verified. Start again.");
        if provider == "google" {
            let raw = token
                .get("id_token")
                .and_then(Json::as_str)
                .ok_or_else(invalid)?;
            let header = jsonwebtoken::decode_header(raw).map_err(|_| invalid())?;
            if header.alg != jsonwebtoken::Algorithm::RS256 {
                return Err(invalid());
            }
            let discovery = bounded_json(
                self.client
                    .get("https://accounts.google.com/.well-known/openid-configuration")
                    .send()
                    .await
                    .map_err(|_| Error::unavailable())?,
            )
            .await?;
            let issuer = discovery
                .get("issuer")
                .and_then(Json::as_str)
                .filter(|v| *v == "https://accounts.google.com")
                .ok_or_else(invalid)?;
            let jwks_url = discovery
                .get("jwks_uri")
                .and_then(Json::as_str)
                .ok_or_else(invalid)?;
            if !jwks_url.starts_with("https://") {
                return Err(invalid());
            }
            let jwks: jsonwebtoken::jwk::JwkSet = serde_json::from_value(
                bounded_json(
                    self.client
                        .get(jwks_url)
                        .send()
                        .await
                        .map_err(|_| Error::unavailable())?,
                )
                .await?,
            )
            .map_err(|_| invalid())?;
            let key = jwks
                .find(header.kid.as_deref().ok_or_else(invalid)?)
                .ok_or_else(invalid)?;
            let key = jsonwebtoken::DecodingKey::from_jwk(key).map_err(|_| invalid())?;
            let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
            validation.set_audience(&[client_id]);
            validation.set_issuer(&[issuer, "accounts.google.com"]);
            validation.leeway = 0;
            #[derive(Deserialize)]
            struct Claims {
                sub: String,
                nonce: String,
                exp: u64,
                aud: Json,
                iss: String,
            }
            let identity = jsonwebtoken::decode::<Claims>(raw, &key, &validation)
                .map_err(|_| invalid())?
                .claims;
            if identity.nonce != nonce || identity.sub.is_empty() {
                return Err(invalid());
            }
            return Ok(identity.sub);
        }
        let access = token
            .get("access_token")
            .and_then(Json::as_str)
            .ok_or_else(invalid)?;
        let response = self
            .client
            .get("https://api.github.com/user")
            .bearer_auth(access)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header("User-Agent", "Foltivo")
            .send()
            .await
            .map_err(|_| Error::unavailable())?;
        let identity = bounded_json(response).await.map_err(|_| invalid())?;
        let id = identity
            .get("id")
            .and_then(Json::as_i64)
            .filter(|i| *i > 0)
            .ok_or_else(invalid)?;
        Ok(id.to_string())
    }
    pub async fn unlink_oauth(&self, s: &Session, provider: &str) -> Result<()> {
        if provider != "github" && provider != "google" {
            return Err(Error::validation("Unknown provider."));
        }
        s.recent()?;
        let tx = self.db.begin().await?;
        let a = self.factor_account(&tx, s, true, false).await?;
        if a.hash.is_empty() {
            return Err(Error::validation(
                "Set a password before removing this sign-in method.",
            ));
        }
        if exec(
            &tx,
            "DELETE FROM auth_oauth_identities WHERE user_id=$1 AND provider=$2",
            vec![uid(&a.user.id), provider.into()],
        )
        .await?
            != 1
        {
            return Err(Error::new(404, "not_found", "Provider is not linked."));
        }
        exec(
            &tx,
            "DELETE FROM auth_oauth_states WHERE user_id=$1 AND provider=$2",
            vec![uid(&a.user.id), provider.into()],
        )
        .await?;
        exec(
            &tx,
            "DELETE FROM auth_oauth_grants WHERE user_id=$1 AND provider=$2",
            vec![uid(&a.user.id), provider.into()],
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }
    pub async fn complete_oauth(&self, s: &Session, peer: &str, token: &str) -> Result<Session> {
        if s.user.is_some() {
            return Err(Error::conflict());
        }
        let invalid = || Error::validation("Provider sign-in expired. Start again.");
        if !crypto::valid_token(token) {
            return Err(invalid());
        }
        self.throttle(&format!("oauth/complete/{peer}"), 30).await?;
        let r=optional(&self.db,"SELECT user_id::text AS user_id FROM auth_oauth_grants WHERE token_hash=$1 AND session_id=$2 AND consumed_at IS NULL AND expires_at>now()",vec![crypto::hash(token).into(),uid(&s.id)]).await?.ok_or_else(invalid)?;
        let id: String = get(&r, "user_id")?;
        let tx = self.db.begin().await?;
        let a = lock_account(&tx, &id).await?;
        if !a.user.email_verified || a.closure_at.is_some() {
            return Err(Error::invalid_credentials());
        }
        self.anonymous_active(&tx, s).await?;
        optional(&tx,"UPDATE auth_oauth_grants g SET consumed_at=now() WHERE g.token_hash=$1 AND g.session_id=$2 AND g.user_id=$3 AND g.user_version=$4 AND g.consumed_at IS NULL AND g.expires_at>now() AND EXISTS(SELECT 1 FROM auth_oauth_identities i WHERE i.user_id=g.user_id AND i.provider=g.provider AND i.subject=g.subject) RETURNING provider,subject",vec![crypto::hash(token).into(),uid(&s.id),uid(&a.user.id),a.version.into()]).await?.ok_or_else(invalid)?;
        exec(
            &tx,
            "UPDATE auth_sessions SET revoked_at=now() WHERE id=$1",
            vec![uid(&s.id)],
        )
        .await?;
        let token = crypto::token();
        insert_session(&tx, &token, Some(&a), false, Some(Utc::now())).await?;
        tx.commit().await?;
        self.required_session(&token).await
    }
}
async fn bounded_json(mut response: reqwest::Response) -> Result<Json> {
    if !response.status().is_success() {
        return Err(Error::unavailable());
    }
    let mut bytes = vec![];
    while let Some(chunk) = response.chunk().await.map_err(|_| Error::unavailable())? {
        if bytes.len() + chunk.len() > 65536 {
            return Err(Error::unavailable());
        }
        bytes.extend_from_slice(&chunk)
    }
    serde_json::from_slice(&bytes).map_err(|_| Error::unavailable())
}
