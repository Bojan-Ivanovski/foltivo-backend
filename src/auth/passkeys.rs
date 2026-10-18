use super::*;
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use ciborium::value::Value as Cbor;
use sea_orm::TransactionTrait;
use serde_json::{json, Value as Json};
use webauthn_rs_core::proto::*;

fn to_json<T: serde::Serialize>(v: T) -> Result<Json> {
    serde_json::to_value(v).map_err(|_| Error::unavailable())
}
fn from_json<T: serde::de::DeserializeOwned>(v: Json) -> Result<T> {
    serde_json::from_value(v).map_err(|_| Error::unavailable())
}
fn credential_purpose(id: &str, kid: &[u8]) -> String {
    format!("passkey/{id}/{}", URL_SAFE_NO_PAD.encode(kid))
}
impl Service {
    async fn passkey_credentials(
        &self,
        tx: &DatabaseTransaction,
        a: &Account,
    ) -> Result<Vec<Credential>> {
        let mut credentials = vec![];
        for r in all(tx,"SELECT credential_id,credential FROM auth_passkeys WHERE user_id=$1 ORDER BY created_at",vec![uid(&a.user.id)]).await?{let kid:Vec<u8>=get(&r,"credential_id")?;let plain=self.secrets.open(&get::<Vec<u8>>(&r,"credential")?,&credential_purpose(&a.user.id,&kid))?;let v:Json=serde_json::from_slice(&plain).map_err(|_|Error::unavailable())?;let c:Credential=if let Some(rust)=v.get("rustCredential"){from_json(rust.clone())?}else if v.get("publicKey").is_some(){legacy_credential(&v)?}else{from_json(v)?};if c.cred_id.as_slice()!=kid.as_slice(){return Err(Error::unavailable())}credentials.push(c);}
        Ok(credentials)
    }
    fn registration_builder(
        &self,
        a: &Account,
        credentials: &[Credential],
    ) -> Result<webauthn_rs_core::ChallengeRegisterBuilder> {
        self.webauthn
            .new_challenge_register_builder(a.user.id.as_bytes(), &a.user.email, &a.user.name)
            .map(|b| {
                b.user_verification_policy(UserVerificationPolicy::Required)
                    .require_resident_key(true)
                    .credential_algorithms(
                        COSEAlgorithm::all_possible_algs()
                            .into_iter()
                            .filter(|a| !matches!(a, COSEAlgorithm::INSECURE_RS1))
                            .collect(),
                    )
                    .exclude_credentials(Some(
                        credentials.iter().map(|c| c.cred_id.clone()).collect(),
                    ))
            })
            .map_err(|_| Error::unavailable())
    }
    fn decoy_assertion(&self) -> Result<Json> {
        let b = self
            .webauthn
            .new_challenge_authenticate_builder(vec![], Some(UserVerificationPolicy::Required))
            .map_err(|_| Error::unavailable())?;
        let (options, _) = self
            .webauthn
            .generate_challenge_authenticate(b)
            .map_err(|_| Error::unavailable())?;
        let mut options = to_json(options)?;
        options["publicKey"]
            .as_object_mut()
            .map(|o| o.remove("allowCredentials"));
        Ok(options)
    }
    pub async fn begin_passkey(
        &self,
        s: &Session,
        peer: &str,
        kind: &str,
        value: &str,
    ) -> Result<Json> {
        let name;
        let candidate;
        if kind == "registration" {
            s.recent()?;
            name = crypto::name(value)?;
            self.factor_limit(s, peer).await?;
            candidate = None;
        } else if kind == "login" {
            if s.state != "anonymous" {
                return Err(Error::conflict());
            }
            let email = crypto::email(value).map_err(|_| Error::invalid_credentials())?;
            self.throttle(&format!("passkey/ip/{peer}"), 30).await?;
            self.throttle(&format!("passkey/email/{email}"), 10).await?;
            exec(
                &self.db,
                "DELETE FROM auth_ceremonies WHERE session_id=$1 AND kind='login'",
                vec![uid(&s.id)],
            )
            .await?;
            candidate = self.account(&email).await?;
            if candidate.is_none() {
                return self.decoy_assertion();
            }
            name = String::new();
        } else {
            return Err(Error::validation("Unknown passkey operation."));
        }
        let tx = self.db.begin().await?;
        let a = if kind == "registration" {
            self.factor_account(&tx, s, true, false).await?
        } else {
            let a = lock_account(
                &tx,
                &candidate.ok_or_else(Error::invalid_credentials)?.user.id,
            )
            .await?;
            self.anonymous_active(&tx, s).await?;
            a
        };
        let credentials = self.passkey_credentials(&tx, &a).await?;
        let (mut options, state) = if kind == "registration" {
            if credentials.len() >= 10 {
                return Err(Error::validation("Remove a passkey before adding another."));
            }
            let (options, state) = self
                .webauthn
                .generate_challenge_register(self.registration_builder(&a, &credentials)?)
                .map_err(|_| Error::validation("Unable to start passkey authentication."))?;
            (
                to_json(options)?,
                json!({"rustRegistration":to_json(state)?}),
            )
        } else {
            if credentials.is_empty() {
                return self.decoy_assertion();
            }
            let b = self
                .webauthn
                .new_challenge_authenticate_builder(
                    credentials,
                    Some(UserVerificationPolicy::Required),
                )
                .map_err(|_| Error::unavailable())?;
            let (options, state) = self
                .webauthn
                .generate_challenge_authenticate(b)
                .map_err(|_| Error::validation("Unable to start passkey authentication."))?;
            (
                to_json(options)?,
                json!({"rustAuthentication":to_json(state)?}),
            )
        };
        // Omit allowCredentials on both known and unknown email responses.
        if kind == "login" {
            if let Some(o) = options["publicKey"].as_object_mut() {
                o.remove("allowCredentials");
            }
        }
        exec(&tx,"INSERT INTO auth_ceremonies(session_id,kind,user_id,user_version,data,name,expires_at) VALUES($1,$2,$3,$4,$5,$6,now()+interval '5 minutes') ON CONFLICT(session_id,kind) DO UPDATE SET user_id=excluded.user_id,user_version=excluded.user_version,data=excluded.data,name=excluded.name,expires_at=excluded.expires_at",vec![uid(&s.id),kind.into(),uid(&a.user.id),a.version.into(),state.into(),name.into()]).await?;
        tx.commit().await?;
        Ok(options)
    }
    pub async fn finish_passkey(
        &self,
        s: &Session,
        peer: &str,
        kind: &str,
        body: Json,
    ) -> Result<Option<Session>> {
        if kind == "registration" {
            s.recent()?;
        } else if kind != "login" || s.state != "anonymous" {
            return Err(Error::conflict());
        }
        self.throttle(&format!("passkey-finish/ip/{peer}"), 30)
            .await?;
        // Autocommit burn matches Go: even a malformed finish consumes this attempt.
        let r=optional(&self.db,"DELETE FROM auth_ceremonies WHERE session_id=$1 AND kind=$2 AND expires_at>now() RETURNING user_id::text AS user_id,user_version,data,name",vec![uid(&s.id),kind.into()]).await?.ok_or_else(Error::factor)?;
        let id: String = get(&r, "user_id")?;
        let version: i64 = get(&r, "user_version")?;
        let state: Json = get(&r, "data")?;
        let name: String = get(&r, "name")?;
        let tx = self.db.begin().await?;
        let a = if kind == "registration" {
            let a = self.factor_account(&tx, s, true, false).await?;
            if a.user.id != id || a.version != version {
                return Err(Error::conflict());
            }
            a
        } else {
            let a = lock_account(&tx, &id).await?;
            if a.version != version {
                return Err(Error::conflict());
            }
            self.anonymous_active(&tx, s).await?;
            a
        };
        let credentials = self.passkey_credentials(&tx, &a).await?;
        let credential = if kind == "registration" {
            if credentials.len() >= 10 {
                return Err(Error::validation("Remove a passkey before adding another."));
            }
            let registration: RegistrationState = if let Some(v) = state.get("rustRegistration") {
                from_json(v.clone())?
            } else {
                self.legacy_registration(&a, &credentials, &state)?
            };
            let response: RegisterPublicKeyCredential =
                serde_json::from_value(normalize_extensions(body)).map_err(|_| Error::factor())?;
            self.webauthn
                .register_credential(&response, &registration, None)
                .map_err(|_| Error::factor())?
        } else {
            let mut authentication: AuthenticationState =
                if let Some(v) = state.get("rustAuthentication") {
                    from_json(v.clone())?
                } else {
                    self.legacy_authentication(&credentials, &state)?
                };
            // Re-read credentials under the account lock: another completed login
            // may have advanced a counter since the ceremony began.
            authentication.set_allowed_credentials(credentials.clone());
            let response: PublicKeyCredential =
                serde_json::from_value(normalize_extensions(body)).map_err(|_| Error::factor())?;
            if response
                .get_user_unique_id()
                .is_some_and(|u| !u.is_empty() && u != a.user.id.as_bytes())
            {
                return Err(Error::factor());
            }
            let result = self
                .webauthn
                .authenticate_credential(&response, &authentication)
                .map_err(|_| Error::factor())?;
            if !result.user_verified() {
                return Err(Error::factor());
            }
            let mut c = credentials
                .into_iter()
                .find(|c| &c.cred_id == result.cred_id())
                .ok_or_else(Error::factor)?;
            if (c.counter != 0 || result.counter() != 0) && result.counter() <= c.counter {
                return Err(Error::factor());
            }
            c.counter = result.counter();
            c.user_verified = true;
            c.backup_state = result.backup_state();
            c.backup_eligible = result.backup_eligible();
            c
        };
        if !credential.user_verified {
            return Err(Error::factor());
        }
        let kid = credential.cred_id.as_slice().to_vec();
        let mut record = to_json(&credential)?;
        if kind == "login" {
            if let Some(row) = optional(
                &tx,
                "SELECT credential FROM auth_passkeys WHERE user_id=$1 AND credential_id=$2",
                vec![uid(&a.user.id), kid.clone().into()],
            )
            .await?
            {
                let plain = self.secrets.open(
                    &get::<Vec<u8>>(&row, "credential")?,
                    &credential_purpose(&a.user.id, &kid),
                )?;
                let mut original: Json =
                    serde_json::from_slice(&plain).map_err(|_| Error::unavailable())?;
                if original.get("publicKey").is_some() {
                    // Keep Go-only attestation/extensions and synchronize the
                    // counter/flags used by both implementations. The Go reader
                    // ignores the additive Rust representation.
                    original["authenticator"]["signCount"] = json!(credential.counter);
                    original["authenticator"]["cloneWarning"] = json!(false);
                    original["flags"]["userPresent"] = json!(true);
                    original["flags"]["userVerified"] = json!(credential.user_verified);
                    original["flags"]["backupEligible"] = json!(credential.backup_eligible);
                    original["flags"]["backupState"] = json!(credential.backup_state);
                    original["rustCredential"] = record;
                    record = original;
                }
            }
        }
        let stored = self.secrets.seal(
            &serde_json::to_vec(&record).map_err(|_| Error::unavailable())?,
            &credential_purpose(&a.user.id, &kid),
        )?;
        if kind == "registration" {
            if exec(&tx,"INSERT INTO auth_passkeys(user_id,credential_id,credential,name) VALUES($1,$2,$3,$4) ON CONFLICT(credential_id) DO NOTHING",vec![uid(&a.user.id),kid.into(),stored.into(),name.into()]).await?!=1{return Err(Error::conflict())}
            super::factors::factor_change(&tx, &a, s).await?;
            tx.commit().await?;
            return Ok(None);
        }
        if exec(
            &tx,
            "UPDATE auth_passkeys SET credential=$3 WHERE user_id=$1 AND credential_id=$2",
            vec![uid(&a.user.id), kid.into(), stored.into()],
        )
        .await?
            != 1
        {
            return Err(Error::conflict());
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
        Ok(Some(self.required_session(&token).await?))
    }
    fn legacy_registration(
        &self,
        a: &Account,
        credentials: &[Credential],
        legacy: &Json,
    ) -> Result<RegistrationState> {
        legacy_ceremony(legacy, &self.config.origin, &a.user.id)?;
        let (_, state) = self
            .webauthn
            .generate_challenge_register(self.registration_builder(a, credentials)?)
            .map_err(|_| Error::unavailable())?;
        let mut state = to_json(state)?;
        state["challenge"] = json!(legacy
            .get("challenge")
            .and_then(Json::as_str)
            .ok_or_else(Error::factor)?);
        if let Some(params) = legacy.get("credParams").and_then(Json::as_array) {
            let mut algorithms = vec![];
            for p in params {
                let alg = p
                    .get("alg")
                    .and_then(Json::as_i64)
                    .ok_or_else(Error::factor)?;
                algorithms.push(to_json(
                    COSEAlgorithm::try_from(alg as i128).map_err(|_| Error::factor())?,
                )?)
            }
            if !algorithms.is_empty() {
                state["credential_algorithms"] = json!(algorithms);
            }
        }
        from_json(state)
    }
    fn legacy_authentication(
        &self,
        credentials: &[Credential],
        legacy: &Json,
    ) -> Result<AuthenticationState> {
        legacy_ceremony(legacy, &self.config.origin, "")?;
        let b = self
            .webauthn
            .new_challenge_authenticate_builder(
                credentials.to_vec(),
                Some(UserVerificationPolicy::Required),
            )
            .map_err(|_| Error::unavailable())?;
        let (_, state) = self
            .webauthn
            .generate_challenge_authenticate(b)
            .map_err(|_| Error::unavailable())?;
        let mut state = to_json(state)?;
        state["challenge"] = json!(legacy
            .get("challenge")
            .and_then(Json::as_str)
            .ok_or_else(Error::factor)?);
        from_json(state)
    }
}
fn normalize_extensions(mut body: Json) -> Json {
    if let Some(ext) = body.get("clientExtensionResults").cloned() {
        body["extensions"] = ext;
    }
    body
}
fn legacy_ceremony(v: &Json, origin: &str, id: &str) -> Result<()> {
    if let Some(o) = v.get("origin").and_then(Json::as_str) {
        if !o.is_empty() && o != origin {
            return Err(Error::factor());
        }
    }
    if let Some(rp) = v.get("rpId").and_then(Json::as_str) {
        let u = url::Url::parse(origin).map_err(|_| Error::factor())?;
        if !rp.is_empty() && Some(rp) != u.host_str() {
            return Err(Error::factor());
        }
    }
    if let Some(expires) = v.get("expires").and_then(Json::as_str) {
        let t = DateTime::parse_from_rfc3339(expires).map_err(|_| Error::factor())?;
        if t.year() > 1 && t.with_timezone(&Utc) <= Utc::now() {
            return Err(Error::factor());
        }
    }
    if !id.is_empty() {
        if let Some(user) = v.get("user_id").and_then(Json::as_str) {
            let u = decode_go(user)?;
            if u != id.as_bytes() {
                return Err(Error::factor());
            }
        }
    }
    Ok(())
}
use chrono::Datelike;
fn decode_go(v: &str) -> Result<Vec<u8>> {
    STANDARD
        .decode(v)
        .or_else(|_| URL_SAFE_NO_PAD.decode(v))
        .map_err(|_| Error::unavailable())
}
fn legacy_credential(v: &Json) -> Result<Credential> {
    let kid = decode_go(
        v.get("id")
            .and_then(Json::as_str)
            .ok_or_else(Error::unavailable)?,
    )?;
    let public = decode_go(
        v.get("publicKey")
            .and_then(Json::as_str)
            .ok_or_else(Error::unavailable)?,
    )?;
    let cbor: Cbor =
        ciborium::de::from_reader(public.as_slice()).map_err(|_| Error::unavailable())?;
    let map = cbor.as_map().ok_or_else(Error::unavailable)?;
    let item = |n: i128| -> Result<&Cbor> {
        map.iter()
            .find_map(|(k, v)| {
                if k.as_integer().is_some_and(|i| i128::from(i) == n) {
                    Some(v)
                } else {
                    None
                }
            })
            .ok_or_else(Error::unavailable)
    };
    let int = |n| -> Result<i128> {
        item(n)?
            .as_integer()
            .map(i128::from)
            .ok_or_else(Error::unavailable)
    };
    let bin =
        |n| -> Result<Vec<u8>> { item(n)?.as_bytes().cloned().ok_or_else(Error::unavailable) };
    let alg = COSEAlgorithm::try_from(int(3)?).map_err(|_| Error::unavailable())?;
    let key = match int(1)? {
        1 => COSEKeyType::EC_OKP(COSEOKPKey {
            curve: match int(-1)? {
                6 => EDDSACurve::ED25519,
                7 => EDDSACurve::ED448,
                _ => return Err(Error::unavailable()),
            },
            x: bin(-2)?.into(),
        }),
        2 => COSEKeyType::EC_EC2(COSEEC2Key {
            curve: match int(-1)? {
                1 => ECDSACurve::SECP256R1,
                2 => ECDSACurve::SECP384R1,
                3 => ECDSACurve::SECP521R1,
                _ => return Err(Error::unavailable()),
            },
            x: bin(-2)?.into(),
            y: bin(-3)?.into(),
        }),
        3 => {
            let exponent = bin(-2)?;
            if exponent.len() > 3 {
                return Err(Error::unavailable());
            }
            let mut e = [0u8; 3];
            e[3 - exponent.len()..].copy_from_slice(&exponent);
            COSEKeyType::RSA(COSERSAKey {
                n: bin(-1)?.into(),
                e,
            })
        }
        _ => return Err(Error::unavailable()),
    };
    // Transports are browser hints, not authentication policy. Preserve their
    // original JSON above while ignoring newer/unknown hints in the Rust view.
    let transports = v.get("transport").and_then(Json::as_array).map(|items| {
        items
            .iter()
            .filter_map(|v| serde_json::from_value::<AuthenticatorTransport>(v.clone()).ok())
            .collect()
    });
    Ok(Credential {
        cred_id: kid.into(),
        cred: COSEKey { type_: alg, key },
        counter: v
            .pointer("/authenticator/signCount")
            .and_then(Json::as_u64)
            .unwrap_or(0) as u32,
        transports,
        user_verified: v
            .pointer("/flags/userVerified")
            .and_then(Json::as_bool)
            .unwrap_or(false),
        backup_eligible: v
            .pointer("/flags/backupEligible")
            .and_then(Json::as_bool)
            .unwrap_or(false),
        backup_state: v
            .pointer("/flags/backupState")
            .and_then(Json::as_bool)
            .unwrap_or(false),
        registration_policy: UserVerificationPolicy::Required,
        extensions: RegisteredExtensions::none(),
        attestation: ParsedAttestation {
            data: ParsedAttestationData::None,
            metadata: AttestationMetadata::None,
        },
        attestation_format: AttestationFormat::None,
    })
}
