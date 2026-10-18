use crate::auth::{Error, Result, Service, Session};
use axum::{
    body::{to_bytes, Body},
    extract::{ConnectInfo, Request, State},
    http::{header, HeaderMap, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
    Json, Router,
};
use serde::{
    de::{self, MapAccess, Visitor},
    Deserializer,
};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    fmt,
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use subtle::ConstantTimeEq;

pub fn router(service: Service) -> Router {
    Router::new().fallback(dispatch).with_state(service)
}
async fn dispatch(
    State(service): State<Service>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    request: Request,
) -> Response {
    let path = request.uri().path().to_owned();
    let method = request.method().clone();
    let mut response = if path == "/health" && (method == Method::GET || method == Method::HEAD) {
        json_response(200, json!({"status":"ok"}))
    } else if path == "/ready" && (method == Method::GET || method == Method::HEAD) {
        use sea_orm::ConnectionTrait;
        match tokio::time::timeout(Duration::from_secs(2), service.db.ping()).await {
            Ok(Ok(())) => json_response(200, json!({"status":"ready"})),
            _ => json_response(503, json!({"status":"unavailable"})),
        }
    } else {
        let callback = path.starts_with("/api/v1/auth/providers/")
            && path.ends_with("/callback")
            && (method == Method::GET || method == Method::HEAD);
        let timeout = if callback { 15 } else { 7 };
        match tokio::time::timeout(
            Duration::from_secs(timeout),
            handle(&service, remote, request),
        )
        .await
        {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => e.into_response(),
            Err(_) => Error::unavailable().into_response(),
        }
    };
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if path.starts_with("/api/") {
        response.headers_mut().insert(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        );
    }
    if method == Method::HEAD {
        *response.body_mut() = Body::empty();
    }
    response
}
fn json_response(status: u16, value: Value) -> Response {
    (
        StatusCode::from_u16(status).unwrap_or(StatusCode::OK),
        Json(value),
    )
        .into_response()
}
fn message(status: u16, text: &str) -> Response {
    json_response(status, json!({"message":text}))
}
fn header_str<'a>(h: &'a HeaderMap, key: &str) -> &'a str {
    h.get(key).and_then(|v| v.to_str().ok()).unwrap_or("")
}
fn user_agent(headers: &HeaderMap) -> String {
    let Some(value) = headers.get(header::USER_AGENT) else {
        return String::new();
    };
    let mut remaining = value.as_bytes();
    let mut agent = String::new();
    while !remaining.is_empty() {
        match std::str::from_utf8(remaining) {
            Ok(valid) => {
                agent.push_str(valid);
                break;
            }
            Err(error) => {
                // Match strings.ToValidUTF8(agent, "") without discarding
                // legitimate non-ASCII display metadata or replacement runes.
                let valid = &remaining[..error.valid_up_to()];
                if let Ok(valid) = std::str::from_utf8(valid) {
                    agent.push_str(valid);
                }
                let skip = error.valid_up_to()
                    + error
                        .error_len()
                        .unwrap_or(remaining.len() - error.valid_up_to());
                remaining = &remaining[skip..];
            }
        }
    }
    agent
}
fn token(h: &HeaderMap, name: &str) -> String {
    h.get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|v| {
            v.trim()
                .split_once('=')
                .filter(|(k, _)| *k == name)
                .map(|(_, v)| v.trim_matches('"').to_owned())
        })
        .unwrap_or_default()
}
fn cookie(service: &Service, response: &mut Response, s: Option<&Session>) {
    let secure = if service.config.secure_cookies {
        "; Secure"
    } else {
        ""
    };
    let value = if let Some(s) = s {
        format!(
            "{}={}; Path=/; HttpOnly; SameSite=Lax{}; Expires={}; Max-Age={}",
            service.config.cookie_name(),
            s.token,
            secure,
            s.expires_at.format("%a, %d %b %Y %H:%M:%S GMT"),
            (s.expires_at - chrono::Utc::now()).num_seconds().max(1)
        )
    } else {
        format!(
            "{}=; Path=/; HttpOnly; SameSite=Lax{}; Max-Age=0",
            service.config.cookie_name(),
            secure
        )
    };
    if let Ok(v) = value.parse() {
        response.headers_mut().append(header::SET_COOKIE, v);
    }
}
fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(i) => i.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(i)),
        v => v,
    }
}
fn peer(service: &Service, remote: SocketAddr, h: &HeaderMap) -> String {
    let direct = normalize_ip(remote.ip());
    let trusted = |ip: &IpAddr| {
        service
            .config
            .trusted_proxies
            .iter()
            .any(|p| p.contains(ip))
    };
    if !trusted(&direct) {
        return direct.to_string();
    }
    let vals: Vec<_> = h.get_all("x-forwarded-for").iter().collect();
    if vals.len() != 1 {
        return direct.to_string();
    }
    let Ok(raw) = vals[0].to_str() else {
        return direct.to_string();
    };
    if raw.len() > 1024 {
        return direct.to_string();
    }
    let parts: Vec<_> = raw.split(',').collect();
    if parts.len() > 16 {
        return direct.to_string();
    }
    let mut chain = vec![];
    for p in parts {
        let Ok(ip) = p.trim().parse::<IpAddr>() else {
            return direct.to_string();
        };
        chain.push(normalize_ip(ip));
    }
    let mut address = direct;
    for ip in chain.iter().rev() {
        address = *ip;
        if !trusted(ip) {
            break;
        }
    }
    address.to_string()
}

// Match the Go decoder: bounded object, no duplicate top-level keys, no null
// values, unknown DTO fields rejected and no trailing JSON values.
struct StrictObject;
impl<'de> Visitor<'de> for StrictObject {
    type Value = serde_json::Map<String, Value>;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a JSON object")
    }
    fn visit_map<M: MapAccess<'de>>(
        self,
        mut access: M,
    ) -> std::result::Result<Self::Value, M::Error> {
        let mut map = serde_json::Map::new();
        while let Some((key, value)) = access.next_entry::<String, Value>()? {
            if map.contains_key(&key) {
                return Err(de::Error::custom("duplicate field"));
            }
            if value.is_null() {
                return Err(de::Error::custom("null value"));
            }
            map.insert(key, value);
        }
        Ok(map)
    }
}
async fn body(request: Request, fields: Option<&[&str]>) -> Result<Value> {
    let content = header_str(request.headers(), "content-type")
        .parse::<mime::Mime>()
        .map_err(|_| Error::validation("Send a JSON request body."))?;
    if content.essence_str() != "application/json" {
        return Err(Error::validation("Send a JSON request body."));
    }
    let bytes = to_bytes(request.into_body(), 16 * 1024)
        .await
        .map_err(|_| Error::validation("Request body is invalid or too large."))?;
    let mut d = serde_json::Deserializer::from_slice(&bytes);
    let map = d.deserialize_map(StrictObject).map_err(|e| {
        let text = e.to_string();
        Error::validation(if text.contains("duplicate field") {
            "Request body has duplicate or invalid fields."
        } else if text.contains("null value") {
            "Request body has invalid values."
        } else if !bytes
            .iter()
            .find(|b| !b.is_ascii_whitespace())
            .is_some_and(|b| *b == b'{')
        {
            "Send a JSON object."
        } else {
            "Request body is invalid or too large."
        })
    })?;
    d.end()
        .map_err(|_| Error::validation("Send exactly one JSON object."))?;
    if let Some(fields) = fields {
        for (k, v) in &map {
            if !fields.contains(&k.as_str()) || !v.is_string() {
                return Err(Error::validation("Request body is invalid or too large."));
            }
        }
    }
    Ok(Value::Object(map))
}
fn text<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or("")
}

async fn handle(service: &Service, remote: SocketAddr, request: Request) -> Result<Response> {
    let method = request.method().clone();
    let effective = if method == Method::HEAD {
        Method::GET
    } else {
        method.clone()
    };
    let path = request.uri().path().to_owned();
    let headers = request.headers().clone();
    let peer = peer(service, remote, &headers);
    let token = token(&headers, service.config.cookie_name());
    if let Some(provider) = path
        .strip_prefix("/api/v1/auth/providers/")
        .and_then(|p| p.strip_suffix("/callback"))
        .filter(|p| !p.is_empty() && !p.contains('/'))
    {
        if effective == Method::GET {
            return callback(
                service,
                &token,
                &peer,
                provider,
                request.uri().query().unwrap_or(""),
            )
            .await;
        }
    }
    let route = route(&path, &effective);
    let Some((action, arg)) = route else {
        let mut allowed = Vec::new();
        for candidate in [Method::GET, Method::POST, Method::PATCH, Method::DELETE] {
            let callback_path =
                path.starts_with("/api/v1/auth/providers/") && path.ends_with("/callback");
            if self::route(&path, &candidate).is_some()
                || (callback_path && candidate == Method::GET)
            {
                allowed.push(candidate.as_str().to_owned());
                if candidate == Method::GET {
                    allowed.push("HEAD".into());
                }
            }
        }
        if !allowed.is_empty() {
            allowed.sort();
            let mut response =
                (StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed\n").into_response();
            if let Ok(value) = allowed.join(", ").parse() {
                response.headers_mut().insert(header::ALLOW, value);
            }
            return Ok(response);
        }
        return Ok((StatusCode::NOT_FOUND, "404 page not found\n").into_response());
    };
    let mutation = effective != Method::GET;
    if mutation && header_str(&headers, "origin") != service.config.origin {
        return Err(Error::new(
            403,
            "origin_rejected",
            "Request origin is not trusted.",
        ));
    }
    let mut session = service.session(&token, &peer, action == "session").await?;
    if mutation
        && !bool::from(
            header_str(&headers, "x-csrf-token")
                .as_bytes()
                .ct_eq(session.csrf_token.as_bytes()),
        )
    {
        return Err(Error::new(
            403,
            "csrf_rejected",
            "Reload this page and try again.",
        ));
    }
    service
        .observe_session(&session, &user_agent(&headers))
        .await?;
    let response = match action {
        "session" => {
            let mut response = json_response(
                200,
                serde_json::to_value(&session).map_err(|_| Error::unavailable())?,
            );
            if session.token != token {
                cookie(service, &mut response, Some(&session));
            }
            response
        }
        "register" => {
            session.anonymous()?;
            let b = body(request, Some(&["name", "email", "password"])).await?;
            service
                .register(
                    &peer,
                    text(&b, "name"),
                    text(&b, "email"),
                    text(&b, "password"),
                )
                .await?;
            message(
                202,
                "If this address can be registered, check your email to continue.",
            )
        }
        "login" => {
            session.anonymous()?;
            let b = body(request, Some(&["email", "password"])).await?;
            session_response(
                service,
                service
                    .login(&session, &peer, text(&b, "email"), text(&b, "password"))
                    .await?,
            )?
        }
        "logout" => {
            body(request, Some(&[])).await?;
            session_response(service, service.rotate(&session, None).await?)?
        }
        "me" => {
            session.authenticated()?;
            json_response(200, json!({"user":session.user}))
        }
        "profile" => {
            let b = body(request, Some(&["name"])).await?;
            json_response(
                200,
                json!({"user":service.profile(&session,text(&b,"name")).await?}),
            )
        }
        "sessions" => json_response(200, json!({"sessions":service.sessions(&session).await?})),
        "revoke" => {
            service.revoke(&session, arg).await?;
            let mut r = message(200, "Session revoked.");
            if arg == session.id {
                cookie(service, &mut r, None);
            }
            r
        }
        "others" => json_response(
            200,
            json!({"revokedCount":service.revoke_others(&session).await?}),
        ),
        "reauth" => {
            let b = body(request, Some(&["password", "code"])).await?;
            service
                .reauthenticate(&mut session, &peer, text(&b, "password"), text(&b, "code"))
                .await?;
            message(200, "Identity confirmed.")
        }
        "request-email" => {
            let b = body(request, Some(&["email"])).await?;
            service.request_email(&peer, text(&b, "email"), arg).await?;
            message(202,"If the account is eligible, an email has been queued. Please check your inbox shortly.")
        }
        "consume-email" => {
            let b = body(request, Some(&["token", "password"])).await?;
            service
                .throttle(&format!("email-consume/ip/{peer}"), 20)
                .await?;
            service
                .consume_email(text(&b, "token"), arg, text(&b, "password"))
                .await?;
            message(200, "Account request completed. Continue to sign in.")
        }
        "password" => {
            let b = body(request, Some(&["currentPassword", "password", "code"])).await?;
            service
                .change_password(
                    &mut session,
                    &peer,
                    text(&b, "currentPassword"),
                    text(&b, "password"),
                    text(&b, "code"),
                )
                .await?;
            message(200, "Password changed. Sign in again.")
        }
        "enroll" => {
            body(request, Some(&[])).await?;
            json_response(200, service.enroll_totp(&session).await?)
        }
        "confirm-totp" => {
            let b = body(request, Some(&["code"])).await?;
            json_response(
                200,
                json!({"recoveryCodes":service.confirm_totp(&session,&peer,text(&b,"code")).await?}),
            )
        }
        "challenge" => {
            let b = body(request, Some(&["code", "recoveryCode"])).await?;
            session_response(
                service,
                service
                    .challenge(&session, &peer, text(&b, "code"), text(&b, "recoveryCode"))
                    .await?,
            )?
        }
        "modify-totp" => {
            let b = body(request, Some(&["password", "code"])).await?;
            let codes = service
                .modify_totp(
                    &session,
                    &peer,
                    text(&b, "password"),
                    text(&b, "code"),
                    arg == "remove",
                )
                .await?;
            if arg == "remove" {
                message(200, "Authenticator removed.")
            } else {
                json_response(200, json!({"recoveryCodes":codes}))
            }
        }
        "security" => json_response(200, service.security(&session).await?),
        "passkey-begin" => {
            let field = if arg == "registration" {
                "name"
            } else {
                "email"
            };
            let b = body(request, Some(&[field])).await?;
            json_response(
                200,
                service
                    .begin_passkey(&session, &peer, arg, text(&b, field))
                    .await?,
            )
        }
        "passkey-finish" => {
            let b = body(request, None).await?;
            let next = service.finish_passkey(&session, &peer, arg, b).await?;
            if let Some(next) = next {
                session_response(service, next)?
            } else {
                message(200, "Passkey registered.")
            }
        }
        "remove-passkey" => {
            service.remove_passkey(&session, arg).await?;
            message(200, "Passkey removed.")
        }
        "pending-email" => json_response(
            200,
            json!({"pending":service.pending_email(&session).await?}),
        ),
        "email-change" => {
            let b = body(request, Some(&["email"])).await?;
            service
                .request_email_change(&session, &peer, text(&b, "email"))
                .await?;
            message(202,"If this address is available, check its inbox to confirm the change. Your current email remains active until confirmation.")
        }
        "cancel-email" => {
            service.cancel_email_change(&session).await?;
            message(200, "Pending email change canceled.")
        }
        "confirm-email" => {
            let b = body(request, Some(&["token"])).await?;
            service
                .confirm_email_change(&session, &peer, text(&b, "token"))
                .await?;
            let mut r = message(200, "Email changed. Sign in again with your new address.");
            cookie(service, &mut r, None);
            r
        }
        "closure" => json_response(200, service.account_closure(&session).await?),
        "close" => {
            body(request, Some(&[])).await?;
            let expires = service.schedule_closure(&session).await?;
            let mut r = json_response(
                202,
                json!({"message":"Account closed. You can recover it within 30 days using your email, password and enrolled authentication factor.","expiresAt":expires}),
            );
            cookie(service, &mut r, None);
            r
        }
        "recover-request" => {
            session.anonymous()?;
            let b = body(request, Some(&["email"])).await?;
            service
                .request_closure_recovery(&peer, text(&b, "email"))
                .await?;
            message(
                202,
                "If this account is eligible for recovery, check your inbox for a recovery link.",
            )
        }
        "recover-confirm" => {
            session.anonymous()?;
            let b = body(request, Some(&["token", "password", "code"])).await?;
            service
                .confirm_closure_recovery(
                    &peer,
                    text(&b, "token"),
                    text(&b, "password"),
                    text(&b, "code"),
                )
                .await?;
            message(200, "Account recovered. Sign in to continue.")
        }
        "providers" => json_response(200, json!({"providers":service.providers(&session).await?})),
        "provider-link" | "provider-login" => {
            if action == "provider-login" {
                session.anonymous()?;
            }
            body(request, Some(&[])).await?;
            json_response(
                200,
                json!({"url":service.begin_oauth(&session,&peer,arg,if action=="provider-login"{"login"}else{"link"}).await?}),
            )
        }
        "provider-unlink" => {
            service.unlink_oauth(&session, arg).await?;
            json_response(200, json!({"ok":true}))
        }
        "provider-complete" => {
            session.anonymous()?;
            let b = body(request, Some(&["token"])).await?;
            session_response(
                service,
                service
                    .complete_oauth(&session, &peer, text(&b, "token"))
                    .await?,
            )?
        }
        _ => return Err(Error::unavailable()),
    };
    Ok(response)
}
fn session_response(service: &Service, s: Session) -> Result<Response> {
    let mut response = json_response(
        200,
        serde_json::to_value(&s).map_err(|_| Error::unavailable())?,
    );
    cookie(service, &mut response, Some(&s));
    Ok(response)
}
async fn callback(
    service: &Service,
    token: &str,
    peer: &str,
    provider: &str,
    query: &str,
) -> Result<Response> {
    let query: HashMap<String, String> = url::form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect();
    let mut target = format!("{}/sign-in?provider=failed", service.config.origin);
    if let Ok(s) = service.session(token, peer, false).await {
        if s.user.is_some() {
            target = format!("{}/settings?provider=failed", service.config.origin)
        }
        let code = if query.get("error").is_some_and(|e| !e.is_empty()) {
            ""
        } else {
            query.get("code").map(String::as_str).unwrap_or("")
        };
        if let Ok(result) = service
            .finish_oauth(
                &s,
                peer,
                provider,
                query.get("state").map(String::as_str).unwrap_or(""),
                code,
            )
            .await
        {
            target = if result.operation == "link" {
                format!("{}/settings?provider=linked", service.config.origin)
            } else {
                format!(
                    "{}/complete-provider-sign-in#token={}",
                    service.config.origin, result.grant
                )
            }
        }
    }
    let mut response = StatusCode::SEE_OTHER.into_response();
    response.headers_mut().insert(
        header::LOCATION,
        target.parse().map_err(|_| Error::unavailable())?,
    );
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    Ok(response)
}
fn route<'a>(path: &'a str, method: &Method) -> Option<(&'static str, &'a str)> {
    let method = method.as_str();
    let result = match (method, path) {
        ("GET", "/api/v1/auth/session") => ("session", ""),
        ("POST", "/api/v1/auth/register") => ("register", ""),
        ("POST", "/api/v1/auth/login") => ("login", ""),
        ("POST", "/api/v1/auth/logout") => ("logout", ""),
        ("GET", "/api/v1/me") => ("me", ""),
        ("PATCH", "/api/v1/auth/profile") => ("profile", ""),
        ("GET", "/api/v1/auth/sessions") => ("sessions", ""),
        ("DELETE", "/api/v1/auth/sessions/others") => ("others", ""),
        ("POST", "/api/v1/auth/reauthenticate") => ("reauth", ""),
        ("POST", "/api/v1/auth/verification/resend") => ("request-email", "verification"),
        ("POST", "/api/v1/auth/verification/confirm") => ("consume-email", "verification"),
        ("POST", "/api/v1/auth/password/forgot") => ("request-email", "reset"),
        ("POST", "/api/v1/auth/password/reset") => ("consume-email", "reset"),
        ("POST", "/api/v1/auth/password/change") => ("password", ""),
        ("POST", "/api/v1/auth/totp/enroll") => ("enroll", ""),
        ("POST", "/api/v1/auth/totp/confirm") => ("confirm-totp", ""),
        ("POST", "/api/v1/auth/mfa/challenge") => ("challenge", ""),
        ("POST", "/api/v1/auth/totp/remove") => ("modify-totp", "remove"),
        ("POST", "/api/v1/auth/recovery-codes/regenerate") => ("modify-totp", "regenerate"),
        ("GET", "/api/v1/auth/security") => ("security", ""),
        ("POST", "/api/v1/auth/passkeys/register/begin") => ("passkey-begin", "registration"),
        ("POST", "/api/v1/auth/passkeys/register/finish") => ("passkey-finish", "registration"),
        ("POST", "/api/v1/auth/passkeys/login/begin") => ("passkey-begin", "login"),
        ("POST", "/api/v1/auth/passkeys/login/finish") => ("passkey-finish", "login"),
        ("GET", "/api/v1/auth/email-change") => ("pending-email", ""),
        ("POST", "/api/v1/auth/email-change") => ("email-change", ""),
        ("DELETE", "/api/v1/auth/email-change") => ("cancel-email", ""),
        ("POST", "/api/v1/auth/email-change/confirm") => ("confirm-email", ""),
        ("GET", "/api/v1/auth/account-closure") => ("closure", ""),
        ("POST", "/api/v1/auth/account-closure") => ("close", ""),
        ("POST", "/api/v1/auth/account-closure/recovery/request") => ("recover-request", ""),
        ("POST", "/api/v1/auth/account-closure/recovery/confirm") => ("recover-confirm", ""),
        ("GET", "/api/v1/auth/providers") => ("providers", ""),
        ("POST", "/api/v1/auth/providers/complete") => ("provider-complete", ""),
        _ => {
            if method == "DELETE" {
                if let Some(id) = path
                    .strip_prefix("/api/v1/auth/sessions/")
                    .filter(|p| !p.contains('/'))
                {
                    return Some(("revoke", id));
                }
                if let Some(id) = path
                    .strip_prefix("/api/v1/auth/passkeys/")
                    .filter(|p| !p.contains('/'))
                {
                    return Some(("remove-passkey", id));
                }
            }
            if let Some(p) = path.strip_prefix("/api/v1/auth/providers/") {
                if method == "DELETE" && !p.contains('/') {
                    return Some(("provider-unlink", p));
                }
                if method == "POST" {
                    if let Some(provider) = p.strip_suffix("/link").filter(|p| !p.contains('/')) {
                        return Some(("provider-link", provider));
                    }
                    if let Some(provider) = p.strip_suffix("/login").filter(|p| !p.contains('/')) {
                        return Some(("provider-login", provider));
                    }
                }
            }
            return None;
        }
    };
    Some(result)
}
