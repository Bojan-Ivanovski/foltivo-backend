use axum::{
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
#[derive(Debug, Clone)]
pub struct Error {
    pub status: u16,
    pub code: String,
    pub message: String,
    pub retry_after: u64,
}
pub type Result<T> = std::result::Result<T, Error>;
impl Error {
    pub fn new(status: u16, code: &str, message: &str) -> Self {
        Self {
            status,
            code: code.into(),
            message: message.into(),
            retry_after: 0,
        }
    }
    pub fn unavailable() -> Self {
        Self::new(
            503,
            "unavailable",
            "Authentication is temporarily unavailable. Try again shortly.",
        )
    }
    pub fn unauthenticated() -> Self {
        Self::new(401, "unauthenticated", "Sign in to continue.")
    }
    pub fn invalid_credentials() -> Self {
        Self::new(
            401,
            "invalid_credentials",
            "Email or password is incorrect.",
        )
    }
    pub fn conflict() -> Self {
        Self::new(
            409,
            "conflict",
            "Your session changed. Reload and try again.",
        )
    }
    pub fn validation(message: &str) -> Self {
        Self::new(400, "validation_error", message)
    }
    pub fn factor() -> Self {
        Self::new(
            401,
            "invalid_factor",
            "Authentication code is invalid, expired or already used.",
        )
    }
    pub fn link() -> Self {
        Self::validation("This link is invalid or has expired.")
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}
impl std::error::Error for Error {}
impl From<sea_orm::DbErr> for Error {
    fn from(_: sea_orm::DbErr) -> Self {
        Self::unavailable()
    }
}
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let mut response = (
            StatusCode::from_u16(self.status).unwrap_or(StatusCode::SERVICE_UNAVAILABLE),
            Json(json!({"error":{"code":self.code,"message":self.message}})),
        )
            .into_response();
        if self.retry_after > 0 {
            if let Ok(v) = self.retry_after.to_string().parse() {
                response.headers_mut().insert(header::RETRY_AFTER, v);
            }
        }
        response
    }
}
