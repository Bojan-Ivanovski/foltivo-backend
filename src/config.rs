use crate::auth::{Error, Result};
use ipnet::IpNet;
use std::{collections::HashMap, env, time::Duration};
use url::Url;

#[derive(Clone)]
pub struct Provider {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_url: String,
}
#[derive(Clone)]
pub struct Config {
    pub http_addr: String,
    pub database_url: String,
    pub environment: String,
    pub origin: String,
    pub secure_cookies: bool,
    pub trusted_proxies: Vec<IpNet>,
    pub encryption_key: String,
    pub smtp_addr: String,
    pub smtp_from: String,
    pub smtp_username: String,
    pub smtp_password: String,
    pub smtp_require_tls: bool,
    pub providers: HashMap<String, Provider>,
}
fn env_value(key: &str, default: &str) -> String {
    env::var(key)
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| default.into())
}
fn config_error(message: &str) -> Error {
    Error::validation(message)
}
impl Config {
    pub fn database() -> Result<(String, String)> {
        Self::database_from(&env_value)
    }
    fn database_from(value: &dyn Fn(&str, &str) -> String) -> Result<(String, String)> {
        let environment = value("APP_ENV", "production");
        if !["production", "development", "test"].contains(&environment.as_str()) {
            return Err(config_error(
                "APP_ENV must be development, test or production",
            ));
        }
        let database_url = value("DATABASE_URL", "");
        if database_url.is_empty() {
            return Err(config_error("DATABASE_URL is required"));
        }
        Ok((database_url, environment))
    }
    pub fn load() -> Result<Self> {
        Self::load_from(&env_value)
    }
    fn load_from(value: &dyn Fn(&str, &str) -> String) -> Result<Self> {
        let (database_url, environment) = Self::database_from(value)?;
        let origin = value(
            "APP_ORIGIN",
            if environment == "production" {
                ""
            } else {
                "http://localhost:5173"
            },
        );
        let parsed=Url::parse(&origin).map_err(|_|config_error("APP_ORIGIN must be an exact http(s) origin without path, credentials, query or fragment"))?;
        let authority = origin
            .strip_prefix("https://")
            .or_else(|| origin.strip_prefix("http://"))
            .unwrap_or("");
        if !["http", "https"].contains(&parsed.scheme())
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || authority.contains('/')
            || parsed.origin().ascii_serialization() != origin
        {
            return Err(config_error("APP_ORIGIN must be an exact http(s) origin without path, credentials, query or fragment"));
        }
        let secure_cookies = parsed.scheme() == "https";
        let mut trusted_proxies = vec![];
        let raw = value("TRUSTED_PROXY_CIDRS", "");
        if !raw.is_empty() {
            for value in raw.split(',') {
                let prefix: IpNet = value.trim().parse().map_err(|_| {
                    config_error("TRUSTED_PROXY_CIDRS must contain explicit non-global proxy CIDRs")
                })?;
                if prefix.prefix_len() == 0 {
                    return Err(config_error(
                        "TRUSTED_PROXY_CIDRS must contain explicit non-global proxy CIDRs",
                    ));
                }
                trusted_proxies.push(prefix.trunc())
            }
        }
        if environment == "production" {
            if !secure_cookies || value("TRUSTED_TLS_TERMINATION", "") != "true" {
                return Err(config_error("production requires HTTPS APP_ORIGIN and TRUSTED_TLS_TERMINATION=true behind a trusted HTTPS reverse proxy"));
            }
            if trusted_proxies.is_empty() {
                return Err(config_error(
                    "production requires TRUSTED_PROXY_CIDRS for the actual TLS reverse proxies",
                ));
            }
            let db = Url::parse(&database_url).map_err(|_| {
                config_error(
                    "production DATABASE_URL must use PostgreSQL TLS with sslmode=verify-full",
                )
            })?;
            if !["postgres", "postgresql"].contains(&db.scheme())
                || !db
                    .query_pairs()
                    .any(|(k, v)| k == "sslmode" && v == "verify-full")
                || db
                    .query_pairs()
                    .any(|(k, v)| k == "sslsni" && v.contains('0'))
            {
                return Err(config_error(
                    "production DATABASE_URL must use PostgreSQL TLS with sslmode=verify-full",
                ));
            }
        } else if !secure_cookies
            && !["localhost", "127.0.0.1", "[::1]", "::1"]
                .contains(&parsed.host_str().unwrap_or(""))
        {
            return Err(config_error(
                "insecure development APP_ORIGIN must use localhost or a loopback address",
            ));
        }
        let mut providers = HashMap::new();
        for provider in ["github", "google"] {
            let prefix = format!("OAUTH_{}_", provider.to_uppercase());
            let cfg = Provider {
                client_id: value(&(prefix.clone() + "CLIENT_ID"), "").trim().into(),
                client_secret: value(&(prefix.clone() + "CLIENT_SECRET"), ""),
                redirect_url: value(&(prefix + "REDIRECT_URL"), "").trim().into(),
            };
            if cfg.client_id.is_empty()
                && cfg.client_secret.is_empty()
                && cfg.redirect_url.is_empty()
            {
                continue;
            }
            let url = Url::parse(&cfg.redirect_url)
                .map_err(|_| config_error("invalid OAuth provider configuration"))?;
            if cfg.client_id.is_empty()
                || cfg.client_secret.is_empty()
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
                || (url.scheme() != "https"
                    && !(url.scheme() == "http"
                        && ["localhost", "127.0.0.1"].contains(&url.host_str().unwrap_or(""))))
                || url.path() != format!("/api/v1/auth/providers/{provider}/callback")
            {
                return Err(config_error("invalid OAuth provider configuration"));
            }
            providers.insert(provider.into(), cfg);
        }
        Ok(Self {
            http_addr: value("HTTP_ADDR", ":8080"),
            database_url,
            environment,
            origin,
            secure_cookies,
            trusted_proxies,
            encryption_key: value("AUTH_ENCRYPTION_KEY", ""),
            smtp_addr: value("SMTP_ADDR", ""),
            smtp_from: value("SMTP_FROM", ""),
            smtp_username: value("SMTP_USERNAME", ""),
            smtp_password: value("SMTP_PASSWORD", ""),
            smtp_require_tls: value("SMTP_REQUIRE_TLS", "") != "false",
            providers,
        })
    }
    pub fn cookie_name(&self) -> &'static str {
        if self.secure_cookies {
            "__Host-foltivo_session"
        } else {
            "foltivo_session"
        }
    }
}
pub async fn connect(url: &str) -> Result<sea_orm::DatabaseConnection> {
    let mut options = sea_orm::ConnectOptions::new(url.to_owned());
    options
        .connect_timeout(Duration::from_secs(5))
        .acquire_timeout(Duration::from_secs(5))
        .sqlx_logging(false)
        .max_connections(10)
        .min_connections(0)
        .connect_lazy(true);
    sea_orm::Database::connect(options).await.map_err(|_| {
        Error::validation("database connection unavailable (connection details suppressed)")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn load(pairs: &[(&str, &str)]) -> Result<Config> {
        let values: HashMap<_, _> = pairs.iter().copied().collect();
        Config::load_from(&|key, default| {
            values
                .get(key)
                .copied()
                .filter(|v| !v.is_empty())
                .unwrap_or(default)
                .into()
        })
    }
    fn production() -> Vec<(&'static str, &'static str)> {
        vec![
            (
                "DATABASE_URL",
                "postgres://test:secret@db.invalid/app?sslmode=verify-full",
            ),
            ("APP_ORIGIN", "https://foltivo.com"),
            ("TRUSTED_TLS_TERMINATION", "true"),
            ("TRUSTED_PROXY_CIDRS", "10.0.0.0/24"),
        ]
    }
    #[test]
    fn defaults_and_production_requirements_without_global_environment_mutation() {
        assert!(load(&[]).is_err());
        let dev = load(&[
            ("DATABASE_URL", "postgres://localhost/test"),
            ("APP_ENV", "test"),
        ])
        .unwrap();
        assert_eq!(dev.origin, "http://localhost:5173");
        assert_eq!(dev.http_addr, ":8080");
        assert_eq!(dev.cookie_name(), "foltivo_session");
        assert!(!dev.secure_cookies);
        let config = load(&production()).unwrap();
        assert!(config.secure_cookies);
        assert_eq!(config.cookie_name(), "__Host-foltivo_session");
        for key in [
            "DATABASE_URL",
            "APP_ORIGIN",
            "TRUSTED_TLS_TERMINATION",
            "TRUSTED_PROXY_CIDRS",
        ] {
            let mut pairs = production();
            pairs.retain(|(k, _)| *k != key);
            assert!(load(&pairs).is_err(), "{key}");
        }
    }
    #[rstest::rstest]
    #[case("APP_ENV", "staging")]
    #[case("APP_ORIGIN", "http://foltivo.com")]
    #[case("APP_ORIGIN", "https://foltivo.com/")]
    #[case("APP_ORIGIN", "https://user:secret@foltivo.com")]
    #[case("APP_ORIGIN", "https://foltivo.com?query=1")]
    #[case("APP_ORIGIN", "https://foltivo.com#fragment")]
    #[case("TRUSTED_PROXY_CIDRS", "0.0.0.0/0")]
    #[case("TRUSTED_PROXY_CIDRS", "::/0")]
    #[case("TRUSTED_PROXY_CIDRS", "invalid")]
    #[case("DATABASE_URL", "postgres://secret:password@db/app?sslmode=disable")]
    #[case(
        "DATABASE_URL",
        "postgres://secret:password@db/app?sslmode=verify-full&sslsni=0"
    )]
    fn rejects_unsafe_config_without_leaking_secrets(#[case] key: &str, #[case] value: &str) {
        let mut pairs = production();
        pairs.retain(|(k, _)| *k != key);
        pairs.push((key, value));
        let error = load(&pairs)
            .err()
            .expect("reject unsafe config")
            .to_string();
        assert!(!error.contains("secret"));
        assert!(!error.contains("password@"));
    }
    #[test]
    fn provider_config_is_optional_but_partial_or_unsafe_callbacks_are_rejected() {
        let mut pairs = production();
        assert!(load(&pairs).unwrap().providers.is_empty());
        pairs.push(("OAUTH_GITHUB_CLIENT_ID", "fixture-id"));
        assert!(load(&pairs).is_err());
        pairs.push(("OAUTH_GITHUB_CLIENT_SECRET", "fixture-secret"));
        pairs.push((
            "OAUTH_GITHUB_REDIRECT_URL",
            "https://foltivo.com/api/v1/auth/providers/github/callback",
        ));
        assert!(load(&pairs).unwrap().providers.contains_key("github"));
        for callback in [
            "https://foltivo.com/wrong",
            "http://remote.invalid/api/v1/auth/providers/github/callback",
            "https://user:secret@foltivo.com/api/v1/auth/providers/github/callback",
            "https://foltivo.com/api/v1/auth/providers/github/callback?x=1",
        ] {
            let mut invalid = pairs.clone();
            invalid.retain(|(k, _)| *k != "OAUTH_GITHUB_REDIRECT_URL");
            invalid.push(("OAUTH_GITHUB_REDIRECT_URL", callback));
            assert!(load(&invalid).is_err());
        }
    }
}
