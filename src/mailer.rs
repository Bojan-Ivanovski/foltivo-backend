use crate::{
    auth::{Error, Result},
    config::Config,
};
use lettre::{
    message::{header::ContentType, Mailbox},
    transport::smtp::{
        authentication::Credentials,
        client::{Tls, TlsParameters},
    },
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};
use std::{net::IpAddr, time::Duration};
#[derive(Clone)]
pub struct Mailer {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
}
impl Mailer {
    pub fn new(c: &Config) -> Result<Self> {
        let (host, port) = c
            .smtp_addr
            .rsplit_once(':')
            .ok_or_else(|| Error::validation("SMTP_ADDR must contain a host and port"))?;
        let host = host.trim_start_matches('[').trim_end_matches(']');
        let port: u16 = port
            .parse()
            .map_err(|_| Error::validation("SMTP_ADDR must contain a host and port"))?;
        let from: Mailbox = c
            .smtp_from
            .parse()
            .map_err(|_| Error::validation("SMTP_FROM must be a plain sender address"))?;
        if from.name.is_some()
            || c.smtp_from.contains(['\r', '\n'])
            || from.email.to_string() != c.smtp_from
        {
            return Err(Error::validation(
                "SMTP_FROM must be a plain sender address",
            ));
        }
        if !c.smtp_require_tls
            && (c.environment == "production"
                || !(host == "localhost" || host.parse::<IpAddr>().is_ok_and(|i| i.is_loopback())))
        {
            return Err(Error::validation(
                "unencrypted SMTP is allowed only for local development loopback delivery",
            ));
        }
        if c.smtp_username.is_empty() != c.smtp_password.is_empty() {
            return Err(Error::validation(
                "SMTP_USERNAME and SMTP_PASSWORD must be configured together",
            ));
        }
        let tls = if c.smtp_require_tls {
            Tls::Required(TlsParameters::new(host.to_owned()).map_err(|_| Error::unavailable())?)
        } else {
            Tls::Opportunistic(
                TlsParameters::new(host.to_owned()).map_err(|_| Error::unavailable())?,
            )
        };
        let mut builder = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host)
            .port(port)
            .tls(tls)
            .timeout(Some(Duration::from_secs(5)));
        if !c.smtp_username.is_empty() {
            builder = builder.credentials(Credentials::new(
                c.smtp_username.clone(),
                c.smtp_password.clone(),
            ))
        }
        Ok(Self {
            transport: builder.build(),
            from,
        })
    }
    pub async fn send(&self, to: &str, subject: &str, body: &str) -> Result<()> {
        if to.contains(['\r', '\n']) || subject.contains(['\r', '\n']) {
            return Err(Error::unavailable());
        }
        let mail = Message::builder()
            .from(self.from.clone())
            .to(to.parse().map_err(|_| Error::unavailable())?)
            .subject(subject)
            .header(ContentType::TEXT_PLAIN)
            .body(body.to_owned())
            .map_err(|_| Error::unavailable())?;
        self.transport
            .send(mail)
            .await
            .map_err(|_| Error::unavailable())?;
        Ok(())
    }
}
