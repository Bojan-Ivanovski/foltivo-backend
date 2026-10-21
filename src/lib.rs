pub mod auth;
pub mod config;
pub mod http;
pub mod mailer;
pub mod server;

#[cfg(test)]
extern crate self as foltivo_backend;
#[cfg(test)]
#[path = "../tests/common/mod.rs"]
mod test_common;
