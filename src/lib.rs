//! mxhop: a headless SMTP forwarder.
//!
//! The binary is a thin shell around this library, so the tests drive the same
//! entry points the service uses.

pub mod config;
pub mod dns;
pub mod envelope;
pub mod policy;
pub mod routing;
pub mod server;
pub mod smtp;
pub mod spool;
pub mod srs;
pub mod telemetry;
pub mod tls;
