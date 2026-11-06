//! mxhop: a headless SMTP forwarder.
//!
//! The binary is a thin shell around this library, so the tests drive the same
//! entry points the service uses.

pub mod config;
pub mod routing;
pub mod telemetry;
