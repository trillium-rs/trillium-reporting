//! [Reporting API](https://w3c.github.io/reporting/) support for [trillium](https://trillium.rs).
//!
//! Browsers batch up CSP violations, deprecations, interventions, crashes, and
//! cross-origin-isolation failures and POST them to an endpoint the site names in its
//! `Reporting-Endpoints` header. This crate provides both halves: a handler that sets that header
//! on document responses, and a handler that receives the reports, parses them into typed
//! structs, and hands them to a sink of your choice.
//!
//! ```
//! use trillium_reporting::{LogSink, reporting};
//!
//! let app = (reporting(LogSink), |conn: trillium::Conn| async move {
//!     conn.ok("hello")
//! });
//! ```
//!
//! [`reporting`] pairs a [`ReportingEndpoints`] handler that names `/_reports` as the `default`
//! endpoint with a [`ReportReceiver`] at that path. The two compose independently: use only the
//! receiver if a cdn sets the header, or only the header if reports go to another service.
//!
//! Report types that name their own endpoint, such as csp's `report-to` directive, need an
//! endpoint with that name and a policy that refers to it. See
//! [`ReportingEndpoints::with_endpoint`] and [`ReportingEndpoints::with_csp_report_to`].
//!
//! Browsers only honor `Reporting-Endpoints` on secure origins, and same-origin deliveries carry
//! cookies, so a sink can read session state from the delivering conn.
#![forbid(unsafe_code)]
#![deny(
    clippy::dbg_macro,
    missing_copy_implementations,
    rustdoc::missing_crate_level_docs,
    missing_debug_implementations,
    missing_docs,
    nonstandard_style,
    unused_qualifications
)]
#![warn(missing_docs, clippy::pedantic, clippy::nursery, clippy::cargo)]
#![allow(
    clippy::must_use_candidate,
    clippy::module_name_repetitions,
    clippy::multiple_crate_versions
)]

mod endpoints;
mod receiver;
mod report;
mod sink;

pub use endpoints::{ReportingEndpoints, reporting_endpoints};
pub use receiver::{DEFAULT_MAX_BODY_LEN, ReportReceiver, report_receiver};
pub use report::{
    CoepViolation, CoopViolation, Crash, CspViolation, Deprecation, Disposition,
    DocumentPolicyViolation, IntegrityViolation, Intervention, NetworkError,
    PermissionsPolicyViolation, Report, ReportBody,
};
pub use sink::{LogSink, MemorySink, ReportSink};

/// Constructs a [`ReportingEndpoints`] header handler and a [`ReportReceiver`] at `/_reports`
/// delivering to `sink`, as a handler tuple.
pub fn reporting<Sink: ReportSink>(sink: Sink) -> (ReportingEndpoints, ReportReceiver<Sink>) {
    (reporting_endpoints(), report_receiver(sink))
}

// Compile the README as a doctest so its examples stay in sync with the crate.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
mod readme {}
