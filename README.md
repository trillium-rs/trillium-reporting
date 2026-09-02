# trillium-reporting

[![ci][ci-badge]][ci]
[![crates.io version][version-badge]][crate]
[![docs.rs][docs-badge]][docs]
[![codecov][codecov-badge]][codecov]

[ci]: https://github.com/trillium-rs/trillium-reporting/actions?query=workflow%3ACI
[ci-badge]: https://github.com/trillium-rs/trillium-reporting/workflows/CI/badge.svg
[version-badge]: https://img.shields.io/crates/v/trillium-reporting.svg?style=flat-square
[crate]: https://crates.io/crates/trillium-reporting
[docs-badge]: https://img.shields.io/badge/docs-latest-blue.svg?style=flat-square
[docs]: https://docs.rs/trillium-reporting
[codecov-badge]: https://codecov.io/gh/trillium-rs/trillium-reporting/graph/badge.svg
[codecov]: https://codecov.io/gh/trillium-rs/trillium-reporting

Browsers batch up CSP violations, deprecations, interventions, crashes, and
cross-origin-isolation failures and POST them to an endpoint the site names in
its `Reporting-Endpoints` header. This crate provides both halves: a handler
that sets that header on document responses, and a handler that receives the
reports, parses them into typed structs, and hands them to a sink of your
choice. It ships with a logging sink and a bounded in-memory sink for
low-ceremony setups.

## Example

```rust
use trillium_reporting::{LogSink, reporting};

let app = (
    reporting(LogSink),
    |conn: trillium::Conn| async move { conn.ok("hello") },
);
```

`reporting` pairs a handler that sets `Reporting-Endpoints: default="/_reports"`
on html responses with a handler that receives deliveries at that path. Reports
are parsed into typed structs (`csp-violation`, `deprecation`, `coop`, and so
on, with an opaque fallback for anything else) and passed to a sink: a logging
sink, a bounded in-memory sink, any async closure, or your own `ReportSink`.

## Safety

This crate uses `#![forbid(unsafe_code)]`.

## License

<sup>
Licensed under either of <a href="LICENSE-APACHE">Apache License, Version
2.0</a> or <a href="LICENSE-MIT">MIT license</a> at your option.
</sup>

<br/>

<sub>
Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
</sub>
