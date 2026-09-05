# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1](https://github.com/trillium-rs/trillium-reporting/compare/v0.1.0...v0.1.1) - 2026-09-05

### Other

- *(deps)* update codecov/codecov-action action to v7
- *(deps)* update actions/upload-pages-artifact action to v5
- *(deps)* update actions/checkout action to v7

## [0.1.0] - 2026-09-02

### Added

- `ReportingEndpoints` handler that sets `Reporting-Endpoints` on document responses, with
  optional `report-to` injection into outgoing csp headers.
- `ReportReceiver` handler accepting `application/reports+json` batches and legacy
  `application/csp-report` documents.
- Typed `Report` / `ReportBody` for the report types browsers ship, with an `Other` fallback.
- `ReportSink` trait (implemented for async closures), `LogSink`, and bounded `MemorySink`.
- `reporting(sink)` one-shot returning both handlers.
