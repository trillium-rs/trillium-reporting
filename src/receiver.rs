use crate::{Report, ReportSink};
use trillium::{
    Conn, Handler,
    KnownHeaderName::{Allow, ContentType, UserAgent},
    Method, Status,
};

/// The default maximum accepted delivery size, one mebibyte.
///
/// The spec caps a browser's buffer at 100 reports per type and Chromium's cache holds 100
/// reports total, and a csp report is dominated by the policy it quotes, so a real delivery is
/// well under this. The limit guards against clients that are not browsers.
pub const DEFAULT_MAX_BODY_LEN: u64 = 1024 * 1024;

/// A [`Handler`] that receives reports at a path and passes them to a [`ReportSink`].
///
/// Requests to any other path pass through untouched, so this can sit anywhere in a handler
/// tuple. At its path it accepts `POST` with either `application/reports+json` (the Reporting
/// API batch format) or `application/csp-report` (the legacy csp `report-uri` format) and
/// responds 204. Other methods get 405, other content types 415, oversized bodies 413, and
/// unparseable bodies 400.
///
/// A cross-origin endpoint additionally needs cors preflight handling, which this handler does
/// not provide.
#[derive(Debug)]
pub struct ReportReceiver<Sink> {
    path: String,
    sink: Sink,
    max_body_len: u64,
}

/// Constructs a [`ReportReceiver`] at `/_reports` delivering to `sink`.
pub fn report_receiver<Sink: ReportSink>(sink: Sink) -> ReportReceiver<Sink> {
    ReportReceiver::new(sink)
}

impl<Sink: ReportSink> ReportReceiver<Sink> {
    /// Constructs a receiver at `/_reports` delivering to `sink`.
    pub fn new(sink: Sink) -> Self {
        Self {
            path: String::from("/_reports"),
            sink,
            max_body_len: DEFAULT_MAX_BODY_LEN,
        }
    }

    /// Sets the path this receiver responds at. Compared exactly against the request path.
    #[must_use]
    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = path.into();
        self
    }

    /// Sets the maximum accepted delivery size in bytes. See [`DEFAULT_MAX_BODY_LEN`].
    #[must_use]
    pub const fn with_max_body_len(mut self, max_body_len: u64) -> Self {
        self.max_body_len = max_body_len;
        self
    }

    /// The path this receiver responds at.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The sink this receiver delivers to.
    pub const fn sink(&self) -> &Sink {
        &self.sink
    }
}

enum Format {
    Batch,
    LegacyCsp,
}

fn format(content_type: Option<&str>) -> Option<Format> {
    let mime = content_type?.split(';').next()?.trim();
    if mime.eq_ignore_ascii_case("application/reports+json") {
        Some(Format::Batch)
    } else if mime.eq_ignore_ascii_case("application/csp-report") {
        Some(Format::LegacyCsp)
    } else {
        None
    }
}

impl<Sink: ReportSink> Handler for ReportReceiver<Sink> {
    async fn run(&self, mut conn: Conn) -> Conn {
        if conn.path() != self.path {
            return conn;
        }

        if conn.method() != Method::Post {
            return conn
                .with_status(Status::MethodNotAllowed)
                .with_response_header(Allow, "POST")
                .halt();
        }

        let Some(format) = format(conn.request_headers().get_str(ContentType)) else {
            return conn.with_status(Status::UnsupportedMediaType).halt();
        };

        let body = match conn
            .request_body()
            .with_max_len(self.max_body_len)
            .read_bytes()
            .await
        {
            Ok(body) => body,
            Err(error) => {
                log::warn!("could not read report delivery: {error}");
                return conn.with_status(Status::PayloadTooLarge).halt();
            }
        };

        let parsed = match format {
            Format::Batch => Report::parse_batch(&body),
            Format::LegacyCsp => {
                Report::parse_legacy_csp(&body, conn.request_headers().get_str(UserAgent))
                    .map(|report| vec![report])
            }
        };

        let reports = match parsed {
            Ok(reports) => reports,
            Err(error) => {
                log::warn!("could not parse report delivery: {error}");
                return conn.with_status(Status::BadRequest).halt();
            }
        };

        if !reports.is_empty() {
            self.sink.receive(reports, &conn).await;
        }

        conn.with_status(Status::NoContent).halt()
    }
}
