use trillium::{
    Conn, Handler, HeaderValues, Headers, Info,
    KnownHeaderName::{ContentSecurityPolicy, ContentSecurityPolicyReportOnly, ContentType},
};

const HEADER_NAME: &str = "reporting-endpoints";

/// A [`Handler`] that sets the `Reporting-Endpoints` header on outgoing responses.
///
/// Endpoint urls may be relative; browsers resolve them against the response url, so `/_reports`
/// names this host. The header is only meaningful on responses that create a document or worker,
/// so by default it is set only when the response content type is html or unset. See
/// [`ReportingEndpoints::on_all_responses`] to set it unconditionally.
///
/// Responses that already carry a `Reporting-Endpoints` header are left alone.
#[derive(Debug)]
pub struct ReportingEndpoints {
    endpoints: Vec<(String, String)>,
    header_value: String,
    csp_report_to: Option<String>,
    all_responses: bool,
}

/// Constructs a [`ReportingEndpoints`] handler with a single endpoint named `default` at
/// `/_reports`.
pub fn reporting_endpoints() -> ReportingEndpoints {
    ReportingEndpoints::new()
}

impl ReportingEndpoints {
    /// Constructs a handler with a single endpoint named `default` at `/_reports`.
    ///
    /// The `default` endpoint receives every report type that does not name its own endpoint,
    /// such as deprecations, interventions, and crashes.
    #[must_use]
    pub fn new() -> Self {
        Self {
            endpoints: Vec::new(),
            header_value: String::new(),
            csp_report_to: None,
            all_responses: false,
        }
        .with_endpoint("default", "/_reports")
    }

    /// Adds a named endpoint, replacing any existing endpoint with the same name.
    ///
    /// Policies refer to endpoints by name: a csp `report-to csp` directive sends to the endpoint
    /// named `csp`. Several names may point at the same url.
    ///
    /// # Panics
    ///
    /// Panics if the name is not a valid structured-field key (lowercase ascii letters, digits,
    /// `_`, `-`, `.`, and `*`, not starting with a digit), or if the url contains characters
    /// that cannot appear in a header value.
    #[must_use]
    pub fn with_endpoint(mut self, name: impl Into<String>, url: impl Into<String>) -> Self {
        let name = name.into();
        let url = url.into();
        validate_name(&name);
        validate_url(&url);

        match self.endpoints.iter_mut().find(|(n, _)| *n == name) {
            Some(existing) => existing.1 = url,
            None => self.endpoints.push((name, url)),
        }

        self.header_value = self
            .endpoints
            .iter()
            .map(|(name, url)| format!("{name}=\"{url}\""))
            .collect::<Vec<_>>()
            .join(", ");

        self
    }

    /// Appends `report-to <name>` to each outgoing `Content-Security-Policy` and
    /// `Content-Security-Policy-Report-Only` header that does not already have a `report-to`
    /// directive.
    ///
    /// The name must refer to an endpoint configured on this handler at the time the server
    /// starts.
    #[must_use]
    pub fn with_csp_report_to(mut self, name: impl Into<String>) -> Self {
        let name = name.into();
        validate_name(&name);
        self.csp_report_to = Some(name);
        self
    }

    /// Sets the header on every response, regardless of content type.
    #[must_use]
    pub const fn on_all_responses(mut self) -> Self {
        self.all_responses = true;
        self
    }

    /// The configured `Reporting-Endpoints` header value.
    pub fn header_value(&self) -> &str {
        &self.header_value
    }

    fn applies_to(&self, headers: &Headers) -> bool {
        self.all_responses
            || headers.get_str(ContentType).is_none_or(|content_type| {
                content_type
                    .trim_start()
                    .get(..9)
                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case("text/html"))
            })
    }
}

impl Default for ReportingEndpoints {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(
    clippy::unused_async_trait_impl,
    reason = "header rewriting needs no io; async is the trait's signature"
)]
impl Handler for ReportingEndpoints {
    async fn run(&self, conn: Conn) -> Conn {
        conn
    }

    async fn init(&mut self, _info: &mut Info) {
        if let Some(name) = &self.csp_report_to {
            assert!(
                self.endpoints.iter().any(|(n, _)| n == name),
                "with_csp_report_to({name:?}) names an endpoint that was not configured with \
                 with_endpoint"
            );
        }
    }

    async fn before_send(&self, mut conn: Conn) -> Conn {
        let headers = conn.response_headers_mut();
        if !self.applies_to(headers) {
            return conn;
        }

        headers.try_insert(HEADER_NAME, self.header_value.clone());

        if let Some(name) = &self.csp_report_to {
            for header in [ContentSecurityPolicy, ContentSecurityPolicyReportOnly] {
                if let Some(values) = headers.get_values(header) {
                    let appended = values
                        .iter()
                        .map(|value| {
                            value.as_str().map_or_else(
                                || value.clone(),
                                |policy| with_report_to(policy, name).into(),
                            )
                        })
                        .collect::<HeaderValues>();
                    headers.insert(header, appended);
                }
            }
        }

        conn
    }
}

/// Appends `report-to <name>` to a serialized csp policy unless one is already present.
///
/// Uses the csp parsing rules: directives are separated by `;`, and a directive's name is its
/// first whitespace-delimited token, compared ascii-case-insensitively.
fn with_report_to(policy: &str, name: &str) -> String {
    let has_report_to = policy.split(';').any(|directive| {
        directive
            .split_ascii_whitespace()
            .next()
            .is_some_and(|directive_name| directive_name.eq_ignore_ascii_case("report-to"))
    });

    if has_report_to {
        return policy.to_string();
    }

    let trimmed = policy.trim().trim_end_matches(';').trim_end();
    if trimmed.is_empty() {
        format!("report-to {name}")
    } else {
        format!("{trimmed}; report-to {name}")
    }
}

fn validate_name(name: &str) {
    let mut chars = name.chars();
    let valid_start = chars
        .next()
        .is_some_and(|first| first.is_ascii_lowercase() || first == '*');
    let valid_rest =
        chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "_-.*".contains(c));

    assert!(
        valid_start && valid_rest,
        "endpoint name {name:?} must be a structured-field key: lowercase ascii letters, digits, \
         `_`, `-`, `.`, `*`, not starting with a digit"
    );
}

fn validate_url(url: &str) {
    assert!(
        !url.is_empty()
            && url
                .chars()
                .all(|c| c.is_ascii_graphic() && c != '"' && c != '\\'),
        "endpoint url {url:?} must be nonempty, printable ascii, and contain no `\"` or `\\`"
    );
}

#[cfg(test)]
mod tests {
    use super::with_report_to;

    #[test]
    fn report_to_append() {
        assert_eq!(
            with_report_to("default-src 'self'", "csp"),
            "default-src 'self'; report-to csp"
        );
        assert_eq!(
            with_report_to("default-src 'self';", "csp"),
            "default-src 'self'; report-to csp"
        );
        assert_eq!(
            with_report_to("default-src 'self'; Report-To other", "csp"),
            "default-src 'self'; Report-To other"
        );
        assert_eq!(with_report_to("", "csp"), "report-to csp");
        assert_eq!(
            with_report_to("report-uri /legacy", "csp"),
            "report-uri /legacy; report-to csp"
        );
    }
}
