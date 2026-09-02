use serde::Deserialize;
use serde_json::{Map, Value};
use std::time::Duration;

/// A single report as delivered by a browser.
#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    /// Time elapsed between the report's generation and its delivery.
    pub age: Duration,
    /// The url of the document or worker that generated the report, with credentials and
    /// fragment stripped by the browser.
    pub url: String,
    /// The user agent that generated the report.
    pub user_agent: Option<String>,
    /// The type-specific content of the report.
    pub body: ReportBody,
}

impl Report {
    /// Parses an `application/reports+json` batch.
    ///
    /// Reports whose `type` names a variant of [`ReportBody`] but whose `body` does not match
    /// that variant's shape are preserved as [`ReportBody::Other`] rather than rejected.
    ///
    /// # Errors
    ///
    /// Returns an error if the input is not a json array of objects with the required `type`
    /// and `url` fields.
    pub fn parse_batch(bytes: &[u8]) -> serde_json::Result<Vec<Self>> {
        let raw: Vec<RawReport> = serde_json::from_slice(bytes)?;
        Ok(raw.into_iter().map(Self::from).collect())
    }

    /// Parses a legacy `application/csp-report` document, as sent for the csp `report-uri`
    /// directive.
    ///
    /// Legacy reports carry no age or user agent, so age is zero and the user agent must be
    /// supplied from the request.
    ///
    /// # Errors
    ///
    /// Returns an error if the input is not a json object with a `csp-report` member carrying
    /// `document-uri` and `original-policy`.
    pub fn parse_legacy_csp(bytes: &[u8], user_agent: Option<&str>) -> serde_json::Result<Self> {
        let LegacyCspDocument { csp_report } = serde_json::from_slice(bytes)?;
        Ok(Self {
            age: Duration::ZERO,
            url: csp_report.document_uri.clone(),
            user_agent: user_agent.map(String::from),
            body: ReportBody::CspViolation(csp_report.into()),
        })
    }

    /// The report's `type` string, such as `csp-violation`.
    pub fn type_name(&self) -> &str {
        self.body.type_name()
    }
}

#[derive(Deserialize)]
struct RawReport {
    #[serde(default)]
    age: i64,
    #[serde(rename = "type")]
    type_name: String,
    url: String,
    #[serde(default)]
    user_agent: Option<String>,
    #[serde(default)]
    body: Value,
}

impl From<RawReport> for Report {
    fn from(raw: RawReport) -> Self {
        let RawReport {
            age,
            type_name,
            url,
            user_agent,
            body,
        } = raw;

        Self {
            age: Duration::from_millis(u64::try_from(age).unwrap_or(0)),
            url,
            user_agent,
            body: ReportBody::parse(type_name, body),
        }
    }
}

/// The type-specific content of a [`Report`].
///
/// Every typed variant keeps fields it does not model in an `extra` map, so a browser adding a
/// field does not lose data. A report whose type is unknown, or whose body does not match the
/// expected shape for its type, is [`ReportBody::Other`].
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum ReportBody {
    /// A `csp-violation` report.
    CspViolation(CspViolation),
    /// A `coop` (cross-origin-opener-policy) report.
    Coop(CoopViolation),
    /// A `coep` (cross-origin-embedder-policy) report.
    Coep(CoepViolation),
    /// A `deprecation` report.
    Deprecation(Deprecation),
    /// An `intervention` report.
    Intervention(Intervention),
    /// A `crash` report.
    Crash(Crash),
    /// A `document-policy-violation` report.
    DocumentPolicyViolation(DocumentPolicyViolation),
    /// A `permissions-policy-violation` report.
    PermissionsPolicyViolation(PermissionsPolicyViolation),
    /// An `integrity-violation` report.
    IntegrityViolation(IntegrityViolation),
    /// A `network-error` (network error logging) report.
    NetworkError(NetworkError),
    /// A report of a type this crate does not model, or whose body did not have the expected
    /// shape for its type.
    Other {
        /// The report's `type` string.
        type_name: String,
        /// The report's `body`, unparsed.
        body: Value,
    },
}

impl ReportBody {
    fn parse(type_name: String, body: Value) -> Self {
        fn typed<T: for<'de> Deserialize<'de>>(body: &Value) -> Option<T> {
            serde_json::from_value(body.clone()).ok()
        }

        let parsed = match &*type_name {
            "csp-violation" => typed(&body).map(Self::CspViolation),
            "coop" => typed(&body).map(Self::Coop),
            "coep" => typed(&body).map(Self::Coep),
            "deprecation" => typed(&body).map(Self::Deprecation),
            "intervention" => typed(&body).map(Self::Intervention),
            "crash" => typed(&body).map(Self::Crash),
            "document-policy-violation" => typed(&body).map(Self::DocumentPolicyViolation),
            "permissions-policy-violation" => typed(&body).map(Self::PermissionsPolicyViolation),
            "integrity-violation" => typed(&body).map(Self::IntegrityViolation),
            "network-error" => typed(&body).map(Self::NetworkError),
            _ => None,
        };

        parsed.unwrap_or(Self::Other { type_name, body })
    }

    /// The report's `type` string, such as `csp-violation`.
    pub fn type_name(&self) -> &str {
        match self {
            Self::CspViolation(_) => "csp-violation",
            Self::Coop(_) => "coop",
            Self::Coep(_) => "coep",
            Self::Deprecation(_) => "deprecation",
            Self::Intervention(_) => "intervention",
            Self::Crash(_) => "crash",
            Self::DocumentPolicyViolation(_) => "document-policy-violation",
            Self::PermissionsPolicyViolation(_) => "permissions-policy-violation",
            Self::IntegrityViolation(_) => "integrity-violation",
            Self::NetworkError(_) => "network-error",
            Self::Other { type_name, .. } => type_name,
        }
    }
}

/// Whether the policy that generated a report was enforced or report-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Disposition {
    /// The policy blocked the action.
    Enforce,
    /// The policy was report-only and the action proceeded.
    Report,
}

/// Body of a `csp-violation` report.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CspViolation {
    /// The url of the document that violated the policy.
    #[serde(rename = "documentURL")]
    pub document_url: String,
    /// The document's referrer.
    #[serde(default)]
    pub referrer: Option<String>,
    /// The url of the blocked resource, or a keyword such as `inline` or `eval`.
    #[serde(default, rename = "blockedURL")]
    pub blocked_url: Option<String>,
    /// The directive whose enforcement caused the violation.
    pub effective_directive: String,
    /// The full policy that was violated.
    pub original_policy: String,
    /// The script or stylesheet in which the violation occurred.
    #[serde(default)]
    pub source_file: Option<String>,
    /// The first 40 characters of the violating inline script or style, when the policy
    /// includes `'report-sample'`.
    #[serde(default)]
    pub sample: Option<String>,
    /// Whether the policy was enforced or report-only.
    pub disposition: Disposition,
    /// The http status of the document.
    #[serde(default)]
    pub status_code: Option<u16>,
    /// The line at which the violation occurred.
    #[serde(default)]
    pub line_number: Option<u32>,
    /// The column at which the violation occurred.
    #[serde(default)]
    pub column_number: Option<u32>,
    /// Fields not modeled by this struct.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Body of a `coop` (cross-origin-opener-policy) report.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CoopViolation {
    /// Whether the policy was enforced or report-only.
    pub disposition: Disposition,
    /// The opener policy in effect.
    pub effective_policy: String,
    /// The kind of event, such as `navigation-from-response` or `access-to-opener`.
    #[serde(rename = "type")]
    pub type_name: String,
    /// The url of the previous document in a navigation.
    #[serde(default, rename = "previousResponseURL")]
    pub previous_response_url: Option<String>,
    /// The url of the next document in a navigation.
    #[serde(default, rename = "nextResponseURL")]
    pub next_response_url: Option<String>,
    /// The url of the opener document.
    #[serde(default, rename = "openerURL")]
    pub opener_url: Option<String>,
    /// The url of the opened document.
    #[serde(default, rename = "openeeURL")]
    pub openee_url: Option<String>,
    /// The url of the other document in an access violation.
    #[serde(default, rename = "otherDocumentURL")]
    pub other_document_url: Option<String>,
    /// The document's referrer.
    #[serde(default)]
    pub referrer: Option<String>,
    /// The script in which the violation occurred.
    #[serde(default)]
    pub source_file: Option<String>,
    /// The line at which the violation occurred.
    #[serde(default)]
    pub line_number: Option<u32>,
    /// The column at which the violation occurred.
    #[serde(default)]
    pub column_number: Option<u32>,
    /// Fields not modeled by this struct.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Body of a `coep` (cross-origin-embedder-policy) report.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CoepViolation {
    /// The kind of event: `corp`, `navigation`, or `worker initialization`.
    #[serde(rename = "type")]
    pub type_name: String,
    /// The url of the blocked resource.
    #[serde(default, rename = "blockedURL")]
    pub blocked_url: Option<String>,
    /// Whether the policy was enforced or report-only.
    #[serde(default)]
    pub disposition: Option<Disposition>,
    /// The request destination of the blocked resource.
    #[serde(default)]
    pub destination: Option<String>,
    /// Fields not modeled by this struct.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Body of a `deprecation` report.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Deprecation {
    /// The browser's identifier for the deprecated feature.
    pub id: String,
    /// The date the browser expects to remove the feature, if known.
    #[serde(default)]
    pub anticipated_removal: Option<String>,
    /// A human-readable description.
    #[serde(default)]
    pub message: Option<String>,
    /// The script in which the feature was used.
    #[serde(default)]
    pub source_file: Option<String>,
    /// The line at which the feature was used.
    #[serde(default)]
    pub line_number: Option<u32>,
    /// The column at which the feature was used.
    #[serde(default)]
    pub column_number: Option<u32>,
    /// Fields not modeled by this struct.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Body of an `intervention` report.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Intervention {
    /// The browser's identifier for the intervention.
    pub id: String,
    /// A human-readable description.
    #[serde(default)]
    pub message: Option<String>,
    /// The script that triggered the intervention.
    #[serde(default)]
    pub source_file: Option<String>,
    /// The line that triggered the intervention.
    #[serde(default)]
    pub line_number: Option<u32>,
    /// The column that triggered the intervention.
    #[serde(default)]
    pub column_number: Option<u32>,
    /// Fields not modeled by this struct.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Body of a `crash` report.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Crash {
    /// The reason for the crash, such as `oom` or `unresponsive`, if known.
    #[serde(default)]
    pub reason: Option<String>,
    /// Fields not modeled by this struct.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Body of a `document-policy-violation` report.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DocumentPolicyViolation {
    /// The policy feature that was violated.
    pub feature_id: String,
    /// Whether the policy was enforced or report-only.
    #[serde(default)]
    pub disposition: Option<Disposition>,
    /// A human-readable description.
    #[serde(default)]
    pub message: Option<String>,
    /// The script in which the violation occurred.
    #[serde(default)]
    pub source_file: Option<String>,
    /// The line at which the violation occurred.
    #[serde(default)]
    pub line_number: Option<u32>,
    /// The column at which the violation occurred.
    #[serde(default)]
    pub column_number: Option<u32>,
    /// Fields not modeled by this struct.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Body of a `permissions-policy-violation` report.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionsPolicyViolation {
    /// The policy feature that was violated.
    #[serde(alias = "policyId")]
    pub feature_id: String,
    /// Whether the policy was enforced or report-only.
    #[serde(default)]
    pub disposition: Option<Disposition>,
    /// A human-readable description.
    #[serde(default)]
    pub message: Option<String>,
    /// The script in which the violation occurred.
    #[serde(default)]
    pub source_file: Option<String>,
    /// The line at which the violation occurred.
    #[serde(default)]
    pub line_number: Option<u32>,
    /// The column at which the violation occurred.
    #[serde(default)]
    pub column_number: Option<u32>,
    /// Fields not modeled by this struct.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Body of an `integrity-violation` report.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IntegrityViolation {
    /// The url of the document that made the request.
    #[serde(rename = "documentURL")]
    pub document_url: String,
    /// The url of the resource that failed its integrity check.
    #[serde(rename = "blockedURL")]
    pub blocked_url: String,
    /// The request destination of the blocked resource.
    #[serde(default)]
    pub destination: Option<String>,
    /// Whether the policy was report-only.
    #[serde(default)]
    pub report_only: bool,
    /// Fields not modeled by this struct.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Body of a `network-error` report.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct NetworkError {
    /// The fraction of requests of this kind that the browser reports.
    #[serde(default)]
    pub sampling_fraction: Option<f64>,
    /// The ip address the browser connected to.
    #[serde(default)]
    pub server_ip: Option<String>,
    /// The negotiated application protocol, such as `h2`.
    #[serde(default)]
    pub protocol: Option<String>,
    /// The request method.
    #[serde(default)]
    pub method: Option<String>,
    /// The response status, or zero if none was received.
    #[serde(default)]
    pub status_code: Option<u16>,
    /// Milliseconds between request start and completion or failure.
    #[serde(default)]
    pub elapsed_time: Option<u64>,
    /// The phase in which the error occurred: `dns`, `connection`, or `application`.
    #[serde(default)]
    pub phase: Option<String>,
    /// The error, such as `ok` or `http.dns.name_not_resolved`.
    #[serde(rename = "type")]
    pub type_name: String,
    /// The request's referrer.
    #[serde(default)]
    pub referrer: Option<String>,
    /// Fields not modeled by this struct.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Deserialize)]
struct LegacyCspDocument {
    #[serde(rename = "csp-report")]
    csp_report: LegacyCspReport,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
struct LegacyCspReport {
    document_uri: String,
    #[serde(default)]
    referrer: Option<String>,
    #[serde(default)]
    blocked_uri: Option<String>,
    #[serde(default)]
    effective_directive: Option<String>,
    #[serde(default)]
    violated_directive: Option<String>,
    original_policy: String,
    #[serde(default)]
    source_file: Option<String>,
    #[serde(default)]
    script_sample: Option<String>,
    #[serde(default)]
    disposition: Option<Disposition>,
    #[serde(default)]
    status_code: Option<u16>,
    #[serde(default)]
    line_number: Option<u32>,
    #[serde(default)]
    column_number: Option<u32>,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

impl From<LegacyCspReport> for CspViolation {
    fn from(legacy: LegacyCspReport) -> Self {
        Self {
            document_url: legacy.document_uri,
            referrer: legacy.referrer.filter(|referrer| !referrer.is_empty()),
            blocked_url: legacy.blocked_uri,
            effective_directive: legacy
                .effective_directive
                .or(legacy.violated_directive)
                .unwrap_or_default(),
            original_policy: legacy.original_policy,
            source_file: legacy.source_file,
            sample: legacy.script_sample,
            disposition: legacy.disposition.unwrap_or(Disposition::Enforce),
            status_code: legacy.status_code,
            line_number: legacy.line_number,
            column_number: legacy.column_number,
            extra: legacy.extra,
        }
    }
}
