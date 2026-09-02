use trillium::{Conn, Handler, KnownHeaderName};
use trillium_reporting::{
    Disposition, LogSink, MemorySink, Report, ReportBody, ReportReceiver, ReportingEndpoints,
    report_receiver, reporting, reporting_endpoints,
};
use trillium_testing::{TestServer, harness, test};

const BATCH: &str = r#"[{
    "type": "csp-violation",
    "age": 1500,
    "url": "https://example.com/page",
    "user_agent": "Mozilla/5.0",
    "body": {
        "documentURL": "https://example.com/page",
        "referrer": "https://example.com/",
        "blockedURL": "https://evil.example/evil.js",
        "effectiveDirective": "script-src",
        "originalPolicy": "script-src 'self'; report-to csp",
        "disposition": "enforce",
        "statusCode": 200,
        "lineNumber": 12,
        "columnNumber": 3,
        "futureField": true
    }
}, {
    "type": "deprecation",
    "age": 10,
    "url": "https://example.com/page",
    "user_agent": "Mozilla/5.0",
    "body": {
        "id": "WebSQL",
        "anticipatedRemoval": "2026-01-01",
        "message": "WebSQL is deprecated",
        "sourceFile": "https://example.com/app.js",
        "lineNumber": 1,
        "columnNumber": 1
    }
}, {
    "type": "security-violation",
    "age": 10,
    "url": "https://example.com/page",
    "user_agent": "Mozilla/5.0",
    "body": { "blocked": "https://evil.example/evil.js" }
}, {
    "type": "csp-violation",
    "age": 10,
    "url": "https://example.com/page",
    "user_agent": "Mozilla/5.0",
    "body": { "not": "a csp violation" }
}]"#;

const LEGACY: &str = r#"{"csp-report": {
    "document-uri": "https://example.com/page",
    "referrer": "",
    "violated-directive": "script-src 'self'",
    "effective-directive": "script-src",
    "original-policy": "script-src 'self'; report-uri /_reports",
    "disposition": "report",
    "blocked-uri": "inline",
    "line-number": 5,
    "status-code": 200,
    "script-sample": ""
}}"#;

async fn html(conn: Conn) -> Conn {
    with_html(conn)
}

fn with_html(conn: Conn) -> Conn {
    conn.with_response_header(KnownHeaderName::ContentType, "text/html; charset=utf-8")
        .ok("<html></html>")
}

fn app(endpoints: ReportingEndpoints, receiver: ReportReceiver<MemorySink>) -> impl Handler {
    (endpoints, receiver, html)
}

#[test(harness)]
async fn typed_batch_parsing() {
    let sink = MemorySink::new(10);
    let app = TestServer::new(app(reporting_endpoints(), report_receiver(sink.clone()))).await;

    app.post("/_reports")
        .with_request_header(KnownHeaderName::ContentType, "application/reports+json")
        .with_body(BATCH)
        .await
        .assert_status(204);

    let reports = sink.drain();
    assert_eq!(reports.len(), 4);

    let ReportBody::CspViolation(csp) = &reports[0].body else {
        panic!("expected csp violation, got {:?}", reports[0].body);
    };
    assert_eq!(reports[0].age.as_millis(), 1500);
    assert_eq!(reports[0].user_agent.as_deref(), Some("Mozilla/5.0"));
    assert_eq!(
        csp.blocked_url.as_deref(),
        Some("https://evil.example/evil.js")
    );
    assert_eq!(csp.effective_directive, "script-src");
    assert_eq!(csp.disposition, Disposition::Enforce);
    assert_eq!(csp.line_number, Some(12));
    assert_eq!(csp.extra["futureField"], true);

    let ReportBody::Deprecation(deprecation) = &reports[1].body else {
        panic!("expected deprecation, got {:?}", reports[1].body);
    };
    assert_eq!(deprecation.id, "WebSQL");
    assert_eq!(
        deprecation.anticipated_removal.as_deref(),
        Some("2026-01-01")
    );

    let ReportBody::Other { type_name, body } = &reports[2].body else {
        panic!("expected other, got {:?}", reports[2].body);
    };
    assert_eq!(type_name, "security-violation");
    assert_eq!(body["blocked"], "https://evil.example/evil.js");

    let ReportBody::Other { type_name, .. } = &reports[3].body else {
        panic!("expected malformed csp report to fall back to other");
    };
    assert_eq!(type_name, "csp-violation");
    assert_eq!(reports[3].type_name(), "csp-violation");
}

#[test(harness)]
async fn legacy_csp_report() {
    let sink = MemorySink::new(10);
    let app = TestServer::new(app(reporting_endpoints(), report_receiver(sink.clone()))).await;

    app.post("/_reports")
        .with_request_header(KnownHeaderName::ContentType, "application/csp-report")
        .with_request_header(KnownHeaderName::UserAgent, "Legacy/1.0")
        .with_body(LEGACY)
        .await
        .assert_status(204);

    let [report] = &sink.drain()[..] else {
        panic!("expected exactly one report");
    };
    assert_eq!(report.url, "https://example.com/page");
    assert_eq!(report.user_agent.as_deref(), Some("Legacy/1.0"));
    let ReportBody::CspViolation(csp) = &report.body else {
        panic!("expected csp violation, got {:?}", report.body);
    };
    assert_eq!(csp.referrer, None);
    assert_eq!(csp.effective_directive, "script-src");
    assert_eq!(csp.disposition, Disposition::Report);
    assert_eq!(csp.blocked_url.as_deref(), Some("inline"));
}

#[test(harness)]
async fn receiver_rejections() {
    let sink = MemorySink::new(10);
    let app = TestServer::new(app(reporting_endpoints(), report_receiver(sink.clone()))).await;

    app.get("/_reports")
        .await
        .assert_status(405)
        .assert_header(KnownHeaderName::Allow, "POST");

    app.post("/_reports")
        .with_request_header(KnownHeaderName::ContentType, "application/json")
        .with_body(BATCH)
        .await
        .assert_status(415);

    app.post("/_reports")
        .with_request_header(KnownHeaderName::ContentType, "application/reports+json")
        .with_body("not json")
        .await
        .assert_status(400);

    app.post("/_reports")
        .with_request_header(KnownHeaderName::ContentType, "application/reports+json")
        .with_body("[]")
        .await
        .assert_status(204);

    app.post("/elsewhere").await.assert_status(200);

    assert!(sink.is_empty());
}

#[test(harness)]
async fn oversized_delivery() {
    let sink = MemorySink::new(10);
    let receiver = report_receiver(sink.clone()).with_max_body_len(16);
    let app = TestServer::new(app(reporting_endpoints(), receiver)).await;

    app.post("/_reports")
        .with_request_header(KnownHeaderName::ContentType, "application/reports+json")
        .with_body(BATCH)
        .await
        .assert_status(413);
}

#[test(harness)]
async fn header_on_html_only_by_default() {
    let app = TestServer::new((
        reporting_endpoints(),
        report_receiver(LogSink),
        |conn: Conn| async move {
            if conn.path() == "/json" {
                conn.with_response_header(KnownHeaderName::ContentType, "application/json")
                    .ok("{}")
            } else if conn.path() == "/untyped" {
                conn.ok("plain")
            } else {
                with_html(conn)
            }
        },
    ))
    .await;

    app.get("/")
        .await
        .assert_header("reporting-endpoints", "default=\"/_reports\"");
    app.get("/untyped")
        .await
        .assert_header("reporting-endpoints", "default=\"/_reports\"");
    app.get("/json")
        .await
        .assert_no_header("reporting-endpoints");
}

#[test(harness)]
async fn header_on_all_responses() {
    let app = TestServer::new((
        reporting_endpoints()
            .with_endpoint("csp", "/_reports")
            .on_all_responses(),
        |conn: Conn| async move {
            conn.with_response_header(KnownHeaderName::ContentType, "application/json")
                .ok("{}")
        },
    ))
    .await;

    app.get("/").await.assert_header(
        "reporting-endpoints",
        "default=\"/_reports\", csp=\"/_reports\"",
    );
}

#[test(harness)]
async fn existing_header_is_preserved() {
    let app = TestServer::new((reporting_endpoints(), |conn: Conn| async move {
        with_html(conn).with_response_header("reporting-endpoints", "default=\"https://other/\"")
    }))
    .await;

    app.get("/")
        .await
        .assert_header("reporting-endpoints", "default=\"https://other/\"");
}

#[test(harness)]
async fn csp_report_to() {
    let app = TestServer::new((
        reporting_endpoints()
            .with_endpoint("csp", "/_reports")
            .with_csp_report_to("csp"),
        |conn: Conn| async move {
            with_html(conn)
                .with_response_header(KnownHeaderName::ContentSecurityPolicy, "default-src 'self'")
                .with_response_header(
                    KnownHeaderName::ContentSecurityPolicyReportOnly,
                    "script-src 'none'; report-to existing",
                )
        },
    ))
    .await;

    app.get("/")
        .await
        .assert_header(
            KnownHeaderName::ContentSecurityPolicy,
            "default-src 'self'; report-to csp",
        )
        .assert_header(
            KnownHeaderName::ContentSecurityPolicyReportOnly,
            "script-src 'none'; report-to existing",
        );
}

#[test(harness)]
async fn closure_sink_and_one_shot() {
    let sink = MemorySink::new(2);
    let clone = sink.clone();
    let app = TestServer::new((
        reporting(move |reports: Vec<Report>| {
            let clone = clone.clone();
            async move { clone.receive_all(reports) }
        }),
        html,
    ))
    .await;

    for _ in 0..3 {
        app.post("/_reports")
            .with_request_header(KnownHeaderName::ContentType, "application/reports+json")
            .with_body(BATCH)
            .await
            .assert_status(204);
    }

    assert_eq!(sink.len(), 2);
    assert_eq!(sink.capacity(), 2);
}

trait ReceiveAll {
    fn receive_all(&self, reports: Vec<Report>);
}

impl ReceiveAll for MemorySink {
    fn receive_all(&self, reports: Vec<Report>) {
        for report in reports {
            self.push(report);
        }
    }
}

#[test]
#[should_panic(expected = "structured-field key")]
fn invalid_endpoint_name() {
    let _ = reporting_endpoints().with_endpoint("Bad Name", "/x");
}

#[test]
#[should_panic(expected = "endpoint url")]
fn invalid_endpoint_url() {
    let _ = reporting_endpoints().with_endpoint("ok", "/has\"quote");
}
