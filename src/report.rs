use std::{fmt::Write as _, fs, path::Path};

use anyhow::{Context, Result};
use clap::ValueEnum;

use crate::model::{DiagnosticReport, ProbeStatus, StageResult};

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ReportFormat {
    Table,
    Json,
    Markdown,
}

/// Renders a report without changing its target ordering.
///
/// # Errors
///
/// Returns an error when JSON serialization fails.
pub fn render(report: &DiagnosticReport, format: ReportFormat) -> Result<String> {
    match format {
        ReportFormat::Table => Ok(render_table(report)),
        ReportFormat::Json => {
            serde_json::to_string_pretty(report).context("could not serialize JSON report")
        }
        ReportFormat::Markdown => Ok(render_markdown(report)),
    }
}

/// Writes a report to a requested path or standard output.
///
/// # Errors
///
/// Returns an error when the output directory or report file cannot be written.
pub fn write(contents: &str, path: Option<&Path>) -> Result<()> {
    if let Some(path) = path {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
            && !parent.exists()
        {
            fs::create_dir_all(parent).with_context(|| {
                format!("could not create output directory {}", parent.display())
            })?;
        }
        fs::write(path, contents)
            .with_context(|| format!("could not write report {}", path.display()))?;
        println!("report written: {}", path.display());
    } else {
        println!("{contents}");
    }
    Ok(())
}

fn render_table(report: &DiagnosticReport) -> String {
    let mut output = String::new();
    output.push_str(
        "NAME                         HEALTH  DNS      TCP      HTTP     TOTAL   TARGET\n",
    );
    output.push_str(
        "---------------------------  ------  -------  -------  -------  ------  ------\n",
    );
    for target in &report.targets {
        writeln!(
            output,
            "{:<27}  {:<6}  {:<7}  {:<7}  {:<7}  {:>5}ms  {}",
            truncate(&target.name, 27),
            if target.healthy { "yes" } else { "no" },
            stage_label(&target.dns.stage),
            stage_label(&target.tcp.stage),
            stage_label(&target.http.stage),
            target.total_ms,
            target.target
        )
        .expect("writing to a String cannot fail");
    }
    writeln!(
        output,
        "\nsummary: {} total | {} healthy | {} unhealthy",
        report.summary.total, report.summary.healthy, report.summary.unhealthy
    )
    .expect("writing to a String cannot fail");
    output
}

fn render_markdown(report: &DiagnosticReport) -> String {
    let mut output = format!(
        "# PathLens network diagnostic report\n\n- Generated: `{}`\n- Schema: `{}`\n- Targets: **{}**\n- Healthy: **{}**\n- Unhealthy: **{}**\n\n",
        report.generated_at.to_rfc3339(),
        report.schema_version,
        report.summary.total,
        report.summary.healthy,
        report.summary.unhealthy
    );
    output.push_str("| Target | Healthy | DNS | TCP | HTTP | Total |\n");
    output.push_str("|---|---:|---|---|---|---:|\n");
    for target in &report.targets {
        writeln!(
            output,
            "| {} (`{}`) | {} | {} | {} | {} | {} ms |",
            escape_markdown(&target.name),
            escape_markdown(&target.target),
            if target.healthy { "yes" } else { "no" },
            stage_label(&target.dns.stage),
            stage_label(&target.tcp.stage),
            stage_label(&target.http.stage),
            target.total_ms
        )
        .expect("writing to a String cannot fail");
    }
    output.push_str("\n## Details\n");
    for target in &report.targets {
        writeln!(
            output,
            "\n### {}\n\n- DNS: {}\n- Addresses: {}\n- TCP: {}\n- Connected address: {}\n- HTTP: {}\n- TLS validated: {}",
            escape_markdown(&target.name),
            escape_markdown(&target.dns.stage.detail),
            escape_markdown(&target.dns.addresses.join(", ")),
            escape_markdown(&target.tcp.stage.detail),
            escape_markdown(target.tcp.connected_address.as_deref().unwrap_or("n/a")),
            escape_markdown(&target.http.stage.detail),
            target
                .http
                .tls_validated
                .map_or("n/a", |validated| if validated { "yes" } else { "no" })
        )
        .expect("writing to a String cannot fail");
    }
    output
}

fn stage_label(stage: &StageResult) -> &'static str {
    match stage.status {
        ProbeStatus::Pass => "pass",
        ProbeStatus::Fail => "fail",
        ProbeStatus::Skipped => "skipped",
    }
}

fn truncate(value: &str, max_chars: usize) -> String {
    let mut chars = value.chars();
    let truncated = chars.by_ref().take(max_chars).collect::<String>();
    if chars.next().is_some() && max_chars >= 1 {
        format!(
            "{}…",
            truncated.chars().take(max_chars - 1).collect::<String>()
        )
    } else {
        truncated
    }
}

fn escape_markdown(value: &str) -> String {
    value.replace('|', "\\|").replace(['\r', '\n'], " ")
}

#[cfg(test)]
mod tests {
    use crate::model::{
        DiagnosticReport, DnsObservation, HttpObservation, StageResult, TargetResult,
        TcpObservation,
    };

    use super::render_markdown;

    #[test]
    fn markdown_contains_stage_details() {
        let report = DiagnosticReport::new(vec![TargetResult {
            name: "example".to_owned(),
            target: "https://example.com/?redacted".to_owned(),
            healthy: true,
            total_ms: 12,
            dns: DnsObservation {
                stage: StageResult::pass(1, "resolved 1 address"),
                addresses: vec!["192.0.2.10".to_owned()],
            },
            tcp: TcpObservation {
                stage: StageResult::pass(3, "connected"),
                connected_address: Some("192.0.2.10:443".to_owned()),
            },
            http: HttpObservation {
                stage: StageResult::pass(8, "HTTP 200"),
                status_code: Some(200),
                protocol: Some("HTTP/2".to_owned()),
                content_type: None,
                server: None,
                location: None,
                tls_validated: Some(true),
            },
        }]);

        let markdown = render_markdown(&report);
        assert!(markdown.contains("# PathLens"));
        assert!(markdown.contains("192.0.2.10:443"));
        assert!(!markdown.contains("token="));
    }
}
