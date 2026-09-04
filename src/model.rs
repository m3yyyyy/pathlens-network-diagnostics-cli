use chrono::{DateTime, Utc};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ProbeStatus {
    Pass,
    Fail,
    Skipped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StageResult {
    pub status: ProbeStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    pub detail: String,
}

impl StageResult {
    pub fn pass(latency_ms: u64, detail: impl Into<String>) -> Self {
        Self {
            status: ProbeStatus::Pass,
            latency_ms: Some(latency_ms),
            detail: detail.into(),
        }
    }

    pub fn fail(latency_ms: u64, detail: impl Into<String>) -> Self {
        Self {
            status: ProbeStatus::Fail,
            latency_ms: Some(latency_ms),
            detail: detail.into(),
        }
    }

    pub fn skipped(detail: impl Into<String>) -> Self {
        Self {
            status: ProbeStatus::Skipped,
            latency_ms: None,
            detail: detail.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DnsObservation {
    #[serde(flatten)]
    pub stage: StageResult,
    pub addresses: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TcpObservation {
    #[serde(flatten)]
    pub stage: StageResult,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connected_address: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HttpObservation {
    #[serde(flatten)]
    pub stage: StageResult,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_validated: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TargetResult {
    pub name: String,
    pub target: String,
    pub healthy: bool,
    pub total_ms: u64,
    pub dns: DnsObservation,
    pub tcp: TcpObservation,
    pub http: HttpObservation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ReportSummary {
    pub total: usize,
    pub healthy: usize,
    pub unhealthy: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiagnosticReport {
    pub schema_version: &'static str,
    pub generated_at: DateTime<Utc>,
    pub summary: ReportSummary,
    pub targets: Vec<TargetResult>,
}

impl DiagnosticReport {
    pub fn new(targets: Vec<TargetResult>) -> Self {
        let healthy = targets.iter().filter(|target| target.healthy).count();
        Self {
            schema_version: "pathlens/v1",
            generated_at: Utc::now(),
            summary: ReportSummary {
                total: targets.len(),
                healthy,
                unhealthy: targets.len() - healthy,
            },
            targets,
        }
    }

    pub const fn is_healthy(&self) -> bool {
        self.summary.unhealthy == 0
    }
}
