use std::{collections::BTreeSet, net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use reqwest::{Client, Method, redirect::Policy};
use tokio::{
    net::{TcpStream, lookup_host},
    sync::Semaphore,
    task::JoinSet,
    time::{Instant, timeout},
};

use crate::{
    VERSION,
    config::{ResolvedConfig, ResolvedTarget},
    model::{
        DiagnosticReport, DnsObservation, HttpObservation, StageResult, TargetResult,
        TcpObservation,
    },
    redact::{sanitized_location, sanitized_url},
};

/// Runs every validated target with bounded concurrency and stable result ordering.
///
/// # Errors
///
/// Returns an error when the shared client or task scheduler cannot complete safely.
pub async fn run(config: ResolvedConfig) -> Result<DiagnosticReport> {
    let client = Client::builder()
        .redirect(Policy::none())
        .no_proxy()
        .user_agent(format!("pathlens/{VERSION}"))
        .build()
        .context("could not initialize HTTP client")?;
    let semaphore = Arc::new(Semaphore::new(config.concurrency));
    let mut tasks = JoinSet::new();

    for (index, target) in config.targets.into_iter().enumerate() {
        let permit = Arc::clone(&semaphore)
            .acquire_owned()
            .await
            .context("probe scheduler closed unexpectedly")?;
        let client = client.clone();
        tasks.spawn(async move {
            let _permit = permit;
            (index, probe_target(client, target).await)
        });
    }

    let mut results = Vec::new();
    while let Some(result) = tasks.join_next().await {
        results.push(result.context("a probe task ended unexpectedly")?);
    }
    results.sort_by_key(|(index, _)| *index);

    Ok(DiagnosticReport::new(
        results.into_iter().map(|(_, result)| result).collect(),
    ))
}

async fn probe_target(client: Client, target: ResolvedTarget) -> TargetResult {
    let overall_start = Instant::now();
    let sanitized_target = sanitized_url(&target.url);
    let host = target.url.host_str().unwrap_or_default().to_owned();
    let port = target.url.port_or_known_default().unwrap_or(80);
    let stage_timeout = Duration::from_millis(target.timeout_ms);

    let dns_start = Instant::now();
    let lookup = timeout(stage_timeout, lookup_host((host.as_str(), port))).await;
    let (dns, socket_addresses) = match lookup {
        Ok(Ok(addresses)) => {
            let socket_addresses = addresses
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            if socket_addresses.is_empty() {
                (
                    DnsObservation {
                        stage: StageResult::fail(
                            elapsed_ms(dns_start),
                            "resolver returned no addresses",
                        ),
                        addresses: Vec::new(),
                    },
                    Vec::new(),
                )
            } else {
                let display_addresses = socket_addresses
                    .iter()
                    .map(|address| address.ip().to_string())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect();
                (
                    DnsObservation {
                        stage: StageResult::pass(
                            elapsed_ms(dns_start),
                            format!("resolved {} address(es)", socket_addresses.len()),
                        ),
                        addresses: display_addresses,
                    },
                    socket_addresses,
                )
            }
        }
        Ok(Err(_)) => (
            DnsObservation {
                stage: StageResult::fail(elapsed_ms(dns_start), "DNS resolution failed"),
                addresses: Vec::new(),
            },
            Vec::new(),
        ),
        Err(_) => (
            DnsObservation {
                stage: StageResult::fail(elapsed_ms(dns_start), "DNS resolution timed out"),
                addresses: Vec::new(),
            },
            Vec::new(),
        ),
    };

    if socket_addresses.is_empty() {
        return TargetResult {
            name: target.name,
            target: sanitized_target,
            healthy: false,
            total_ms: elapsed_ms(overall_start),
            dns,
            tcp: TcpObservation {
                stage: StageResult::skipped("DNS did not produce a usable address"),
                connected_address: None,
            },
            http: skipped_http("TCP probe was not attempted"),
        };
    }

    let tcp_start = Instant::now();
    let connected_address = connect_first(&socket_addresses, stage_timeout).await;
    let tcp = match connected_address {
        Some(address) => TcpObservation {
            stage: StageResult::pass(elapsed_ms(tcp_start), "TCP connection established"),
            connected_address: Some(address.to_string()),
        },
        None => TcpObservation {
            stage: StageResult::fail(
                elapsed_ms(tcp_start),
                "TCP connection failed for all resolved addresses",
            ),
            connected_address: None,
        },
    };

    if connected_address.is_none() {
        return TargetResult {
            name: target.name,
            target: sanitized_target,
            healthy: false,
            total_ms: elapsed_ms(overall_start),
            dns,
            tcp,
            http: skipped_http("TCP connection could not be established"),
        };
    }

    let http_start = Instant::now();
    let method = if target.method == "HEAD" {
        Method::HEAD
    } else {
        Method::GET
    };
    let response = client
        .request(method, target.url.clone())
        .timeout(stage_timeout)
        .send()
        .await;

    let http = match response {
        Ok(response) => {
            let status = response.status().as_u16();
            let accepted = target.accepts_status(status);
            let headers = response.headers();
            let content_type = header_value(headers, reqwest::header::CONTENT_TYPE);
            let server = header_value(headers, reqwest::header::SERVER);
            let location = header_value(headers, reqwest::header::LOCATION)
                .map(|value| sanitized_location(&value));
            let protocol = format!("{:?}", response.version());
            let tls_validated = (target.url.scheme() == "https").then_some(true);
            let stage = if accepted {
                StageResult::pass(elapsed_ms(http_start), format!("HTTP {status}"))
            } else {
                StageResult::fail(
                    elapsed_ms(http_start),
                    format!("HTTP {status} was outside the expected set"),
                )
            };
            HttpObservation {
                stage,
                status_code: Some(status),
                protocol: Some(protocol),
                content_type,
                server,
                location,
                tls_validated,
            }
        }
        Err(error) => HttpObservation {
            stage: StageResult::fail(elapsed_ms(http_start), describe_http_error(&error)),
            status_code: None,
            protocol: None,
            content_type: None,
            server: None,
            location: None,
            tls_validated: None,
        },
    };

    let healthy = matches!(http.stage.status, crate::model::ProbeStatus::Pass);
    TargetResult {
        name: target.name,
        target: sanitized_target,
        healthy,
        total_ms: elapsed_ms(overall_start),
        dns,
        tcp,
        http,
    }
}

async fn connect_first(addresses: &[SocketAddr], duration: Duration) -> Option<SocketAddr> {
    timeout(duration, async {
        for address in addresses {
            if TcpStream::connect(address).await.is_ok() {
                return Some(*address);
            }
        }
        None
    })
    .await
    .ok()
    .flatten()
}

fn skipped_http(reason: &str) -> HttpObservation {
    HttpObservation {
        stage: StageResult::skipped(reason),
        status_code: None,
        protocol: None,
        content_type: None,
        server: None,
        location: None,
        tls_validated: None,
    }
}

fn header_value(
    headers: &reqwest::header::HeaderMap,
    name: reqwest::header::HeaderName,
) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.chars().take(256).collect())
}

fn describe_http_error(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "HTTP request timed out"
    } else if error.is_connect() {
        "HTTP connection or TLS validation failed"
    } else if error.is_redirect() {
        "HTTP redirect processing failed"
    } else if error.is_request() {
        "HTTP request could not be created"
    } else {
        "HTTP request failed"
    }
}

fn elapsed_ms(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    use crate::config::from_cli_targets;

    use super::run;

    #[tokio::test]
    async fn probes_local_http_without_exposing_query_values() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind server");
        let address = listener.local_addr().expect("server address");
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().await.expect("accept request");
                let mut request = [0_u8; 1_024];
                let bytes_read = stream.read(&mut request).await.expect("read request");
                if bytes_read > 0 {
                    stream
                        .write_all(b"HTTP/1.1 204 No Content\r\nServer: pathlens-test\r\nConnection: close\r\n\r\n")
                        .await
                        .expect("write response");
                }
            }
        });
        let config = from_cli_targets(
            vec![format!("http://{address}/health?token=secret")],
            2_000,
            1,
            "GET".to_owned(),
            vec![204],
        )
        .expect("valid config");

        let report = run(config).await.expect("probe report");
        server.await.expect("server task");

        assert!(report.is_healthy());
        assert_eq!(report.targets[0].http.status_code, Some(204));
        assert!(report.targets[0].target.contains("?redacted"));
        assert!(!report.targets[0].target.contains("secret"));
    }
}
