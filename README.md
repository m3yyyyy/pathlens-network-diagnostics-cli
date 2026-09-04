# PathLens Network Diagnostics CLI

[![CI](https://github.com/m3yyyyy/pathlens-network-diagnostics-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/m3yyyyy/pathlens-network-diagnostics-cli/actions/workflows/ci.yml)
[![Rust](https://img.shields.io/badge/Rust-1.90-000000?logo=rust)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

PathLens is a concurrent, safety-focused network reliability diagnostics CLI. It separates DNS resolution, TCP reachability and HTTP/TLS validation so operators can see where a connection path fails instead of receiving one generic timeout.

It is designed as a production-grade reference implementation for IT operations, network support, platform engineering and CI health checks.

## What it does

- checks up to 64 explicit HTTP or HTTPS targets with bounded concurrency;
- records DNS answers, TCP connection results and HTTP response metadata;
- validates HTTPS certificates through Rustls during the HTTP probe;
- supports exact expected status codes or a default successful range of `200..399`;
- emits terminal tables, structured JSON or reviewable Markdown;
- preserves input order even though probes run concurrently;
- returns exit code `2` when any target is unhealthy;
- redacts URL query values and redirect locations from every report.

PathLens does **not** capture packets, scan ports, follow redirects, read response bodies, accept credentials in URLs or disable TLS verification.

## Quick start

Confirm the Rust toolchain:

```powershell
rustc --version
cargo --version
```

Build and test:

```powershell
cargo test --all-targets
cargo build --release
```

Check one endpoint:

```powershell
.\target\release\pathlens.exe check --target https://example.com
```

Check multiple endpoints and write a JSON report:

```powershell
.\target\release\pathlens.exe check `
  --target https://example.com `
  --target https://www.githubstatus.com/api/v2/status.json `
  --method GET `
  --format json `
  --output .\reports\network.json
```

Run the included YAML configuration:

```powershell
.\target\release\pathlens.exe validate --config .\examples\pathlens.yml
.\target\release\pathlens.exe run --config .\examples\pathlens.yml --format markdown
```

Linux and macOS use the same arguments with `./target/release/pathlens`.

## Configuration

```yaml
version: 1

defaults:
  timeout_ms: 5000
  concurrency: 4
  method: HEAD
  expect_status: [200, 204]

targets:
  - name: public-home
    url: https://example.com/

  - name: internal-health
    url: https://service.internal/health
    method: GET
    timeout_ms: 2000
    expect_status: [200]
```

Safety limits are enforced before any network request:

| Setting | Accepted values |
|---|---|
| `version` | `1` |
| targets | 1–64, with unique names |
| URL schemes | `http`, `https` |
| methods | `HEAD`, `GET` |
| timeout | 100–60,000 ms per stage |
| concurrency | 1–32 |
| expected status | 100–599 |

Unknown YAML fields and URL credentials are rejected rather than silently ignored.

## Report contract

JSON output uses the versioned `pathlens/v1` schema. Each target contains:

- the sanitized target URL;
- overall health and elapsed time;
- DNS status and unique addresses;
- TCP status and the connected socket address;
- HTTP status, protocol and a small allowlist of response headers;
- whether TLS validation completed for HTTPS.

PathLens never stores response bodies or request credentials. Query parameters are replaced with `?redacted` in output.

## Exit codes

| Code | Meaning |
|---:|---|
| `0` | Configuration is valid or all probes are healthy |
| `2` | At least one target is unhealthy |
| `70` | Configuration, report or internal execution error |

## Architecture worth studying

PathLens uses a bounded fan-out/fan-in pipeline:

```text
validated targets
      │
      ▼
bounded Tokio task set ──► DNS ──► TCP ──► HTTP/TLS
      │                                  │
      └──────── ordered aggregation ◄────┘
                         │
                         ▼
                table / JSON / Markdown
```

Each stage has a deadline and an explicit `pass`, `fail` or `skipped` state. Failed prerequisites stop downstream probes, while independent targets continue. Results are reordered by their original index before reporting, making JSON and Markdown stable enough for CI artifacts and reviews.

See [architecture](docs/architecture.md) and [threat model](docs/threat-model.md) for the detailed boundaries.

## Development

```powershell
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

CI runs formatting, Clippy, tests and release builds on Windows, Linux and macOS. Tags matching `v*` publish four cross-platform binaries plus `SHA256SUMS`.

## Responsible use

Only probe systems you own or are authorized to test. PathLens performs ordinary DNS lookups and one explicit TCP and HTTP request per target; it is not a vulnerability scanner.

## License

MIT
