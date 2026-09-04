# Architecture

## Design goals

PathLens optimizes for explainability, bounded resource use and deterministic evidence. A failed endpoint should identify the failing layer without turning the tool into a packet capture or broad scanner.

## Modules

| Module | Responsibility |
|---|---|
| `cli` | Command parsing, exit-code policy and output selection |
| `config` | Strict YAML parsing, defaults and fail-closed validation |
| `probe` | Bounded orchestration and DNS/TCP/HTTP execution |
| `model` | Versioned serializable report types |
| `redact` | URL and redirect-location sanitization |
| `report` | Deterministic table, JSON and Markdown rendering |

## Execution flow

1. Parse CLI arguments or a version 1 YAML document.
2. Reject unknown fields, unsafe URL forms and values outside hard limits.
3. Build one HTTP client with redirects and environment proxies disabled.
4. Acquire a semaphore permit for each target task.
5. Resolve the target hostname and sort unique socket addresses.
6. Attempt TCP connections within one stage deadline.
7. Issue one `HEAD` or `GET` request without reading the response body.
8. Keep only allowlisted response metadata and sanitize locations.
9. Restore original target order and render the selected report format.

## Failure semantics

DNS failure skips TCP and HTTP. TCP failure skips HTTP. An unexpected HTTP status fails only the HTTP stage. Other targets continue independently, and the final process returns `2` if any target is unhealthy.

Configuration and internal errors return `70` and do not produce a misleading health report.

## Determinism

Network timing and DNS answers naturally vary. PathLens makes the surrounding structure deterministic by sorting unique addresses, preserving configuration order and using stable field names under the `pathlens/v1` schema.
