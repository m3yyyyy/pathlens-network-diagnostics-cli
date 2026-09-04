# Threat model

## Assets

- credentials and sensitive query values used by operators;
- internal hostnames and addresses present in diagnostic reports;
- availability of the workstation and target services;
- integrity of reports consumed by CI or incident workflows.

## Trust boundary

The operator and configuration file are trusted to choose authorized targets. Remote DNS servers and HTTP endpoints are untrusted. Reports should be treated as operationally sensitive because they can disclose topology even after credential redaction.

## Controls

- only explicit `http` and `https` URLs are accepted;
- usernames and passwords embedded in URLs are rejected;
- fragments and unknown configuration keys are rejected;
- redirects are never followed;
- environment proxy variables are ignored for direct-path diagnostics;
- TLS certificate verification cannot be disabled;
- response bodies are not read or stored;
- only `HEAD` and `GET` are available;
- target count, concurrency, URL length and timeout are bounded;
- query values and redirect-location queries are redacted;
- downstream stages are skipped when prerequisites fail;
- unsafe Rust is forbidden at the crate level.

## Residual risks

- DNS rebinding can make a hostname resolve differently between the explicit DNS stage and the HTTP client's connection.
- A `GET` endpoint can have side effects despite HTTP semantics; prefer `HEAD` unless the service requires `GET`.
- An authorized internal target may expose topology through addresses or server headers in the report.
- A compromised local configuration can direct probes toward sensitive local or link-local services.
- A clean health result proves reachability and expected status at one moment, not application correctness or security.

Use trusted configuration, review reports before sharing and run PathLens with ordinary user privileges.
