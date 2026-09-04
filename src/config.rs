use std::{collections::HashSet, fs, path::Path};

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use url::Url;

const MAX_TARGETS: usize = 64;
const MAX_URL_LENGTH: usize = 2_048;
const MIN_TIMEOUT_MS: u64 = 100;
const MAX_TIMEOUT_MS: u64 = 60_000;
const MAX_CONCURRENCY: usize = 32;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigFile {
    #[serde(default = "default_schema_version")]
    pub version: u8,
    #[serde(default)]
    pub defaults: Defaults,
    pub targets: Vec<TargetInput>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Defaults {
    pub timeout_ms: u64,
    pub concurrency: usize,
    pub method: String,
    pub expect_status: Vec<u16>,
}

impl Default for Defaults {
    fn default() -> Self {
        Self {
            timeout_ms: 5_000,
            concurrency: 8,
            method: "HEAD".to_owned(),
            expect_status: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetInput {
    pub name: String,
    pub url: String,
    pub timeout_ms: Option<u64>,
    pub method: Option<String>,
    #[serde(default)]
    pub expect_status: Vec<u16>,
}

#[derive(Debug, Clone)]
pub struct ResolvedConfig {
    pub concurrency: usize,
    pub targets: Vec<ResolvedTarget>,
}

#[derive(Debug, Clone)]
pub struct ResolvedTarget {
    pub name: String,
    pub url: Url,
    pub timeout_ms: u64,
    pub method: String,
    pub expect_status: Vec<u16>,
}

impl ResolvedTarget {
    pub fn accepts_status(&self, status: u16) -> bool {
        if self.expect_status.is_empty() {
            (200..400).contains(&status)
        } else {
            self.expect_status.contains(&status)
        }
    }
}

impl ConfigFile {
    /// Loads a strict versioned YAML configuration.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be read or parsed.
    pub fn load(path: &Path) -> Result<Self> {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("could not read config {}", path.display()))?;
        serde_yaml_ng::from_str(&contents)
            .with_context(|| format!("could not parse config {}", path.display()))
    }

    /// Validates limits and converts input values into probe-ready targets.
    ///
    /// # Errors
    ///
    /// Returns an error when any setting or target violates the configuration contract.
    pub fn resolve(self) -> Result<ResolvedConfig> {
        if self.version != 1 {
            bail!("unsupported config version {}; expected 1", self.version);
        }
        validate_concurrency(self.defaults.concurrency)?;
        if self.targets.is_empty() {
            bail!("config must contain at least one target");
        }
        if self.targets.len() > MAX_TARGETS {
            bail!("config contains more than {MAX_TARGETS} targets");
        }

        let default_method = normalize_method(&self.defaults.method)?;
        validate_statuses(&self.defaults.expect_status)?;
        let mut names = HashSet::new();
        let mut targets = Vec::with_capacity(self.targets.len());

        for input in self.targets {
            validate_name(&input.name)?;
            if !names.insert(input.name.clone()) {
                bail!("duplicate target name {:?}", input.name);
            }
            let timeout_ms = input.timeout_ms.unwrap_or(self.defaults.timeout_ms);
            validate_timeout(timeout_ms, &input.name)?;
            let method = match input.method {
                Some(method) => normalize_method(&method)?,
                None => default_method.clone(),
            };
            let expect_status = if input.expect_status.is_empty() {
                self.defaults.expect_status.clone()
            } else {
                input.expect_status
            };
            validate_statuses(&expect_status)?;
            let url = parse_safe_url(&input.url)
                .with_context(|| format!("invalid target {:?}", input.name))?;

            targets.push(ResolvedTarget {
                name: input.name,
                url,
                timeout_ms,
                method,
                expect_status,
            });
        }

        Ok(ResolvedConfig {
            concurrency: self.defaults.concurrency,
            targets,
        })
    }
}

/// Converts explicit CLI targets into the same validated representation as YAML input.
///
/// # Errors
///
/// Returns an error when a target URL or command-line setting is invalid.
pub fn from_cli_targets(
    urls: Vec<String>,
    timeout_ms: u64,
    concurrency: usize,
    method: String,
    expect_status: Vec<u16>,
) -> Result<ResolvedConfig> {
    let targets = urls
        .into_iter()
        .enumerate()
        .map(|(index, value)| {
            let parsed = parse_safe_url(&value)?;
            let host = parsed.host_str().unwrap_or("target");
            Ok(TargetInput {
                name: format!("{}-{}", host, index + 1),
                url: value,
                timeout_ms: Some(timeout_ms),
                method: Some(method.clone()),
                expect_status: Vec::new(),
            })
        })
        .collect::<Result<Vec<_>>>()?;

    ConfigFile {
        version: 1,
        defaults: Defaults {
            timeout_ms,
            concurrency,
            method,
            expect_status,
        },
        targets,
    }
    .resolve()
}

fn default_schema_version() -> u8 {
    1
}

fn validate_name(name: &str) -> Result<()> {
    if name.trim().is_empty() {
        bail!("target name cannot be empty");
    }
    if name.len() > 64 {
        bail!("target name {name:?} exceeds 64 characters");
    }
    if name.chars().any(char::is_control) {
        bail!("target name {name:?} contains control characters");
    }
    Ok(())
}

fn validate_concurrency(concurrency: usize) -> Result<()> {
    if !(1..=MAX_CONCURRENCY).contains(&concurrency) {
        bail!("concurrency must be between 1 and {MAX_CONCURRENCY}");
    }
    Ok(())
}

fn validate_timeout(timeout_ms: u64, name: &str) -> Result<()> {
    if !(MIN_TIMEOUT_MS..=MAX_TIMEOUT_MS).contains(&timeout_ms) {
        bail!("target {name:?} timeout must be between {MIN_TIMEOUT_MS} and {MAX_TIMEOUT_MS} ms");
    }
    Ok(())
}

fn normalize_method(method: &str) -> Result<String> {
    let method = method.trim().to_ascii_uppercase();
    if !matches!(method.as_str(), "HEAD" | "GET") {
        bail!("method must be HEAD or GET, not {method:?}");
    }
    Ok(method)
}

fn validate_statuses(statuses: &[u16]) -> Result<()> {
    if let Some(status) = statuses
        .iter()
        .find(|status| !(100..=599).contains(*status))
    {
        bail!("expected HTTP status {status} is outside 100..=599");
    }
    Ok(())
}

fn parse_safe_url(value: &str) -> Result<Url> {
    if value.len() > MAX_URL_LENGTH {
        bail!("URL exceeds {MAX_URL_LENGTH} characters");
    }
    let url = Url::parse(value).context("URL is not valid")?;
    if !matches!(url.scheme(), "http" | "https") {
        bail!("URL scheme must be http or https");
    }
    if url.host_str().is_none() {
        bail!("URL must include a hostname");
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("credentials in URLs are not allowed");
    }
    if url.fragment().is_some() {
        bail!("URL fragments are not allowed");
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::{ConfigFile, from_cli_targets};

    #[test]
    fn applies_safe_defaults() {
        let config: ConfigFile = serde_yaml_ng::from_str(
            r"
version: 1
targets:
  - name: example
    url: https://example.com/health
",
        )
        .expect("valid YAML");
        let resolved = config.resolve().expect("valid config");
        assert_eq!(resolved.concurrency, 8);
        assert_eq!(resolved.targets[0].method, "HEAD");
        assert!(resolved.targets[0].accepts_status(204));
        assert!(!resolved.targets[0].accepts_status(500));
    }

    #[test]
    fn rejects_credentials_in_urls() {
        let error = from_cli_targets(
            vec!["https://user:secret@example.com".to_owned()],
            1_000,
            1,
            "GET".to_owned(),
            Vec::new(),
        )
        .expect_err("credentials must be rejected");
        assert!(error.to_string().contains("credentials"));
    }

    #[test]
    fn rejects_unknown_fields() {
        let error = serde_yaml_ng::from_str::<ConfigFile>(
            r"
version: 1
targets: []
surprise: true
",
        )
        .expect_err("unknown fields must be rejected");
        assert!(error.to_string().contains("unknown field"));
    }
}
