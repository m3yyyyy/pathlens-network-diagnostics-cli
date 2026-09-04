use std::{path::Path, process::Command};

fn pathlens() -> Command {
    Command::new(env!("CARGO_BIN_EXE_pathlens"))
}

#[test]
fn version_command_reports_package_version() {
    let output = pathlens().arg("version").output().expect("run pathlens");
    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "pathlens 0.1.0\n");
}

#[test]
fn validate_command_makes_no_network_request() {
    let config = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("examples")
        .join("pathlens.yml");
    let output = pathlens()
        .arg("validate")
        .arg("--config")
        .arg(config)
        .output()
        .expect("run pathlens");
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("valid: 2 target(s)"));
}

#[test]
fn rejects_credential_url_without_echoing_secret() {
    let output = pathlens()
        .args([
            "check",
            "--target",
            "https://operator:top-secret@example.com/health",
        ])
        .output()
        .expect("run pathlens");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(70));
    assert!(stderr.contains("credentials in URLs are not allowed"));
    assert!(!stderr.contains("top-secret"));
}
