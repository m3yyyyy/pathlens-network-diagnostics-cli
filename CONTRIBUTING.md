# Contributing

1. Open an issue describing the change and its safety impact.
2. Create a focused branch from `main`.
3. Add tests that use local fixtures rather than public network services.
4. Run formatting, Clippy and all tests.
5. Open a pull request and wait for required checks.

```powershell
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

Changes that add credential handling, packet capture, port-range scanning, redirect following or disabled TLS verification require an explicit threat-model update and maintainer approval.
