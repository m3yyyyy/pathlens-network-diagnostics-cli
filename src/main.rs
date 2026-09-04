use std::process::ExitCode;

use pathlens::cli;

#[tokio::main]
async fn main() -> ExitCode {
    match cli::run().await {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::from(70)
        }
    }
}
