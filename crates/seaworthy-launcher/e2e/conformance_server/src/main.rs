//! The conformance lanes' server: the lab server (`seaworthy_lab::server`)
//! on loopback inside each host, `seaworthy-lab serve`'s options without
//! the subcommand:
//!
//! ```text
//! conformance_server --root DIR (--token TOKEN | --token-file FILE) [--listen ADDR]...
//!                    [--ready FILE] [--hold FILE [--held FILE]] [--tls-cert PEM --tls-key PEM]
//! ```
//!
//! It serves the release tree and the repositories under `DIR` and the
//! required-version endpoint the fixture's helper asks (by default on
//! `127.0.0.1:8470`). The lanes restart it to name another token, or give
//! it a token file.

fn main() -> std::process::ExitCode {
    seaworthy_lab::cli::serve_main(std::env::args_os().skip(1))
}
