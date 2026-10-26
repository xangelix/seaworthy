//! `seaworthy-lab`: the lab lanes' server, CA and helpers
//! (`seaworthy_lab::cli`; the crate's `README.md` documents the interface).

fn main() -> std::process::ExitCode {
    seaworthy_lab::cli::main(std::env::args_os().skip(1))
}
