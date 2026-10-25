//! Prints the records a built launcher or core carries:
//! `inspect cpulist <launcher>` / `inspect cpureq <core>`.

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let (Some(kind), Some(path)) = (args.get(1), args.get(2)) else {
        eprintln!("usage: inspect cpulist|cpureq <file>");
        return std::process::ExitCode::from(2);
    };
    let path = std::path::Path::new(path);
    let result = match kind.as_str() {
        "cpulist" => seaworthy_levels::read_cpu_list(path).map(|list| list.render()),
        "cpureq" => seaworthy_levels::read_requirement(path).map(|record| record.render()),
        _ => {
            eprintln!("usage: inspect cpulist|cpureq <file>");
            return std::process::ExitCode::from(2);
        }
    };
    match result {
        Ok(text) => {
            print!("{text}");
            std::process::ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{}: {e}", path.display());
            std::process::ExitCode::FAILURE
        }
    }
}
