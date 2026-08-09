use std::process::ExitCode;

fn usage() -> ! {
    eprintln!("usage: tailfeather-testkit <check|list> [--json] [--expect PATH]");
    std::process::exit(2)
}

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let command = args.next().unwrap_or_else(|| usage());
    let mut json = false;
    let mut expect = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--json" => json = true,
            "--expect" => expect = Some(args.next().unwrap_or_else(|| usage())),
            _ => usage(),
        }
    }

    if command == "list" {
        if json {
            println!(
                "{}",
                serde_json::to_string(
                    &tailfeather_testkit::vectors::ALL
                        .iter()
                        .map(|v| v.name)
                        .collect::<Vec<_>>()
                )
                .unwrap()
            );
        } else {
            for vector in tailfeather_testkit::vectors::ALL {
                println!("{}", vector.name);
            }
        }
        return ExitCode::SUCCESS;
    }
    if command != "check" {
        usage();
    }

    let report = tailfeather_testkit::replay::check_all();
    let rendered = serde_json::to_string_pretty(&report).unwrap();
    if let Some(path) = expect {
        match std::fs::read_to_string(&path) {
            Ok(expected) if expected.trim() == rendered.trim() => {}
            Ok(_) => {
                eprintln!("report differs from {path}");
                return ExitCode::FAILURE;
            }
            Err(error) => {
                eprintln!("{path}: {error}");
                return ExitCode::FAILURE;
            }
        }
    }
    if json {
        println!("{rendered}");
    } else {
        for check in &report.checks {
            println!("{:?} {} ({})", check.status, check.name, check.detail);
        }
    }
    if report.passed() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
