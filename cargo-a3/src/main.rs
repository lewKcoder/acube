use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::process;

const TEMPLATE: &str = include_str!("../../a3/templates/AI_INSTRUCTIONS.md");

const FILES: &[&str] = &[
    "CLAUDE.md",
    ".cursorrules",
    "AGENTS.md",
    ".github/copilot-instructions.md",
    "GEMINI.md",
    ".windsurfrules",
];

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // cargo passes "a3" as the first real arg, then "init"
    let cmd_args: Vec<&str> = args.iter().skip(1).map(|s| s.as_str()).collect();

    match cmd_args.as_slice() {
        ["a3", "init"] => run_init(),
        _ => {
            eprintln!("Usage: cargo a3 init");
            process::exit(1);
        }
    }
}

fn run_init() {
    let mut created = Vec::new();
    let mut skipped = Vec::new();

    for &file in FILES {
        let path = Path::new(file);

        // Create parent directory if needed
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                fs::create_dir_all(parent).unwrap_or_else(|e| {
                    eprintln!("Error creating directory {}: {}", parent.display(), e);
                    process::exit(1);
                });
            }
        }

        if path.exists() {
            eprint!("  Overwrite {}? [y/N] ", file);
            io::stderr().flush().unwrap();

            let mut answer = String::new();
            io::stdin().read_line(&mut answer).unwrap_or(0);

            if answer.trim().eq_ignore_ascii_case("y") {
                write_file(path, TEMPLATE);
                created.push(file);
            } else {
                skipped.push(file);
            }
        } else {
            write_file(path, TEMPLATE);
            created.push(file);
        }
    }

    println!();
    println!("a\u{b3} AI instructions generated:");
    for file in &created {
        println!("  Created {}", file);
    }
    for file in &skipped {
        println!("  Skipped {}", file);
    }
}

fn write_file(path: &Path, content: &str) {
    fs::write(path, content).unwrap_or_else(|e| {
        eprintln!("Error writing {}: {}", path.display(), e);
        process::exit(1);
    });
}
