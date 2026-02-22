use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process;

const FALLBACK_TEMPLATE: &str = include_str!("../../a3/templates/AI_INSTRUCTIONS.md");

const AI_FILES: &[&str] = &[
    "CLAUDE.md",
    ".cursorrules",
    "AGENTS.md",
    ".github/copilot-instructions.md",
    "GEMINI.md",
    ".windsurfrules",
];

/// Try to find the live AI_INSTRUCTIONS.md template from the a3 workspace.
/// Walks up from `start` looking for `a3/templates/AI_INSTRUCTIONS.md`.
/// Returns the file contents if found, otherwise None.
fn find_live_template(start: &Path) -> Option<String> {
    let mut dir = start.to_path_buf();
    loop {
        let candidate = dir.join("a3/templates/AI_INSTRUCTIONS.md");
        if candidate.is_file() {
            return fs::read_to_string(&candidate).ok();
        }
        if !dir.pop() {
            break;
        }
    }
    None
}

/// Get the best available template: live file if found, otherwise compiled-in fallback.
fn get_template() -> String {
    let cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    if let Some(live) = find_live_template(&cwd) {
        return live;
    }

    // Also try from the cargo-a3 binary's original source location (compile-time)
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    if let Some(live) = find_live_template(&manifest_dir) {
        return live;
    }

    FALLBACK_TEMPLATE.to_string()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // cargo passes "a3" as the first real arg, then the subcommand
    let cmd_args: Vec<&str> = args.iter().skip(1).map(|s| s.as_str()).collect();

    match cmd_args.as_slice() {
        ["a3", "init"] => run_init(),
        ["a3", "new", name] => run_new(name),
        _ => {
            eprintln!("Usage:");
            eprintln!("  cargo a3 init              Generate AI instruction files");
            eprintln!("  cargo a3 new <project>     Create a new a3 project");
            process::exit(1);
        }
    }
}

fn run_new(name: &str) {
    let root = Path::new(name);

    // Use basename for the package name (e.g., "/tmp/my-app" → "my-app")
    let pkg_name = root
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(name);

    if root.exists() {
        eprintln!("Error: directory '{}' already exists", name);
        process::exit(1);
    }

    fs::create_dir_all(root.join("src")).unwrap_or_else(|e| {
        eprintln!("Error creating directory: {}", e);
        process::exit(1);
    });

    // Cargo.toml
    let cargo_toml = format!(
        r#"[package]
name = "{pkg_name}"
version = "0.1.0"
edition = "2021"

[dependencies]
a3 = "0.1.0"
axum = "0.7"
serde = {{ version = "1", features = ["derive"] }}
tokio = {{ version = "1", features = ["full"] }}
"#
    );
    write_file(&root.join("Cargo.toml"), &cargo_toml);

    // src/main.rs
    let main_rs = format!(
        r#"use a3::prelude::*;

#[a3_endpoint(GET "/health")]
#[a3_security(none)]
#[a3_authorize(public)]
async fn health(_ctx: A3Context) -> A3Result<Json<HealthStatus>, Never> {{
    Ok(Json(HealthStatus::ok("0.1.0")))
}}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {{
    a3::init_tracing();
    let service = Service::builder()
        .name("{pkg_name}")
        .version("0.1.0")
        .endpoint(health())
        .build()?;
    a3::serve(service, "0.0.0.0:3000").await
}}
"#
    );
    write_file(&root.join("src/main.rs"), &main_rs);

    // .env.example
    write_file(
        &root.join(".env.example"),
        "\
# JWT
JWT_SECRET=change-me-in-production
# JWT_ALGORITHM=HS256
# JWT_PUBLIC_KEY=

# Database
# DATABASE_URL=sqlite:app.db

# Logging
RUST_LOG=info
",
    );

    // README.md
    let readme = format!(
        "\
# {pkg_name}

Built with a\u{b3} — AI Security Framework for Rust.

## Getting Started

```sh
cp .env.example .env
cargo run
```

The server starts at `http://localhost:3000`.

```sh
curl http://localhost:3000/health
```
"
    );
    write_file(&root.join("README.md"), &readme);

    // AI instruction files — use live template if available
    let template = get_template();
    for &file in AI_FILES {
        let path = root.join(file);
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent).unwrap_or_else(|e| {
                    eprintln!("Error creating directory: {}", e);
                    process::exit(1);
                });
            }
        }
        write_file(&path, &template);
    }

    println!("a\u{b3} project '{}' created:", pkg_name);
    println!();
    println!("  {}/", name);
    println!("  \u{251c}\u{2500}\u{2500} Cargo.toml");
    println!("  \u{251c}\u{2500}\u{2500} src/");
    println!("  \u{2502}   \u{2514}\u{2500}\u{2500} main.rs");
    println!("  \u{251c}\u{2500}\u{2500} .env.example");
    println!("  \u{251c}\u{2500}\u{2500} README.md");
    println!("  \u{251c}\u{2500}\u{2500} CLAUDE.md");
    println!("  \u{251c}\u{2500}\u{2500} .cursorrules");
    println!("  \u{251c}\u{2500}\u{2500} AGENTS.md");
    println!("  \u{251c}\u{2500}\u{2500} .github/");
    println!("  \u{2502}   \u{2514}\u{2500}\u{2500} copilot-instructions.md");
    println!("  \u{251c}\u{2500}\u{2500} GEMINI.md");
    println!("  \u{2514}\u{2500}\u{2500} .windsurfrules");
    println!();
    println!("  cd {} && cargo run", name);
}

fn run_init() {
    let template = get_template();
    let mut created = Vec::new();
    let mut skipped = Vec::new();

    for &file in AI_FILES {
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
                write_file(path, &template);
                created.push(file);
            } else {
                skipped.push(file);
            }
        } else {
            write_file(path, &template);
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
