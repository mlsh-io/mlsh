use std::path::Path;
use std::process::Command;

fn main() {
    // Priority: GIT_VERSION env (from Docker build-arg) > git describe > Cargo version
    let version = std::env::var("GIT_VERSION")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| {
            Command::new("git")
                .args(["describe", "--tags", "--always", "--dirty=-dirty"])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_else(|| format!("v{}", env!("CARGO_PKG_VERSION")));
    println!("cargo:rustc-env=GIT_VERSION={version}");
    println!("cargo:rerun-if-changed=.git/HEAD");

    if std::env::var("CARGO_FEATURE_CONTROL_PLANE").is_ok() {
        build_ui();
    }
}

fn build_ui() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let ui_dir = Path::new(&manifest_dir).join("ui");

    println!("cargo:rerun-if-changed=ui/src");
    println!("cargo:rerun-if-changed=ui/index.html");
    println!("cargo:rerun-if-changed=ui/package.json");
    println!("cargo:rerun-if-changed=ui/package-lock.json");
    println!("cargo:rerun-if-changed=ui/vite.config.ts");
    println!("cargo:rerun-if-changed=ui/tsconfig.json");
    println!("cargo:rerun-if-changed=ui/tsconfig.app.json");
    println!("cargo:rerun-if-changed=ui/tsconfig.node.json");

    if !ui_dir.join("node_modules").exists() {
        run("npm", &["ci"], &ui_dir);
    }
    run("npm", &["run", "build"], &ui_dir);

    if !ui_dir.join("dist").join("index.html").exists() {
        panic!("ui/dist/index.html missing after `npm run build`");
    }
}

fn run(cmd: &str, args: &[&str], cwd: &Path) {
    let status = Command::new(cmd)
        .args(args)
        .current_dir(cwd)
        .status()
        .unwrap_or_else(|e| panic!("failed to spawn {cmd}: {e}"));
    if !status.success() {
        panic!("{cmd} {args:?} failed in {cwd:?}");
    }
}
