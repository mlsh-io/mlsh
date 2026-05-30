//! Global output mode for the `mlsh` CLI.
//!
//! The CLI normally prints colorized human text. When the global `--json`
//! flag is passed, every command instead emits a single JSON document to
//! stdout so the output can be consumed programmatically (e.g. by GUI tools).
//!
//! The mode is process-global — like `colored`'s color state — so it can be
//! read from deep helpers and from `main()` (for error formatting) without
//! threading a `json: bool` through every handler signature.
//!
//! JSON envelope:
//! - success: `{"ok":true,"data":<value>}`
//! - failure: `{"ok":false,"error":"<message>"}`
//!
//! Documents are compact (one line per invocation) to ease line-oriented
//! parsing and piping.

use std::sync::atomic::{AtomicBool, Ordering};

use serde::Serialize;

static JSON_MODE: AtomicBool = AtomicBool::new(false);

/// Set the output mode. Call once at startup, right after `Cli::parse()`.
pub fn init(json: bool) {
    JSON_MODE.store(json, Ordering::Relaxed);
}

/// True when `--json` was passed.
pub fn is_json() -> bool {
    JSON_MODE.load(Ordering::Relaxed)
}

/// Emit the final result of a command.
/// - JSON mode: serialize `value` into the success envelope and print one
///   line to stdout. `human` is NOT run.
/// - Human mode: run `human`, which performs the existing colored output
///   (unchanged).
pub fn emit<T: Serialize>(value: &T, human: impl FnOnce()) {
    if is_json() {
        match serde_json::to_value(value) {
            Ok(data) => {
                let doc = serde_json::json!({ "ok": true, "data": data });
                println!("{doc}");
            }
            Err(e) => println!("{}", error_doc(&format!("serialize result: {e}"))),
        }
    } else {
        human();
    }
}

/// Build the failure envelope: `{"ok":false,"error":"..."}`.
pub fn error_doc(msg: &str) -> String {
    serde_json::json!({ "ok": false, "error": msg }).to_string()
}

/// Progress / header / hint line — use exactly like `println!`.
///
/// - JSON mode: written to stderr, so it never corrupts the single JSON
///   document on stdout.
/// - Human mode: written to stdout (unchanged behavior).
#[macro_export]
macro_rules! step {
    ($($arg:tt)*) => {{
        if $crate::output::is_json() {
            eprintln!($($arg)*);
        } else {
            println!($($arg)*);
        }
    }};
}
