use mlsh_cli::control::api::ApiDoc;
use utoipa::OpenApi;

fn main() {
    let spec = ApiDoc::openapi();
    let mut value = serde_json::to_value(&spec).expect("Failed to serialize OpenAPI spec");

    // Pin the spec to OpenAPI 3.0.3 — utoipa 5 emits 3.1.0 by default but
    // progenitor 0.13 only accepts 3.0.x. We then rewrite the few 3.1-only
    // constructs utoipa actually uses (`type: [X, "null"]`) into their 3.0
    // equivalents (`type: X, nullable: true`).
    if let Some(obj) = value.as_object_mut() {
        obj.insert(
            "openapi".to_string(),
            serde_json::Value::String("3.0.3".to_string()),
        );
    }
    downgrade_nullable_types(&mut value);

    println!(
        "{}",
        serde_json::to_string_pretty(&value).expect("Failed to serialize OpenAPI spec")
    );
}

/// Walk the JSON tree and rewrite `{ "type": [T, "null"] }` (OpenAPI 3.1) as
/// `{ "type": T, "nullable": true }` (OpenAPI 3.0). All other shapes are
/// left untouched.
fn downgrade_nullable_types(v: &mut serde_json::Value) {
    match v {
        serde_json::Value::Object(map) => {
            if let Some(serde_json::Value::Array(arr)) = map.get("type").cloned() {
                let mut non_null = Vec::new();
                let mut had_null = false;
                for item in arr {
                    match &item {
                        serde_json::Value::String(s) if s == "null" => had_null = true,
                        _ => non_null.push(item),
                    }
                }
                if had_null && non_null.len() == 1 {
                    map.insert("type".to_string(), non_null.into_iter().next().unwrap());
                    map.insert("nullable".to_string(), serde_json::Value::Bool(true));
                }
            }
            for child in map.values_mut() {
                downgrade_nullable_types(child);
            }
        }
        serde_json::Value::Array(arr) => {
            for child in arr.iter_mut() {
                downgrade_nullable_types(child);
            }
        }
        _ => {}
    }
}
