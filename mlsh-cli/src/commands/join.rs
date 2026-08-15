//! `mlsh join <url>` — enroll via OIDC login instead of an invite.
//!
//! The join URL is non-secret: it only names the destination and pins
//! fingerprints. Proof of identity is the IdP login, done here with a
//! loopback redirect; the resulting id_token rides the normal Adopt path
//! as `pre_auth_token = "oidc:<id_token>"`.

use anyhow::{anyhow, Context, Result};
use base64::Engine;
use colored::Colorize;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::bootstrap::{self, BootstrapInput};
use crate::output;

const DEFAULT_SIGNAL_PORT: u16 = 443;
const DEFAULT_CALLBACK_PORT: u16 = 53682;

/// Payload carried in `mlsh://<host>/join/<b64url json>`.
#[derive(Serialize, Deserialize)]
pub struct JoinRef {
    pub cluster_name: String,
    pub cluster_id: String,
    pub signal_fingerprint: String,
    pub root_fingerprint: String,
    pub issuer: String,
    pub client_id: String,
}

pub async fn handle_join(url: &str, name_override: Option<&str>, port: Option<u16>) -> Result<()> {
    let (signal_host, jref) = parse_join_url(url)?;
    let port = port.unwrap_or(DEFAULT_CALLBACK_PORT);

    crate::step!("{}", "Joining cluster via OIDC...".cyan().bold());
    crate::step!("  Signal: {}", signal_host);
    crate::step!("  IdP:    {}", jref.issuer);

    let id_token = oidc_login(&jref, port).await?;

    let node_id = bootstrap::generate_node_id();
    let display_name = bootstrap::default_display_name(name_override);
    let signal_endpoint = bootstrap::ensure_port(&signal_host, DEFAULT_SIGNAL_PORT);

    let out = bootstrap::run(BootstrapInput {
        cluster_name: &jref.cluster_name,
        cluster_id: &jref.cluster_id,
        signal_endpoint: &signal_endpoint,
        signal_fingerprint: &jref.signal_fingerprint,
        root_fingerprint: &jref.root_fingerprint,
        node_id: &node_id,
        display_name: &display_name,
        pre_auth_token: &format!("oidc:{id_token}"),
        roles: &["node"],
    })
    .await?;

    output::emit(
        &serde_json::json!({
            "cluster": &jref.cluster_name,
            "overlay_ip": &out.overlay_ip,
            "identity_dir": out.identity_dir.display().to_string(),
        }),
        || {
            println!();
            println!("{}", "Cluster joined successfully!".green().bold());
            println!("  Cluster:  {}", jref.cluster_name);
            println!("  Overlay:  {}", out.overlay_ip);
            println!(
                "Connect with: {}",
                format!("mlsh connect {}", jref.cluster_name).bold()
            );
        },
    );
    Ok(())
}

fn parse_join_url(url: &str) -> Result<(String, JoinRef)> {
    let rest = url
        .strip_prefix("mlsh://")
        .or_else(|| url.strip_prefix("https://"))
        .context("Invalid URL scheme. Expected mlsh:// or https://")?;
    let (host, payload) = rest
        .split_once("/join/")
        .filter(|(h, p)| !h.is_empty() && !p.is_empty())
        .context("Invalid join URL format. Expected: mlsh://<host>/join/<payload>")?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .context("Invalid join payload encoding")?;
    let jref: JoinRef = serde_json::from_slice(&bytes).context("Invalid join payload")?;
    Ok((host.to_string(), jref))
}

#[derive(Deserialize)]
struct Discovery {
    authorization_endpoint: String,
    token_endpoint: String,
}

/// Loopback Authorization Code + PKCE against the IdP (public client).
async fn oidc_login(jref: &JoinRef, port: u16) -> Result<String> {
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?;
    let d: Discovery = http
        .get(format!(
            "{}/.well-known/openid-configuration",
            jref.issuer.trim_end_matches('/')
        ))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await
        .context("IdP discovery failed")?;

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .with_context(|| format!("bind 127.0.0.1:{port} (is another join running?)"))?;
    let redirect_uri = format!("http://127.0.0.1:{port}/callback");

    let (verifier, challenge) = mlsh_crypto::pkce::pair();
    let state = mlsh_crypto::pkce::random_urlsafe();
    let sep = if d.authorization_endpoint.contains('?') {
        '&'
    } else {
        '?'
    };
    let auth_url = format!(
        "{}{}response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method=S256",
        d.authorization_endpoint,
        sep,
        urlenc(&jref.client_id),
        urlenc(&redirect_uri),
        urlenc("openid profile email"),
        state,
        challenge,
    );

    crate::step!("Opening your browser to sign in...");
    crate::step!("  {}", auth_url.dimmed());
    open_in_browser(&auth_url);

    let code = wait_for_code(&listener, &state).await?;

    let body = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&code_verifier={}",
        urlenc(&code),
        urlenc(&redirect_uri),
        urlenc(&jref.client_id),
        verifier,
    );
    #[derive(Deserialize)]
    struct TokenResponse {
        id_token: String,
    }
    let tok: TokenResponse = http
        .post(&d.token_endpoint)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await?
        .error_for_status()
        .context("token exchange rejected")?
        .json()
        .await?;
    Ok(tok.id_token)
}

/// Accept loopback connections until the IdP redirect with the right state
/// arrives; 10 minute budget for the human to authenticate.
async fn wait_for_code(listener: &tokio::net::TcpListener, state: &str) -> Result<String> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(600);
    loop {
        let remaining = deadline
            .checked_duration_since(std::time::Instant::now())
            .ok_or_else(|| anyhow!("timed out waiting for the browser login"))?;
        let (mut sock, _) = tokio::time::timeout(remaining, listener.accept())
            .await
            .map_err(|_| anyhow!("timed out waiting for the browser login"))??;
        let mut buf = [0u8; 4096];
        let n = sock.read(&mut buf).await.unwrap_or(0);
        let req = String::from_utf8_lossy(&buf[..n]);
        let query = req
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|p| p.split_once('?'))
            .map(|(_, q)| q.to_string())
            .unwrap_or_default();
        let get = |k: &str| {
            query.split('&').find_map(|kv| {
                kv.split_once('=')
                    .filter(|(key, _)| *key == k)
                    .map(|(_, v)| urldec(v))
            })
        };
        let ok = get("state").as_deref() == Some(state) && get("code").is_some();
        let page = if ok {
            "Signed in. You can close this tab and return to the terminal."
        } else {
            "Unexpected callback; check the terminal."
        };
        let _ = sock
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: text/html\r\nconnection: close\r\n\r\n<html><body><p>{page}</p></body></html>"
                )
                .as_bytes(),
            )
            .await;
        if ok {
            return Ok(get("code").unwrap());
        }
    }
}

fn urlenc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn urldec(s: &str) -> String {
    let mut out = Vec::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    out.push(v);
                    i += 3;
                    continue;
                }
                out.push(b'%');
                i += 1;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn open_in_browser(url: &str) {
    let result = if cfg!(target_os = "macos") {
        std::process::Command::new("open").arg(url).status()
    } else if cfg!(target_os = "windows") {
        std::process::Command::new("cmd")
            .args(["/C", "start", "", url])
            .status()
    } else {
        std::process::Command::new("xdg-open").arg(url).status()
    };
    if result.is_err() {
        crate::step!("Could not open a browser; open the URL above manually.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_url_round_trip() {
        let jref = JoinRef {
            cluster_name: "homelab".into(),
            cluster_id: "c1".into(),
            signal_fingerprint: "fp-sig".into(),
            root_fingerprint: "fp-root".into(),
            issuer: "https://id.example".into(),
            client_id: "mlsh".into(),
        };
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&jref).unwrap());
        let (host, parsed) =
            parse_join_url(&format!("mlsh://signal.example.com/join/{payload}")).unwrap();
        assert_eq!(host, "signal.example.com");
        assert_eq!(parsed.cluster_id, "c1");
        assert_eq!(parsed.issuer, "https://id.example");
    }

    #[test]
    fn join_url_invalid() {
        assert!(parse_join_url("mlsh://host/join/").is_err());
        assert!(parse_join_url("mlsh://host/adopt/abc").is_err());
        assert!(parse_join_url("mlsh://host/join/not-base64!!").is_err());
    }

    #[test]
    fn urlenc_dec_round_trip() {
        let s = "a b:c/d?e=f&g";
        assert_eq!(urldec(&urlenc(s)), s);
    }
}
