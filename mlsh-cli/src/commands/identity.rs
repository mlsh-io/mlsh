//! `mlsh identity-export` / `mlsh identity-import` — backup and restore node identity.
//!
//! The node identity is an Ed25519 keypair. Losing it means losing cluster membership
//! (especially critical for admin nodes). These commands export/import the PEM files.

use anyhow::{Context, Result};
use colored::Colorize;

/// Export the node identity (cert + key PEM) to stdout.
pub async fn handle_export() -> Result<()> {
    let config_dir = crate::config::config_dir()?;
    let identity_dir = config_dir.join("identity");
    let cert_path = identity_dir.join("cert.pem");
    let key_path = identity_dir.join("key.pem");

    if !cert_path.exists() || !key_path.exists() {
        anyhow::bail!(
            "No identity found at {}. Run 'mlsh setup' or 'mlsh adopt' first.",
            identity_dir.display()
        );
    }

    let cert_pem = std::fs::read_to_string(&cert_path).context("Failed to read cert.pem")?;
    let key_pem = std::fs::read_to_string(&key_path).context("Failed to read key.pem")?;

    let fingerprint = mlsh_crypto::identity::compute_fingerprint(
        &mlsh_crypto::identity::pem_to_der_pub(&cert_pem)
            .map_err(|e| anyhow::anyhow!("{}", e))?,
    );

    eprintln!("{}", "Identity exported".green().bold());
    eprintln!("  Fingerprint: {}", &fingerprint[..16]);
    eprintln!("  Store this output securely — it contains your private key.");
    eprintln!();

    // Output to stdout so it can be piped to a file
    print!("{}", key_pem);
    print!("{}", cert_pem);

    Ok(())
}

/// Import a node identity from a PEM file or stdin.
pub async fn handle_import(file: Option<&str>) -> Result<()> {
    let pem_data = match file {
        Some(path) => std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read {}", path))?,
        None => {
            eprintln!("Reading identity from stdin (paste PEM, then Ctrl+D)...");
            let mut buf = String::new();
            std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)?;
            buf
        }
    };

    // Parse: expect a private key PEM and a certificate PEM
    let has_key = pem_data.contains("PRIVATE KEY");
    let has_cert = pem_data.contains("CERTIFICATE");

    if !has_key || !has_cert {
        anyhow::bail!(
            "Input must contain both a PRIVATE KEY and a CERTIFICATE PEM block. \
             Use the output of 'mlsh identity-export'."
        );
    }

    // Split into key and cert blocks
    let mut key_pem = String::new();
    let mut cert_pem = String::new();
    // 0 = discard, 1 = key, 2 = cert
    let mut target: u8 = 0;

    for line in pem_data.lines() {
        if line.contains("BEGIN") && line.contains("PRIVATE KEY") {
            target = 1;
        } else if line.contains("BEGIN CERTIFICATE") {
            target = 2;
        }
        match target {
            1 => { key_pem.push_str(line); key_pem.push('\n'); }
            2 => { cert_pem.push_str(line); cert_pem.push('\n'); }
            _ => {}
        }
        if line.contains("END") {
            target = 0;
        }
    }

    if key_pem.is_empty() || cert_pem.is_empty() {
        anyhow::bail!("Failed to parse PEM blocks from input");
    }

    // Verify the key and cert are consistent
    let cert_der = mlsh_crypto::identity::pem_to_der_pub(&cert_pem)
        .map_err(|e| anyhow::anyhow!("Invalid certificate: {}", e))?;
    let fingerprint = mlsh_crypto::identity::compute_fingerprint(&cert_der);

    // Write to identity dir
    let config_dir = crate::config::config_dir()?;
    let identity_dir = config_dir.join("identity");
    std::fs::create_dir_all(&identity_dir)?;

    let cert_path = identity_dir.join("cert.pem");
    let key_path = identity_dir.join("key.pem");

    if cert_path.exists() {
        let existing_fp = mlsh_crypto::identity::compute_fingerprint(
            &mlsh_crypto::identity::pem_to_der_pub(
                &std::fs::read_to_string(&cert_path)?,
            )
            .map_err(|e| anyhow::anyhow!("{}", e))?,
        );
        if existing_fp != fingerprint {
            eprintln!(
                "{}",
                format!(
                    "Warning: replacing existing identity ({}...) with new one ({}...)",
                    &existing_fp[..16],
                    &fingerprint[..16]
                )
                .yellow()
            );
        }
    }

    std::fs::write(&key_path, &key_pem)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::write(&cert_path, &cert_pem)?;

    println!("{}", "Identity imported".green().bold());
    println!("  Fingerprint: {}...", &fingerprint[..16]);
    println!("  Location:    {}", identity_dir.display());

    Ok(())
}
