use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum Resource {
    Vm {
        name: String,
        pid: u32,
        run_dir: PathBuf,
    },
    Bridge {
        name: String,
    },
    Tap {
        name: String,
        bridge: String,
    },
    NftTable {
        family: String,
        name: String,
    },
}

pub struct Manifest {
    path: PathBuf,
    file: Mutex<File>,
}

impl Manifest {
    pub async fn create(path: PathBuf) -> Result<Self> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .with_context(|| format!("create manifest dir {}", parent.display()))?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await
            .with_context(|| format!("open manifest {}", path.display()))?;
        Ok(Self {
            path,
            file: Mutex::new(file),
        })
    }

    pub async fn record(&self, resource: &Resource) -> Result<()> {
        let mut line = serde_json::to_vec(resource).context("serialize resource")?;
        line.push(b'\n');
        let mut f = self.file.lock().await;
        f.write_all(&line).await.context("append manifest")?;
        f.flush().await.ok();
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

pub async fn read_all(path: &Path) -> Result<Vec<Resource>> {
    let f = File::open(path)
        .await
        .with_context(|| format!("open manifest {}", path.display()))?;
    let mut reader = BufReader::new(f);
    let mut out = Vec::new();
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let r: Resource = serde_json::from_str(trimmed)
            .with_context(|| format!("parse manifest line: {trimmed}"))?;
        out.push(r);
    }
    Ok(out)
}
