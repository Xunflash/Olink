//! Trust store — persisted pairings.
//!
//! The Windows app establishes the session key (KSC) once during the BLE UKey2
//! handshake, then **saves it** (`keyMgrSaveKsc`) together with the peer's device
//! id (`keyMgrSavePeerDeviceId` → a `PeerDeviceId` table). That persistence is
//! exactly why first pairing shows the "Allow this device?" prompt and every
//! reconnect afterwards is silent: the Wi-Fi `authentication` layer re-proves the
//! stored key instead of re-running UKey2.
//!
//! This module is that store. A [`TrustRecord`] is what pairing produces and what
//! [`crate::session`] consumes to resume silently.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

/// One remembered peer: the key material + identity needed to reconnect without
/// a prompt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustRecord {
    /// Peer device id (hex, e.g. `A1B2C3D4E5F6`). The key of the store.
    pub peer_id: String,
    /// Human-readable name last seen.
    pub name: String,
    /// The persisted session credential (KSC) — the SecureMessage D2D key
    /// material derived by UKey2. Treated as a secret; see the on-disk note.
    pub ksc: Vec<u8>,
    /// When this pairing was established (unix seconds).
    pub paired_at: u64,
}

/// Abstract store so the backend (file now, OS keyring later) is swappable.
#[allow(async_fn_in_trait)]
pub trait TrustStore: Send + Sync {
    async fn get(&self, peer_id: &str) -> anyhow::Result<Option<TrustRecord>>;
    async fn put(&self, record: TrustRecord) -> anyhow::Result<()>;
    async fn forget(&self, peer_id: &str) -> anyhow::Result<()>;
    async fn list(&self) -> anyhow::Result<Vec<TrustRecord>>;
}

/// A simple JSON-file-backed store under the app's data dir.
///
/// NOTE: KSC is secret. For a shipping build back this with the OS secret
/// service (`libsecret`/`org.freedesktop.secrets`) and keep only metadata in the
/// JSON. The trait boundary means that swap touches no other module.
pub struct FileTrustStore {
    path: PathBuf,
    cache: Arc<RwLock<HashMap<String, TrustRecord>>>,
}

impl FileTrustStore {
    /// Open (or create) the store at `path`, loading any existing records.
    pub async fn open(path: PathBuf) -> anyhow::Result<Self> {
        let cache = match tokio::fs::read(&path).await {
            Ok(bytes) => serde_json::from_slice::<Vec<TrustRecord>>(&bytes)
                .unwrap_or_default()
                .into_iter()
                .map(|r| (r.peer_id.clone(), r))
                .collect(),
            Err(_) => HashMap::new(),
        };
        Ok(Self {
            path,
            cache: Arc::new(RwLock::new(cache)),
        })
    }

    async fn flush(&self, guard: &HashMap<String, TrustRecord>) -> anyhow::Result<()> {
        let all: Vec<&TrustRecord> = guard.values().collect();
        let bytes = serde_json::to_vec_pretty(&all)?;
        if let Some(dir) = self.path.parent() {
            tokio::fs::create_dir_all(dir).await.ok();
        }
        tokio::fs::write(&self.path, bytes).await?;
        Ok(())
    }
}

impl TrustStore for FileTrustStore {
    async fn get(&self, peer_id: &str) -> anyhow::Result<Option<TrustRecord>> {
        Ok(self.cache.read().await.get(peer_id).cloned())
    }

    async fn put(&self, record: TrustRecord) -> anyhow::Result<()> {
        let mut guard = self.cache.write().await;
        guard.insert(record.peer_id.clone(), record);
        self.flush(&guard).await
    }

    async fn forget(&self, peer_id: &str) -> anyhow::Result<()> {
        let mut guard = self.cache.write().await;
        guard.remove(peer_id);
        self.flush(&guard).await
    }

    async fn list(&self) -> anyhow::Result<Vec<TrustRecord>> {
        Ok(self.cache.read().await.values().cloned().collect())
    }
}
