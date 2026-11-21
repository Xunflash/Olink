//! Orchestration — the piece that makes "connect directly, no helper app" real.
//!
//! [`ConnectionManager`] owns the lifecycle and sequences the layers so the phone
//! can talk to us exactly as it talks to a Windows PC:
//!
//! ```text
//!   advertise (ble 0xAA16 + discovery)
//!        │  phone connects over BLE
//!        ▼
//!   known peer?  ──no──▶  pair: ukey2::run_server over the BLE transport,
//!        │                      gated by the Allow dialog → D2DContext
//!        │                      → trust.put(record)
//!        └─yes─▶  (skip UKey2)
//!        ▼
//!   session: resume from the trust record (Wi-Fi re-proof) → Session
//!        ▼
//!   protocol: run the transfer over the authenticated channel
//! ```
//!
//! Every arrow crosses a trait seam (`MessageTransport`, `TrustStore`,
//! `ConfirmPrompt`, `Discovery`), so each layer is swappable and testable on its
//! own, and the manager's logic can be exercised with in-memory fakes.

pub mod lifecycle;

use std::sync::Arc;

use tokio::sync::{watch, RwLock};

use crate::ble::{Advertisement, BlePeripheral};
use crate::pairing::ukey2::{self, ConfirmPrompt};
use crate::session::Session;
use crate::trust::TrustStore;

pub use lifecycle::Lifecycle;

/// Ties the layers together and exposes the current [`Lifecycle`] to the UI.
pub struct ConnectionManager<S: TrustStore, C: ConfirmPrompt> {
    advert: Advertisement,
    trust: Arc<S>,
    confirm: Arc<C>,
    state_tx: watch::Sender<Lifecycle>,
    /// The live session once connected (held for the transfer layer to use).
    session: Arc<RwLock<Option<Session>>>,
}

impl<S: TrustStore + 'static, C: ConfirmPrompt + 'static> ConnectionManager<S, C> {
    pub fn new(advert: Advertisement, trust: Arc<S>, confirm: Arc<C>) -> Self {
        let (state_tx, _) = watch::channel(Lifecycle::Idle);
        Self {
            advert,
            trust,
            confirm,
            state_tx,
            session: Arc::new(RwLock::new(None)),
        }
    }

    /// Subscribe to lifecycle changes (the UI drives its status off this).
    pub fn watch(&self) -> watch::Receiver<Lifecycle> {
        self.state_tx.subscribe()
    }

    fn set(&self, s: Lifecycle) {
        let _ = self.state_tx.send(s);
    }

    /// Run the full accept loop: advertise, then for each peer that connects,
    /// pair-or-resume and bring up a session. This is the single entry the app
    /// and the `pair_device` command ultimately drive.
    ///
    /// SCAFFOLD: the sequencing is final and compiles; the two awaited backends
    /// (`BlePeripheral`, `Session`) are themselves scaffolds, so this returns
    /// their `todo!()` until they land — the *shape* of the direct-connect path
    /// is what this nails down.
    pub async fn run(&self) -> anyhow::Result<()> {
        self.set(Lifecycle::Advertising);
        let ble = BlePeripheral::new(self.advert.clone());

        // 1. Accept a BLE central (the phone) and get its pairing transport.
        let transport = ble.advertise_and_accept().await?;

        // 2. First-time pair over UKey2, gated by the Allow dialog.
        self.set(Lifecycle::Pairing {
            peer_name: self.advert.name.clone(),
        });
        let ctx = ukey2::run_server(&transport, self.confirm.as_ref()).await?;

        // 3. Persist the trust so the next reconnect is silent.
        let record = ctx.to_trust_record();
        self.trust.put(record.clone()).await?;

        // 4. Bring up the authenticated Wi-Fi session and hold it for transfer.
        self.set(Lifecycle::Resuming {
            peer_id: record.peer_id.clone(),
        });
        let endpoint = resolve_endpoint(&record.peer_id).await?;
        let session = Session::resume(&record, endpoint.clone()).await?;
        self.set(Lifecycle::Connected {
            peer_id: record.peer_id.clone(),
            endpoint,
        });
        *self.session.write().await = Some(session);
        Ok(())
    }
}

/// Resolve a known peer's current `ip:port` via discovery (ONet/mDNS).
async fn resolve_endpoint(peer_id: &str) -> anyhow::Result<String> {
    let _ = peer_id;
    todo!("look up the peer's current Wi-Fi endpoint via discovery (ONet :46888)")
}
