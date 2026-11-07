//! Cross-subnet device discovery via gossip exchanges.
//!
//! Multicast announcements and subnet scans do not leave a device's own
//! subnet, but unicast HTTP between routed subnets works. Gossip builds on
//! that: devices that have confirmed each other exchange their views of
//! confirmed devices via `POST /api/localsend/v2/gossip`, so knowledge of
//! devices in other subnets spreads peer-to-peer without a central server.
//!
//! Entries received from a peer are hints only: each one is probed with a
//! register request (its certificate verified in HTTPS mode) before the
//! device is displayed, so a spoofed hint costs at most one probe. Hints for
//! devices that never answer are retried with a backoff, then dropped;
//! unconfirmed hints expire.

use crate::discovery::{
    DeviceChannel, DeviceIdentity, DiscoveredDevice, DiscoveryHandle, HttpChannel, StatefulDevice,
};
use crate::http::client::v2::LsHttpClientV2;
use crate::http::client::{ClientError, ResultWithPublicKey};
use crate::http::dto_v2::{GossipEntryDtoV2, GossipRequestDtoV2, GossipResponseDtoV2};
use crate::model::discovery::ProtocolType;
use crate::multicast::MulticastDevice;
use crate::util::error::ErrorChain;
use futures_util::StreamExt;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex as AsyncMutex, oneshot};
use tokio::time::MissedTickBehavior;
use tokio_util::sync::CancellationToken;

/// How often the periodic random-peer exchange runs. With push-pull
/// exchanges between random peers, knowledge of `n` devices spreads in
/// roughly `log(n)` rounds, so this keeps cross-subnet convergence in the
/// order of a minute while staying negligible in bandwidth.
pub const DEFAULT_EXCHANGE_INTERVAL: Duration = Duration::from_secs(20);

/// How long an unconfirmed hint is kept before it expires. Generous, because
/// a hinted device may be temporarily offline or unreachable from here.
pub const DEFAULT_HINT_TTL: Duration = Duration::from_secs(600);

/// How many times a hint is probed before it is dropped. Failed attempts are
/// retried with a growing backoff (see [`RETRY_BACKOFF`]).
pub const DEFAULT_MAX_ATTEMPTS: u32 = 3;

/// How many hint probes run at once. Hints arrive in bursts when many
/// devices are learned at once; probing is register requests, so a small
/// burst of concurrent dials is fine (the subnet scan uses 50).
pub const DEFAULT_PROBE_CONCURRENCY: usize = 8;

/// Timeout of an exchange or a hint probe. Cross-subnet peers may be a few
/// routed hops away, so this is more generous than the 500 ms that
/// discovery uses for LAN peers.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(3);

/// Base delay before a failed hint is probed again, multiplied by the number
/// of attempts already made.
const RETRY_BACKOFF: Duration = Duration::from_secs(30);

/// Configuration of the gossip discovery.
pub struct GossipConfig {
    /// This device's information, sent with every exchange.
    pub device: MulticastDevice,

    /// The TLS identity used for exchanges and hint probes.
    pub identity: DeviceIdentity,

    /// The discovery this gossip builds on: its store provides the devices
    /// offered in exchanges, and hint confirmations enter it.
    pub discovery: Arc<DiscoveryHandle>,

    /// Interval of the periodic random-peer exchange, usually
    /// [`DEFAULT_EXCHANGE_INTERVAL`].
    pub interval: Duration,

    /// Timeout of each exchange and hint probe, usually [`DEFAULT_TIMEOUT`].
    pub timeout: Duration,

    /// How long an unconfirmed hint is kept, usually [`DEFAULT_HINT_TTL`].
    pub hint_ttl: Duration,

    /// How many times a hint is probed before it is dropped, usually
    /// [`DEFAULT_MAX_ATTEMPTS`].
    pub max_attempts: u32,

    /// How many hint probes run at once, usually
    /// [`DEFAULT_PROBE_CONCURRENCY`].
    pub probe_concurrency: usize,
}

/// A device hint received from a peer, kept until it is confirmed, expired
/// or given up on.
struct Hint {
    entry: GossipEntryDtoV2,

    /// How many times probing this hint failed.
    attempts: u32,

    /// When the hint may be probed again. Set forward while a probe is
    /// queued so concurrent ticks do not dial the same device twice.
    next_attempt_at: Instant,

    expires_at: Instant,
}

struct GossipState {
    device: MulticastDevice,
    identity: DeviceIdentity,
    discovery: Arc<DiscoveryHandle>,
    timeout: Duration,
    hint_ttl: Duration,
    max_attempts: u32,
    probe_concurrency: usize,

    /// Hints waiting to be confirmed, by fingerprint.
    hints: Mutex<HashMap<String, Hint>>,

    /// Fingerprints whose hint is currently being probed, so that an
    /// overlapping exchange does not dial the same device twice.
    confirming: Mutex<HashSet<String>>,
}

impl GossipState {
    fn client(&self) -> Result<LsHttpClientV2, ClientError> {
        LsHttpClientV2::try_new(
            &self.identity.private_key_pem,
            &self.identity.cert_pem,
            // Hints and gossip peers are not pinned before they answer; the
            // fingerprint is read off the handshake and verified against the
            // store afterwards.
            None,
            Some(self.timeout),
        )
    }

    fn register_dto(&self) -> crate::http::dto_v2::RegisterDtoV2 {
        crate::http::dto_v2::RegisterDtoV2 {
            alias: self.device.alias.clone(),
            version: self.device.version.clone(),
            device_model: self.device.device_model.clone(),
            device_type: self.device.device_type.clone(),
            fingerprint: self.device.fingerprint.clone(),
            port: self.device.port,
            protocol: self.device.protocol,
            download: self.device.download,
        }
    }

    fn own_view(&self) -> Vec<GossipEntryDtoV2> {
        self.discovery.devices().iter().filter_map(entry_of).collect()
    }

    /// Exchanges views with the device at `channel`: sends this device's
    /// info and its confirmed devices, and processes the answer. The peer
    /// itself is confirmed into the store (the exchange proves the channel
    /// works); its devices are kept as hints for the confirmation pipeline.
    async fn exchange(&self, channel: &HttpChannel) -> Result<(), ClientError> {
        let client = self.client()?;
        let request = GossipRequestDtoV2 {
            info: self.register_dto(),
            devices: self.own_view(),
        };

        let response: ResultWithPublicKey<GossipResponseDtoV2> = client
            .gossip(channel.protocol, &channel.host, channel.port, request)
            .await?;

        // The peer itself is proven reachable by this exchange; in HTTPS mode
        // the handshake certificate is its identity, overriding any claim.
        let peer_fingerprint = match channel.protocol {
            ProtocolType::Https => response
                .cert_fingerprint
                .clone()
                .ok_or_else(|| anyhow::anyhow!("gossip response carried no peer certificate"))?,
            ProtocolType::Http => response.body.info.fingerprint.clone(),
        };
        if peer_fingerprint != self.device.fingerprint {
            self.discovery
                .add_device(DiscoveredDevice {
                    alias: response.body.info.alias,
                    version: response.body.info.version,
                    device_model: response.body.info.device_model,
                    device_type: response.body.info.device_type,
                    fingerprint: peer_fingerprint.clone(),
                    channel: DeviceChannel::Http(channel.clone()),
                    download: response.body.info.download,
                })
                .await;
        }

        self.ingest(Some(&peer_fingerprint), response.body.devices);

        Ok(())
    }

    /// Stores device entries as hints, without exchanging views. Entries for
    /// this device itself, for `peer_fingerprint` (confirmed by the exchange
    /// that carried them) and for already confirmed devices are ignored;
    /// fresher claims update a known hint's content and extend its expiry.
    fn ingest(&self, peer_fingerprint: Option<&str>, entries: Vec<GossipEntryDtoV2>) {
        let now = Instant::now();
        let mut hints = self.hints.lock().unwrap();
        for entry in entries {
            if entry.fingerprint == self.device.fingerprint
                || peer_fingerprint.is_some_and(|peer| entry.fingerprint == peer)
                || self
                    .discovery
                    .device_by_fingerprint(&entry.fingerprint)
                    .is_some()
            {
                // Ourselves, the peer, or a device this store has already
                // confirmed: not a hint.
                continue;
            }

            match hints.get_mut(&entry.fingerprint) {
                Some(hint) => {
                    // Keep the fresher claim; the confirmation pipeline is
                    // already racing on this hint, so leave its schedule.
                    if entry.seen_at_millis > hint.entry.seen_at_millis {
                        hint.entry = entry;
                    }
                    hint.expires_at = now + self.hint_ttl;
                }
                None => {
                    hints.insert(
                        entry.fingerprint.clone(),
                        Hint {
                            entry,
                            attempts: 0,
                            next_attempt_at: now,
                            expires_at: now + self.hint_ttl,
                        },
                    );
                }
            }
        }
    }

    /// Probes every due hint concurrently. A hint that confirms (its device
    /// answered a register request and entered the store) is removed; a
    /// failed one is backed off and dropped after [`GossipConfig::max_attempts`].
    async fn process_due_hints(&self) {
        let now = Instant::now();

        let due: Vec<GossipEntryDtoV2> = {
            let mut hints = self.hints.lock().unwrap();
            hints.retain(|_, hint| hint.expires_at > now);

            let mut confirming = self.confirming.lock().unwrap();
            hints
                .iter_mut()
                .filter(|(_, hint)| hint.next_attempt_at <= now)
                .filter(|(fingerprint, _)| confirming.insert((*fingerprint).clone()))
                .map(|(_, hint)| {
                    // Reserve the slot: while this probe is in flight, later
                    // ticks skip the hint instead of dialing it twice.
                    hint.next_attempt_at = now + RETRY_BACKOFF * (hint.attempts + 1);
                    hint.entry.clone()
                })
                .collect()
        };

        if due.is_empty() {
            return;
        }

        // Hints are confirmed with discovery's own probe: a register request
        // with certificate verification, entering the store on success.
        let confirmations = futures_util::stream::iter(due)
            .map(|entry| async move {
                let confirmed = self
                    .discovery
                    .discover(&entry.host, entry.port, entry.protocol)
                    .await
                    .is_ok()
                    && self
                        .discovery
                        .device_by_fingerprint(&entry.fingerprint)
                        .is_some();
                (entry, confirmed)
            })
            .buffer_unordered(self.probe_concurrency)
            .collect::<Vec<_>>()
            .await;

        let mut hints = self.hints.lock().unwrap();
        let mut probed = Vec::new();
        for (entry, confirmed) in confirmations {
            probed.push(entry.fingerprint.clone());
            if confirmed {
                tracing::info!("Gossip hint confirmed: {} ({})", entry.alias, entry.host);
                hints.remove(&entry.fingerprint);
            } else if let Some(hint) = hints.get_mut(&entry.fingerprint) {
                hint.attempts += 1;
                if hint.attempts >= self.max_attempts {
                    tracing::debug!(
                        "Gossip hint given up after {} attempts: {} ({})",
                        hint.attempts,
                        entry.alias,
                        entry.host,
                    );
                    hints.remove(&entry.fingerprint);
                }
            }
        }
        drop(hints);

        self.release_confirming(probed.into_iter());
    }

    fn release_confirming(&self, fingerprints: impl Iterator<Item = String>) {
        let mut confirming = self.confirming.lock().unwrap();
        for fingerprint in fingerprints {
            confirming.remove(&fingerprint);
        }
    }
}

/// The store entry of a confirmed device as a gossip hint, addressed by its
/// best channel. `None` when the device has no usable HTTP channel.
fn entry_of(state: &StatefulDevice) -> Option<GossipEntryDtoV2> {
    let channel = state.get_best_channel()?.http()?.clone();
    Some(GossipEntryDtoV2 {
        fingerprint: state.device.fingerprint.clone(),
        alias: state.device.alias.clone(),
        version: state.device.version.clone(),
        device_model: state.device.device_model.clone(),
        device_type: state.device.device_type.clone(),
        download: state.device.download,
        host: channel.host,
        port: channel.port,
        protocol: channel.protocol,
        seen_at_millis: state
            .logs
            .last()
            .map(|log| {
                log.timestamp
                    .duration_since(UNIX_EPOCH)
                    .map(|since| since.as_millis() as u64)
                    .unwrap_or(0)
            })
            .unwrap_or(0),
    })
}

/// A handle to a running gossip discovery, for exchanges initiated by the
/// application.
pub struct GossipHandle {
    state: Arc<GossipState>,
    cancel: CancellationToken,

    /// The task running the periodic exchange. Completes after a stop has
    /// been requested.
    task: AsyncMutex<Option<tokio::task::JoinHandle<()>>>,
}

impl GossipHandle {
    /// Exchanges views with the device at `channel` right away, in addition
    /// to the periodic random-peer exchange. Call this when a new device
    /// registered (it then learns this network's devices immediately) and on
    /// manual refreshes. Errors are logged, not returned: a failed exchange
    /// is retried by the periodic exchange.
    pub async fn exchange(&self, channel: HttpChannel) {
        if let Err(err) = self.state.exchange(&channel).await {
            tracing::debug!(
                "Gossip exchange with {} failed: {}",
                channel.host,
                ErrorChain(&err)
            );
        }
    }

    /// Stores the device entries a gossip peer sent to this device's HTTP
    /// server as hints, without exchanging views. The confirmation pipeline
    /// picks them up like entries received in an exchange.
    pub async fn ingest_hints(&self, peer_fingerprint: Option<String>, entries: Vec<GossipEntryDtoV2>) {
        self.state.ingest(peer_fingerprint.as_deref(), entries);
    }

    /// Requests the periodic task to stop. Wait for it with
    /// [`GossipHandle::wait_stopped`].
    pub fn stop(&self) {
        self.cancel.cancel();
    }

    /// Waits until the periodic task has terminated. Must be called after
    /// requesting a stop via the stop channel.
    pub async fn wait_stopped(&self) {
        if let Some(task) = self.task.lock().await.take() {
            let _ = task.await;
        }
    }
}

/// Starts the gossip discovery: a periodic task that confirms due hints and
/// exchanges views with a random confirmed peer. Nothing is exchanged until
/// the discovery has confirmed a first device.
///
/// Stop the task by dropping or closing `stop_rx`; wait for the port
/// resources with [`GossipHandle::wait_stopped`].
pub async fn start(config: GossipConfig, stop_rx: oneshot::Receiver<()>) -> GossipHandle {
    let state = Arc::new(GossipState {
        device: config.device,
        identity: config.identity,
        discovery: config.discovery,
        timeout: config.timeout,
        hint_ttl: config.hint_ttl,
        max_attempts: config.max_attempts,
        probe_concurrency: config.probe_concurrency,
        hints: Mutex::new(HashMap::new()),
        confirming: Mutex::new(HashSet::new()),
    });

    let cancel = CancellationToken::new();
    // The stop channel is one-shot; turn it into a token the loop can await
    // on every iteration.
    let stopped = CancellationToken::new();
    tokio::spawn({
        let stopped = stopped.clone();
        async move {
            let _ = stop_rx.await;
            stopped.cancel();
        }
    });
    let task = tokio::spawn({
        let state = state.clone();
        let cancel = cancel.clone();
        async move {
            let mut ticker = tokio::time::interval(config.interval);
            ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
            ticker.tick().await; // The first tick completes immediately; skip it.

            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        state.process_due_hints().await;
                        exchange_with_random_peer(&state).await;
                    }
                    _ = cancel.cancelled() => break,
                    _ = stopped.cancelled() => break,
                }
            }
        }
    });

    GossipHandle {
        state,
        cancel,
        task: AsyncMutex::new(Some(task)),
    }
}

/// One round of the periodic exchange: probes due hints first, then
/// exchanges views with one random confirmed peer.
async fn exchange_with_random_peer(state: &GossipState) {
    let channels: Vec<HttpChannel> = state
        .discovery
        .devices()
        .iter()
        .filter_map(|device| device.get_best_channel().and_then(|channel| channel.http().cloned()))
        .collect();

    let Some(channel) = pick_random(&channels) else {
        return;
    };

    if let Err(err) = state.exchange(channel).await {
        tracing::debug!(
            "Gossip exchange with {} failed: {}",
            channel.host,
            ErrorChain(&err)
        );
    }
}

/// Picks a pseudo-random element. The choice only load-balances exchanges
/// across peers, so a time-based pick is sufficient; `rand` is not pulled in
/// for it.
fn pick_random<T>(items: &[T]) -> Option<&T> {
    if items.is_empty() {
        return None;
    }
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos() as usize;
    Some(&items[nanos % items.len()])
}

/// Builds the device view served in gossip responses from the store, for
/// wiring into [`crate::http::server::ServerConfigV2::gossip_devices`].
pub fn gossip_view(discovery: &DiscoveryHandle) -> Vec<GossipEntryDtoV2> {
    discovery.devices().iter().filter_map(entry_of).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(fingerprint: &str, host: &str, seen_at: u64) -> GossipEntryDtoV2 {
        GossipEntryDtoV2 {
            fingerprint: fingerprint.to_string(),
            alias: format!("Alias of {fingerprint}"),
            version: "2.2".to_string(),
            device_model: None,
            device_type: None,
            download: false,
            host: host.to_string(),
            port: 53317,
            protocol: ProtocolType::Http,
            seen_at_millis: seen_at,
        }
    }

    #[test]
    fn test_entry_of_uses_best_channel_and_last_log() {
        let store_device = StatefulDevice {
            device: DiscoveredDevice {
                alias: "A".to_string(),
                version: "2.2".to_string(),
                device_model: None,
                device_type: None,
                fingerprint: "a".to_string(),
                channel: DeviceChannel::Http(HttpChannel {
                    host: "10.0.0.10".to_string(),
                    port: 53317,
                    protocol: ProtocolType::Http,
                }),
                download: false,
            },
            channels: HashMap::from([(
                DeviceChannel::Http(HttpChannel {
                    host: "10.0.0.10".to_string(),
                    port: 53317,
                    protocol: ProtocolType::Http,
                }),
                crate::discovery::ChannelStatus::Available,
            )]),
            logs: vec![],
        };

        let entry = entry_of(&store_device).expect("a device with an HTTP channel maps");
        assert_eq!(entry.fingerprint, "a");
        assert_eq!(entry.host, "10.0.0.10");
        assert_eq!(entry.seen_at_millis, 0, "no logs means unknown");
    }

    #[test]
    fn test_pick_random_handles_empty_and_bounds() {
        assert!(pick_random::<u8>(&[]).is_none());

        let items = [1_u8, 2, 3];
        for _ in 0..32 {
            assert!(pick_random(&items).is_some(), "non-empty input always picks");
        }
    }
}
