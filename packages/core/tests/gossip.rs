#![cfg(feature = "discovery")]

//! End-to-end gossip tests: real HTTP servers answer the exchanges, and the
//! confirmation pipeline is observed through the discovery store. Multicast
//! is irrelevant here (gossip rides on HTTP), so instances are started
//! regardless of whether multicast could be bound.

use localsend::crypto::cert::{generate_self_signed, SelfSignedCert};
use localsend::discovery::{DeviceIdentity, DiscoveryConfig, DiscoveryHandle};
use localsend::gossip::{GossipConfig, GossipHandle};
use localsend::http::client::v2::LsHttpClientV2;
use localsend::http::dto_v2::{GossipEntryDtoV2, GossipRequestDtoV2};
use localsend::http::server::v2::ServerEventV2;
use localsend::http::server::web::WebConfig;
use localsend::http::server::{start_with_port, GossipDevicesProvider, ServerConfigV2};
use localsend::http::state::ClientInfo;
use localsend::model::discovery::{DeviceType, ProtocolType, PROTOCOL_VERSION_V2};
use localsend::multicast::MulticastDevice;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

/// Distinct from the groups in `discovery.rs` and `multicast.rs`, so that
/// unrelated instances stay out.
const TEST_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 168);

/// See [TEST_GROUP].
const TEST_GROUP_V6: Ipv6Addr = Ipv6Addr::new(0xff12, 0, 0, 0, 0, 0, 0xfd3a, 0xe421);

/// Multicast ports are not reused between tests.
static NEXT_MULTICAST_PORT: AtomicU16 = AtomicU16::new(56317);

const CONFIRM_TIMEOUT: Duration = Duration::from_secs(5);

fn entry(fingerprint: &str, host: &str, port: u16) -> GossipEntryDtoV2 {
    GossipEntryDtoV2 {
        fingerprint: fingerprint.to_string(),
        alias: format!("Alias of {fingerprint}"),
        version: PROTOCOL_VERSION_V2.to_string(),
        device_model: None,
        device_type: None,
        download: false,
        host: host.to_string(),
        port,
        protocol: ProtocolType::Http,
        seen_at_millis: 0,
    }
}

/// Starts a v2 server whose gossip responses offer the given devices.
/// Returns the port the OS picked.
async fn start_gossip_server(
    alias: &str,
    fingerprint: &str,
    devices: Vec<GossipEntryDtoV2>,
) -> (u16, mpsc::Receiver<ServerEventV2>, oneshot::Sender<()>) {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    let (event_tx, event_rx) = mpsc::channel(16);
    let (stop_tx, stop_rx) = oneshot::channel();

    let gossip_devices: Option<GossipDevicesProvider> = if devices.is_empty() {
        None
    } else {
        Some(Arc::new(move || devices.clone()))
    };

    // Port 0 lets the OS pick a free port, avoiding collisions between tests.
    let handle = start_with_port(
        0,
        None, // plain HTTP
        ClientInfo {
            alias: alias.to_string(),
            version: PROTOCOL_VERSION_V2.to_string(),
            device_model: Some("Rust".to_string()),
            device_type: Some(DeviceType::Headless),
            token: fingerprint.to_string(),
        },
        None,
        Some(ServerConfigV2 {
            pin: None,
            verify_checksums: true,
            event_tx,
            gossip_devices,
        }),
        WebConfig::default(),
        stop_rx,
    )
    .await
    .expect("Failed to start server");

    (handle.port(), event_rx, stop_tx)
}

struct GossipInstance {
    fingerprint: String,
    discovery: Arc<DiscoveryHandle>,
    gossip: GossipHandle,
    _discovery_stop: oneshot::Sender<()>,
    _gossip_stop: oneshot::Sender<()>,
}

/// Starts a discovery with a gossip engine on top of it. The short interval
/// and the short timeouts keep the confirmation pipeline observable.
async fn start_gossip_instance(alias: &str) -> GossipInstance {
    let cert: SelfSignedCert = generate_self_signed().expect("Failed to generate an identity");
    let (event_tx, _events) = mpsc::channel(32);
    let (discovery_stop_tx, discovery_stop_rx) = oneshot::channel();

    let discovery = Arc::new(
        localsend::discovery::start(
            DiscoveryConfig {
                group: TEST_GROUP,
                group_v6: Some(TEST_GROUP_V6),
                port: NEXT_MULTICAST_PORT.fetch_add(1, Ordering::Relaxed),
                interface_filter: Default::default(),
                device: MulticastDevice {
                    alias: alias.to_string(),
                    version: PROTOCOL_VERSION_V2.to_string(),
                    device_model: Some("Rust".to_string()),
                    device_type: Some(DeviceType::Headless),
                    fingerprint: cert.fingerprint.clone(),
                    port: 40000,
                    protocol: ProtocolType::Http,
                    download: false,
                },
                identity: DeviceIdentity {
                    cert_pem: cert.certificate_pem.clone(),
                    private_key_pem: cert.private_key_pem.clone(),
                },
                timeout: localsend::discovery::DEFAULT_DISCOVERY_TIMEOUT,
                event_tx: Some(event_tx),
            },
            discovery_stop_rx,
        )
        .await,
    );

    let (gossip_stop_tx, gossip_stop_rx) = oneshot::channel();
    let gossip = localsend::gossip::start(
        GossipConfig {
            device: MulticastDevice {
                alias: alias.to_string(),
                version: PROTOCOL_VERSION_V2.to_string(),
                device_model: Some("Rust".to_string()),
                device_type: Some(DeviceType::Headless),
                fingerprint: cert.fingerprint.clone(),
                port: 40000,
                protocol: ProtocolType::Http,
                download: false,
            },
            identity: DeviceIdentity {
                cert_pem: cert.certificate_pem,
                private_key_pem: cert.private_key_pem,
            },
            discovery: discovery.clone(),
            interval: Duration::from_millis(100),
            timeout: Duration::from_millis(1000),
            hint_ttl: Duration::from_secs(30),
            max_attempts: 2,
            probe_concurrency: 4,
        },
        gossip_stop_rx,
    )
    .await;

    GossipInstance {
        fingerprint: cert.fingerprint,
        discovery,
        gossip,
        _discovery_stop: discovery_stop_tx,
        _gossip_stop: gossip_stop_tx,
    }
}

async fn best_channel(handle: &DiscoveryHandle, fingerprint: &str) -> localsend::discovery::HttpChannel {
    handle
        .device_by_fingerprint(fingerprint)
        .expect("device must be in the store")
        .get_best_channel()
        .and_then(|channel| channel.http().cloned())
        .expect("device must have an HTTP channel")
}

/// Waits until the device with the given fingerprint entered the store.
async fn wait_for_device(handle: &DiscoveryHandle, fingerprint: &str) -> bool {
    let deadline = tokio::time::Instant::now() + CONFIRM_TIMEOUT;
    while tokio::time::Instant::now() < deadline {
        if handle.device_by_fingerprint(fingerprint).is_some() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    handle.device_by_fingerprint(fingerprint).is_some()
}

/// The gossip endpoint answers with the responder's identity and the devices
/// of its provider, and emits the requester's view as a `GossipReceived`
/// event.
#[tokio::test]
async fn test_gossip_endpoint_exchanges_views() {
    let (b_port, mut b_events, _b_stop) = start_gossip_server(
        "B",
        "b-fingerprint",
        vec![entry("c-fingerprint", "127.0.0.1", 40001)],
    )
    .await;

    let client = LsHttpClientV2::try_new_without_cert().expect("client");
    let response = client
        .gossip(
            ProtocolType::Http,
            "127.0.0.1",
            b_port,
            GossipRequestDtoV2 {
                info: crate_test_info("a-fingerprint"),
                devices: vec![entry("d-fingerprint", "127.0.0.1", 40002)],
            },
        )
        .await
        .expect("gossip exchange must succeed");

    assert_eq!(response.body.info.fingerprint, "b-fingerprint");
    assert_eq!(response.body.info.alias, "B");
    assert_eq!(response.body.devices.len(), 1);
    assert_eq!(response.body.devices[0].fingerprint, "c-fingerprint");

    let event = tokio::time::timeout(CONFIRM_TIMEOUT, b_events.recv())
        .await
        .expect("event in time")
        .expect("event channel open");
    match event {
        ServerEventV2::GossipReceived { info, entries, .. } => {
            assert_eq!(info.fingerprint, "a-fingerprint");
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].fingerprint, "d-fingerprint");
        }
        other => panic!("unexpected server event: {other:?}"),
    }
}

/// A device hinted by a gossip peer is probed and, once it answers a register
/// request, enters the store. Entries for the exchanger itself and for
/// already confirmed devices are not hinted.
#[tokio::test]
async fn test_gossip_hint_gets_confirmed_into_the_store() {
    let (c_port, _c_events, _c_stop) = start_gossip_server("C", "c-fingerprint", vec![]).await;

    let instance = start_gossip_instance("A").await;
    let (b_port, _b_events, _b_stop) = start_gossip_server(
        "B",
        "b-fingerprint",
        vec![
            // Confirmed by the pipeline into the store.
            entry("c-fingerprint", "127.0.0.1", c_port),
            // Ourselves and the exchanger: never hinted.
            entry(&instance.fingerprint, "127.0.0.1", 40003),
            entry("b-fingerprint", "127.0.0.1", 40004),
        ],
    )
    .await;

    instance
        .discovery
        .discover("127.0.0.1", b_port, ProtocolType::Http)
        .await
        .expect("register with B")
        .expect("B must not discover itself");
    assert!(instance.discovery.device_by_fingerprint("b-fingerprint").is_some());

    let channel = best_channel(&instance.discovery, "b-fingerprint").await;
    instance.gossip.exchange(channel).await;

    // The periodic exchange confirms due hints; the short interval makes this
    // fast. C answers its probe, so it must enter the store.
    assert!(
        wait_for_device(&instance.discovery, "c-fingerprint").await,
        "the hinted device must be confirmed into the store"
    );
}

/// A hint whose device never answers is dropped after the configured number
/// of attempts; the exchange itself still succeeds meanwhile.
#[tokio::test]
async fn test_gossip_hint_of_unreachable_device_is_not_added() {
    let instance = start_gossip_instance("A").await;
    let (b_port, _b_events, _b_stop) = start_gossip_server(
        "B",
        "b-fingerprint",
        vec![entry("ghost-fingerprint", "127.0.0.1", 1)], // Nothing listens here.
    )
    .await;

    instance
        .discovery
        .discover("127.0.0.1", b_port, ProtocolType::Http)
        .await
        .expect("register with B")
        .expect("B must not discover itself");

    let channel = best_channel(&instance.discovery, "b-fingerprint").await;
    instance.gossip.exchange(channel).await;

    // Give the pipeline a fair chance to (wrongly) confirm the ghost, then
    // assert it never entered the store.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(
        instance.discovery.device_by_fingerprint("ghost-fingerprint").is_none(),
        "an unreachable hinted device must not enter the store"
    );
}

fn crate_test_info(fingerprint: &str) -> localsend::http::dto_v2::RegisterDtoV2 {
    localsend::http::dto_v2::RegisterDtoV2 {
        alias: "A".to_string(),
        version: PROTOCOL_VERSION_V2.to_string(),
        device_model: Some("Rust".to_string()),
        device_type: Some(DeviceType::Headless),
        fingerprint: fingerprint.to_string(),
        port: 40000,
        protocol: ProtocolType::Http,
        download: false,
    }
}
