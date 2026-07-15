use std::{
    error::Error,
    net::TcpListener,
    sync::mpsc,
    time::{Duration, Instant},
};

use dnfast_cache::Cache;
use dnfast_refresh::{HttpTransport, RefreshError, RefreshOutcome, Refresher, Source, Transport};

struct NoNetwork;

impl Transport for NoNetwork {
    fn get(&self, url: &str, _maximum_bytes: u64) -> Result<Vec<u8>, RefreshError> {
        Err(RefreshError::Transport(format!(
            "unexpected request: {url}"
        )))
    }
}

#[test]
fn public_types_retain_construction_and_comparison_contracts() {
    let base = Source::BaseUrl("https://mirror.example/fedora".into());
    let metalink = Source::Metalink("https://meta.example/list".into());
    let outcome = RefreshOutcome {
        digest: "abc".into(),
        packages: 3,
    };

    assert_eq!(base.clone(), base);
    assert_ne!(base, metalink);
    assert_eq!(outcome.clone(), outcome);
    assert_eq!(outcome.digest, "abc");
    assert_eq!(outcome.packages, 3);
}

#[test]
fn public_error_variants_retain_display_and_source_contracts() {
    let errors = [
        RefreshError::Policy("policy".into()),
        RefreshError::Transport("transport".into()),
        RefreshError::Metalink("metalink".into()),
        RefreshError::Metadata("metadata".into()),
        RefreshError::Signature("signature".into()),
        RefreshError::Cache("cache".into()),
    ];

    assert_eq!(errors[0].to_string(), "refresh error: Policy(\"policy\")");
    assert_eq!(
        errors[1].to_string(),
        "refresh error: Transport(\"transport\")"
    );
    assert_eq!(
        errors[2].to_string(),
        "refresh error: Metalink(\"metalink\")"
    );
    assert_eq!(
        errors[3].to_string(),
        "refresh error: Metadata(\"metadata\")"
    );
    assert_eq!(
        errors[4].to_string(),
        "refresh error: Signature(\"signature\")"
    );
    assert_eq!(errors[5].to_string(), "refresh error: Cache(\"cache\")");
    assert!(errors.iter().all(|error| error.source().is_none()));
}

#[test]
fn public_refresher_rejects_untrusted_url_before_transport() {
    let directory = tempfile::tempdir().unwrap();
    let cache = Cache::new(directory.path());
    let error = Refresher::new(NoNetwork, &cache)
        .refresh(
            "fedora",
            Source::BaseUrl("https://user@mirror.example/fedora".into()),
        )
        .unwrap_err();

    assert!(matches!(error, RefreshError::Policy(_)));
}

#[test]
fn public_http_transport_retains_constructors() {
    let _new = HttpTransport::new();
    let _default = HttpTransport::default();
}

#[test]
fn http_transport_times_out_when_tls_peer_never_responds() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (accepted_tx, accepted_rx) = mpsc::channel();
    let (shutdown_tx, shutdown_rx) = mpsc::channel();
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        accepted_tx.send(()).unwrap();
        shutdown_rx.recv_timeout(Duration::from_secs(55)).unwrap();
        drop(stream);
    });

    let started = Instant::now();
    let error = HttpTransport::new()
        .get(&format!("https://{address}/blackhole"), 1024)
        .unwrap_err();
    let elapsed = started.elapsed();

    accepted_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    shutdown_tx.send(()).unwrap();
    server.join().unwrap();
    assert!(matches!(error, RefreshError::Transport(_)));
    assert!(elapsed >= Duration::from_secs(8), "elapsed: {elapsed:?}");
    assert!(elapsed < Duration::from_secs(20), "elapsed: {elapsed:?}");
    assert!(TcpListener::bind(address).is_ok(), "listener port leaked");
}
