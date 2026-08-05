use async_trait::async_trait;
use didwebvh_rs::url::WebVHURL;
use robin_did_resolver_spike::{
    DidResolver, DownloadFailureKind, EvidenceFetcher, EvidenceSource, FetchError, FetchedEvidence,
    Freshness, LocalFailureKind, MAX_DID_BYTES, MAX_SOURCE_URI_BYTES, ResolutionError,
    ResolutionInput, SourceAttempt, SourceAttemptOutcome, SourceAttemptPhase, SourceKind,
    TransportFailureKind, TransportPolicy, WebvhResolver,
};
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;

const DID: &str = "did:webvh:QmUy89VrfryQ254CeHZzQfmcKqByPoKNGqYykP3SeXuegQ:example.com";
const DID_QUERY_PREFIX: &str =
    "did:webvh:QmUy89VrfryQ254CeHZzQfmcKqByPoKNGqYykP3SeXuegQ:example.com?x=";

fn fixture() -> ResolutionInput {
    serde_json::from_str(include_str!("fixtures/basic-create/input.json")).unwrap()
}

fn oversized_ascii_did() -> String {
    let prefix = "did:webvh:";
    let did = format!("{prefix}{}", "a".repeat(MAX_DID_BYTES + 1 - prefix.len()));
    assert_eq!(did.len(), MAX_DID_BYTES + 1);
    did
}

fn did_at_exact_limit_with_query_filler(filler: char) -> String {
    assert!(filler.is_ascii());
    let filler_len = MAX_DID_BYTES - DID_QUERY_PREFIX.len();
    let did = format!(
        "{DID_QUERY_PREFIX}{}",
        std::iter::repeat_n(filler, filler_len).collect::<String>()
    );
    assert_eq!(did.len(), MAX_DID_BYTES);
    did
}

fn assert_did_byte_limit(error: ResolutionError) {
    assert!(matches!(
        error,
        ResolutionError::ResourceLimit(message)
            if message == "DID exceeds the configured byte limit"
    ));
}

#[test]
fn transforms_valid_did_to_fixed_https_evidence_endpoints() {
    let (log, witness) = WebvhResolver::evidence_urls(DID).unwrap();
    assert_eq!(log, "https://example.com/.well-known/did.jsonl");
    assert_eq!(witness, "https://example.com/.well-known/did-witness.json");
}

#[test]
fn rejects_ip_localhost_traversal_separator_and_fragment_smuggling() {
    let scid = "QmUy89VrfryQ254CeHZzQfmcKqByPoKNGqYykP3SeXuegQ";
    let hostile = [
        format!("did:webvh:{scid}:127.0.0.1"),
        format!("did:webvh:{scid}:127%2E0%2E0%2E1"),
        format!("did:webvh:{scid}:localhost"),
        format!("did:webvh:{scid}:example.com:..:admin"),
        format!("did:webvh:{scid}:example.com:%2E%2E:admin"),
        format!("did:webvh:{scid}:example.com:%2fadmin"),
        format!("did:webvh:{scid}:127.0.0.1#@example.com"),
        format!("did:webvh:{scid}:example.com::admin"),
    ];
    for did in hostile {
        assert!(
            WebvhResolver::evidence_urls(&did).is_err(),
            "hostile DID unexpectedly accepted: {did}"
        );
    }
}

struct StubFetcher {
    result: Result<FetchedEvidence, FetchError>,
}

struct CountingFetcher {
    calls: Cell<usize>,
    result: Result<FetchedEvidence, FetchError>,
}

#[async_trait(?Send)]
impl EvidenceFetcher for CountingFetcher {
    async fn fetch(
        &self,
        _log_url: &str,
        _witness_url: &str,
        _policy: &TransportPolicy,
    ) -> Result<FetchedEvidence, FetchError> {
        self.calls.set(self.calls.get() + 1);
        self.result.clone()
    }
}

#[test]
fn oversized_did_is_rejected_before_url_parsing() {
    assert_did_byte_limit(WebvhResolver::evidence_urls(&oversized_ascii_did()).unwrap_err());
}

#[test]
fn did_at_exact_byte_limit_is_not_rejected_by_envelope() {
    let did = did_at_exact_limit_with_query_filler('a');
    let filler = "a".repeat(MAX_DID_BYTES - DID_QUERY_PREFIX.len());

    let (log, witness) = WebvhResolver::evidence_urls(&did).unwrap();

    assert_eq!(
        log,
        format!("https://example.com/.well-known/did.jsonl?x={filler}")
    );
    assert_eq!(
        witness,
        format!("https://example.com/.well-known/did-witness.json?x={filler}")
    );
    assert_eq!(log.len(), 2_021);
    assert_eq!(witness.len(), 2_028);
    assert!(log.len() <= MAX_SOURCE_URI_BYTES);
    assert!(witness.len() <= MAX_SOURCE_URI_BYTES);
}

#[test]
fn evidence_urls_rejects_reachable_public_transformed_url_overflow() {
    let did = did_at_exact_limit_with_query_filler('\'');
    let filler_len = MAX_DID_BYTES - DID_QUERY_PREFIX.len();

    let parsed = WebVHURL::parse_did_url(&did).expect("exact-limit DID URL should parse");
    assert_eq!(parsed.query, Some(format!("x={}", "'".repeat(filler_len))));

    let log = parsed
        .get_http_url(Some("did.jsonl"))
        .expect("accepted query should serialize to a log URL")
        .to_string();
    let witness = parsed
        .get_http_url(Some("did-witness.json"))
        .expect("accepted query should serialize to a witness URL")
        .to_string();
    let encoded_filler = "%27".repeat(filler_len);
    assert_eq!(
        log,
        format!("https://example.com/.well-known/did.jsonl?x={encoded_filler}")
    );
    assert_eq!(
        witness,
        format!("https://example.com/.well-known/did-witness.json?x={encoded_filler}")
    );
    assert_eq!(log.len(), 5_975);
    assert_eq!(witness.len(), 5_982);
    assert!(log.len() > MAX_SOURCE_URI_BYTES);
    assert!(witness.len() > MAX_SOURCE_URI_BYTES);

    assert!(matches!(
        WebvhResolver::evidence_urls(&did),
        Err(ResolutionError::ResourceLimit(message))
            if message == "transformed evidence URL exceeds the configured byte limit"
    ));
}

#[tokio::test]
async fn resolve_via_rejects_oversized_did_before_fetch() {
    let fetcher = CountingFetcher {
        calls: Cell::new(0),
        result: Err(FetchError::Unavailable),
    };
    let policy = TransportPolicy {
        retries: 2,
        ..TransportPolicy::default()
    };
    let error = WebvhResolver
        .resolve_via(
            &oversized_ascii_did(),
            &fetcher,
            &policy,
            Freshness::default(),
        )
        .await
        .unwrap_err();
    assert_did_byte_limit(error);
    assert_eq!(fetcher.calls.get(), 0);
}

fn valid_sources() -> [EvidenceSource; 2] {
    [
        EvidenceSource {
            log_url: "https://one.example/did.jsonl".into(),
            witness_url: "https://one.example/did-witness.json".into(),
            source_kind: SourceKind::Watcher,
        },
        EvidenceSource {
            log_url: "https://two.example/did.jsonl".into(),
            witness_url: "https://two.example/did-witness.json".into(),
            source_kind: SourceKind::Watcher,
        },
    ]
}

#[tokio::test]
async fn resolve_via_sources_rejects_oversized_did_before_any_source_attempt() {
    let input = fixture();
    let fetcher = CountingFetcher {
        calls: Cell::new(0),
        result: Ok(downloaded(input.raw_log)),
    };
    let policy = TransportPolicy {
        retries: 0,
        ..TransportPolicy::default()
    };
    let error = WebvhResolver
        .resolve_via_sources(
            &oversized_ascii_did(),
            &fetcher,
            &valid_sources(),
            &policy,
            Freshness::default(),
        )
        .await
        .unwrap_err();
    assert_did_byte_limit(error);
    assert_eq!(fetcher.calls.get(), 0);
}

#[tokio::test]
async fn oversized_did_bypasses_all_sources_and_retries() {
    let input = fixture();
    let fetcher = CountingFetcher {
        calls: Cell::new(0),
        result: Ok(downloaded(input.raw_log)),
    };
    let policy = TransportPolicy {
        retries: 2,
        ..TransportPolicy::default()
    };
    let error = WebvhResolver
        .resolve_via_sources(
            &oversized_ascii_did(),
            &fetcher,
            &valid_sources(),
            &policy,
            Freshness::default(),
        )
        .await
        .unwrap_err();
    assert_did_byte_limit(error);
    assert_eq!(fetcher.calls.get(), 0);
}

#[tokio::test]
async fn multibyte_did_is_rejected_by_utf8_byte_length_before_fetch() {
    let did = format!("did:webvh:{}", "é".repeat(MAX_DID_BYTES / 2));
    let utf8_bytes = did.as_bytes();
    assert!(did.chars().count() <= MAX_DID_BYTES);
    assert!(utf8_bytes.len() > MAX_DID_BYTES);
    let fetcher = CountingFetcher {
        calls: Cell::new(0),
        result: Err(FetchError::Unavailable),
    };
    let error = WebvhResolver
        .resolve_via(
            &did,
            &fetcher,
            &TransportPolicy::default(),
            Freshness::default(),
        )
        .await
        .unwrap_err();
    assert_did_byte_limit(error);
    assert_eq!(fetcher.calls.get(), 0);
}

#[async_trait(?Send)]
impl EvidenceFetcher for StubFetcher {
    async fn fetch(
        &self,
        _log_url: &str,
        _witness_url: &str,
        _policy: &TransportPolicy,
    ) -> Result<FetchedEvidence, FetchError> {
        self.result.clone()
    }
}

#[tokio::test]
async fn transport_failures_are_typed_and_fail_closed() {
    for (fetch_error, expected) in [
        (FetchError::Dns, TransportFailureKind::Dns),
        (FetchError::Tls, TransportFailureKind::Tls),
        (FetchError::Cors, TransportFailureKind::Cors),
        (FetchError::Timeout, TransportFailureKind::Timeout),
        (FetchError::Http(404), TransportFailureKind::HttpStatus(404)),
        (FetchError::Http(500), TransportFailureKind::HttpStatus(500)),
        (FetchError::Redirect, TransportFailureKind::Redirect),
        (FetchError::TooLarge, TransportFailureKind::TooLarge),
        (FetchError::Unavailable, TransportFailureKind::Unavailable),
        (FetchError::DnsRebinding, TransportFailureKind::DnsRebinding),
        (FetchError::Truncated, TransportFailureKind::Truncated),
        (FetchError::SlowStream, TransportFailureKind::SlowStream),
    ] {
        let fetcher = StubFetcher {
            result: Err(fetch_error),
        };
        let error = WebvhResolver
            .resolve_via(
                DID,
                &fetcher,
                &TransportPolicy::default(),
                Freshness::default(),
            )
            .await
            .unwrap_err();
        assert!(matches!(error, ResolutionError::SourcesExhausted { .. }));
        assert_eq!(error.source_attempts().len(), 2);
        assert!(error.source_attempts().iter().all(|attempt| {
            attempt.phase == SourceAttemptPhase::Transport
                && attempt.outcome == SourceAttemptOutcome::TransportRejected(expected.clone())
                && !attempt.locally_verified
        }));
    }
}

struct ScriptedFetcher {
    results: RefCell<VecDeque<Result<FetchedEvidence, FetchError>>>,
    calls: RefCell<Vec<FetchCall>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FetchCall {
    log_url: String,
    witness_url: String,
    policy: TransportPolicy,
}

impl ScriptedFetcher {
    fn new(results: impl IntoIterator<Item = Result<FetchedEvidence, FetchError>>) -> Self {
        Self {
            results: RefCell::new(results.into_iter().collect()),
            calls: RefCell::new(Vec::new()),
        }
    }

    fn calls(&self) -> Vec<FetchCall> {
        self.calls.borrow().clone()
    }

    fn assert_exhausted(&self) {
        assert!(
            self.results.borrow().is_empty(),
            "resolver made fewer fetch calls than the script expected"
        );
    }
}

#[async_trait(?Send)]
impl EvidenceFetcher for ScriptedFetcher {
    async fn fetch(
        &self,
        log_url: &str,
        witness_url: &str,
        policy: &TransportPolicy,
    ) -> Result<FetchedEvidence, FetchError> {
        self.calls.borrow_mut().push(FetchCall {
            log_url: log_url.into(),
            witness_url: witness_url.into(),
            policy: policy.clone(),
        });
        self.results
            .borrow_mut()
            .pop_front()
            .expect("resolver made more fetch calls than the script allowed")
    }
}

fn downloaded(raw_log: String) -> FetchedEvidence {
    let length = raw_log.len();
    FetchedEvidence {
        raw_log,
        raw_witnesses: None,
        observed_at: "2026-07-30T00:00:00Z".into(),
        resolved_addresses: vec!["93.184.216.34".parse().unwrap()],
        content_length: Some(length),
        complete: true,
    }
}

fn source(name: &str, source_kind: SourceKind) -> EvidenceSource {
    EvidenceSource {
        log_url: format!("https://{name}.example/did.jsonl"),
        witness_url: format!("https://{name}.example/did-witness.json"),
        source_kind,
    }
}

#[allow(clippy::needless_pass_by_value)]
fn assert_attempt(
    attempt: &SourceAttempt,
    source: &EvidenceSource,
    source_index: usize,
    attempt_number: u8,
    phase: SourceAttemptPhase,
    outcome: SourceAttemptOutcome,
    locally_verified: bool,
) {
    assert_eq!(attempt.source_uri, source.log_url);
    assert_eq!(attempt.witness_uri, source.witness_url);
    assert_eq!(attempt.source_kind, source.source_kind);
    assert_eq!(attempt.source_index, source_index);
    assert_eq!(attempt.attempt_number, attempt_number);
    assert_eq!(attempt.phase, phase);
    assert_eq!(attempt.outcome, outcome);
    assert_eq!(attempt.locally_verified, locally_verified);
}

fn assert_calls(fetcher: &ScriptedFetcher, sources: &[EvidenceSource], expected: &[usize]) {
    let calls = fetcher.calls();
    assert_eq!(calls.len(), expected.len());
    for (call, source_index) in calls.iter().zip(expected) {
        assert_eq!(call.log_url, sources[*source_index].log_url);
        assert_eq!(call.witness_url, sources[*source_index].witness_url);
    }
}

#[tokio::test]
async fn bounded_source_fallback_records_every_attempt() {
    let input = fixture();
    let fetcher = ScriptedFetcher::new([
        Err(FetchError::Dns),
        Err(FetchError::Timeout),
        Ok(downloaded(input.raw_log)),
    ]);
    let sources = [
        source("unavailable", SourceKind::Watcher),
        source("alternate", SourceKind::Watcher),
    ];
    let policy = TransportPolicy::default();
    let output = WebvhResolver
        .resolve_via_sources(DID, &fetcher, &sources, &policy, Freshness::default())
        .await
        .unwrap();
    fetcher.assert_exhausted();
    assert_calls(&fetcher, &sources, &[0, 0, 1]);
    assert_eq!(output.evidence.source_attempts.len(), 3);
    assert_attempt(
        &output.evidence.source_attempts[0],
        &sources[0],
        0,
        1,
        SourceAttemptPhase::Transport,
        SourceAttemptOutcome::TransportRejected(TransportFailureKind::Dns),
        false,
    );
    assert_attempt(
        &output.evidence.source_attempts[1],
        &sources[0],
        0,
        2,
        SourceAttemptPhase::Transport,
        SourceAttemptOutcome::TransportRejected(TransportFailureKind::Timeout),
        false,
    );
    assert_attempt(
        &output.evidence.source_attempts[2],
        &sources[1],
        1,
        1,
        SourceAttemptPhase::LocalMethodVerification,
        SourceAttemptOutcome::LocallyVerified,
        true,
    );
    assert_eq!(output.evidence.source_uri, sources[1].log_url);
}

#[tokio::test]
async fn conflicting_valid_sources_return_attempt_provenance() {
    let fetcher = ScriptedFetcher::new([
        Ok(downloaded(
            include_str!("fixtures/basic-update/did.jsonl").into(),
        )),
        Ok(downloaded(
            include_str!("fixtures/key-rotation/did.jsonl").into(),
        )),
    ]);
    let sources = [
        source("one", SourceKind::Watcher),
        source("two", SourceKind::Watcher),
    ];
    let policy = TransportPolicy {
        retries: 0,
        ..TransportPolicy::default()
    };
    let error = WebvhResolver
        .resolve_via_sources(DID, &fetcher, &sources, &policy, Freshness::default())
        .await
        .unwrap_err();
    fetcher.assert_exhausted();
    assert_calls(&fetcher, &sources, &[0, 1]);
    assert!(matches!(error, ResolutionError::SourceConflict { .. }));
    assert_eq!(error.source_attempts().len(), 2);
    for (index, attempt) in error.source_attempts().iter().enumerate() {
        assert_attempt(
            attempt,
            &sources[index],
            index,
            1,
            SourceAttemptPhase::LocalMethodVerification,
            SourceAttemptOutcome::LocallyVerified,
            true,
        );
    }
    assert!(!error.to_string().contains("versionId"));
}

#[tokio::test]
async fn malicious_remote_assertion_is_rejected_before_valid_alternate() {
    let input = fixture();
    let malicious = input.raw_log.replacen("z2gbCNg9", "z2gbCNh9", 1);
    let fetcher = ScriptedFetcher::new([Ok(downloaded(malicious)), Ok(downloaded(input.raw_log))]);
    let sources = [
        source("resolver", SourceKind::RemoteResolver),
        source("direct", SourceKind::DirectHttps),
    ];
    let policy = TransportPolicy {
        retries: 0,
        ..TransportPolicy::default()
    };
    let output = WebvhResolver
        .resolve_via_sources(DID, &fetcher, &sources, &policy, Freshness::default())
        .await
        .unwrap();
    fetcher.assert_exhausted();
    assert_calls(&fetcher, &sources, &[0, 1]);
    assert!(matches!(
        output.evidence.source_attempts[0].outcome,
        SourceAttemptOutcome::LocalMethodRejected(
            LocalFailureKind::InvalidProof
                | LocalFailureKind::InvalidHistory
                | LocalFailureKind::InvalidScid
        )
    ));
    assert_eq!(output.evidence.source_uri, sources[1].log_url);
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn transport_policy_and_post_dns_contract_are_hard_bounded() {
    let unsafe_policies = [
        TransportPolicy {
            timeout_millis: 0,
            ..TransportPolicy::default()
        },
        TransportPolicy {
            timeout_millis: 30_001,
            ..TransportPolicy::default()
        },
        TransportPolicy {
            retries: 3,
            ..TransportPolicy::default()
        },
        TransportPolicy {
            max_concurrency: 0,
            ..TransportPolicy::default()
        },
        TransportPolicy {
            max_concurrency: 3,
            ..TransportPolicy::default()
        },
        TransportPolicy {
            max_response_bytes: 0,
            ..TransportPolicy::default()
        },
    ];
    for policy in unsafe_policies {
        let fetcher = StubFetcher {
            result: Err(FetchError::Unavailable),
        };
        assert!(matches!(
            WebvhResolver
                .resolve_via(DID, &fetcher, &policy, Freshness::default())
                .await,
            Err(ResolutionError::NetworkUnavailable(_))
        ));
    }

    for host in ["localhost", "127.0.0.1", "[::1]", "example.com%3a443"] {
        let fetcher = StubFetcher {
            result: Err(FetchError::Unavailable),
        };
        let sources = [EvidenceSource {
            log_url: format!("https://{host}/did.jsonl"),
            witness_url: format!("https://{host}/did-witness.json"),
            source_kind: SourceKind::Watcher,
        }];
        assert!(matches!(
            WebvhResolver
                .resolve_via_sources(
                    DID,
                    &fetcher,
                    &sources,
                    &TransportPolicy::default(),
                    Freshness::default()
                )
                .await,
            Err(ResolutionError::NetworkUnavailable(_))
        ));
    }

    for address in [
        "0.0.0.0",
        "127.0.0.1",
        "10.0.0.1",
        "169.254.1.1",
        "192.0.2.1",
        "198.51.100.1",
        "203.0.113.1",
        "::",
        "::1",
        "fc00::1",
        "fe80::1",
        "2001:db8::1",
        "ff02::1",
    ] {
        let input = fixture();
        let fetcher = StubFetcher {
            result: Ok(FetchedEvidence {
                raw_log: input.raw_log,
                raw_witnesses: None,
                observed_at: input.observed_at,
                resolved_addresses: vec![address.parse().unwrap()],
                content_length: None,
                complete: true,
            }),
        };
        assert!(
            matches!(
                WebvhResolver
                    .resolve_via(
                        DID,
                        &fetcher,
                        &TransportPolicy::default(),
                        Freshness::default()
                    )
                    .await,
                Err(ResolutionError::SourcesExhausted { attempts })
                    if attempts.len() == 1
                        && attempts.iter().all(|attempt| matches!(
                            attempt.outcome,
                            SourceAttemptOutcome::DownloadRejected(
                                DownloadFailureKind::DisallowedResolvedAddress
                            )
                        ))
            ),
            "disallowed address accepted: {address}"
        );
    }
}

async fn assert_download_fallback(
    invalid: FetchedEvidence,
    expected: DownloadFailureKind,
    policy: TransportPolicy,
) {
    let input = fixture();
    let fetcher = ScriptedFetcher::new([Ok(invalid), Ok(downloaded(input.raw_log.clone()))]);
    let sources = [
        source("invalid", SourceKind::RemoteResolver),
        source("valid", SourceKind::DirectHttps),
    ];
    let output = WebvhResolver
        .resolve_via_sources(DID, &fetcher, &sources, &policy, Freshness::default())
        .await
        .unwrap();
    fetcher.assert_exhausted();
    assert_calls(&fetcher, &sources, &[0, 1]);
    assert_eq!(output.metadata.version_number, 1);
    assert_eq!(output.evidence.source_uri, sources[1].log_url);
    assert_eq!(output.evidence.source_kind, sources[1].source_kind);
    assert_eq!(output.evidence.raw_log, input.raw_log);
    assert_eq!(output.evidence.source_attempts.len(), 2);
    assert_attempt(
        &output.evidence.source_attempts[0],
        &sources[0],
        0,
        1,
        SourceAttemptPhase::DownloadValidation,
        SourceAttemptOutcome::DownloadRejected(expected),
        false,
    );
    assert_attempt(
        &output.evidence.source_attempts[1],
        &sources[1],
        1,
        1,
        SourceAttemptPhase::LocalMethodVerification,
        SourceAttemptOutcome::LocallyVerified,
        true,
    );
}

#[tokio::test]
async fn partial_download_falls_back_to_valid_alternate() {
    let mut invalid = downloaded(fixture().raw_log);
    invalid.complete = false;
    assert_download_fallback(
        invalid,
        DownloadFailureKind::Incomplete,
        TransportPolicy::default(),
    )
    .await;
}

#[tokio::test]
async fn content_length_mismatch_falls_back_to_valid_alternate() {
    let mut invalid = downloaded(fixture().raw_log);
    invalid.content_length = Some(invalid.raw_log.len() + 1);
    assert_download_fallback(
        invalid,
        DownloadFailureKind::DeclaredLengthMismatch,
        TransportPolicy::default(),
    )
    .await;
}

#[tokio::test]
async fn oversized_download_falls_back_to_valid_alternate() {
    let input = fixture();
    let policy = TransportPolicy {
        max_response_bytes: input.raw_log.len(),
        ..TransportPolicy::default()
    };
    let mut invalid = downloaded(format!("{}x", input.raw_log));
    invalid.content_length = Some(invalid.raw_log.len());
    assert_download_fallback(invalid, DownloadFailureKind::LogTooLarge, policy).await;
}

#[tokio::test]
async fn oversized_witness_falls_back_to_valid_alternate() {
    let mut invalid = downloaded(fixture().raw_log);
    invalid.raw_witnesses = Some("w".repeat(200 * 1024 + 1));
    assert_download_fallback(
        invalid,
        DownloadFailureKind::WitnessTooLarge,
        TransportPolicy::default(),
    )
    .await;
}

#[tokio::test]
async fn oversized_combined_evidence_falls_back_to_valid_alternate() {
    let mut invalid = downloaded("l".repeat(180_000));
    invalid.raw_witnesses = Some("w".repeat(130_000));
    assert_download_fallback(
        invalid,
        DownloadFailureKind::CombinedEvidenceTooLarge,
        TransportPolicy::default(),
    )
    .await;
}

#[tokio::test]
async fn missing_required_addresses_falls_back_to_valid_alternate() {
    let mut invalid = downloaded(fixture().raw_log);
    invalid.resolved_addresses.clear();
    let policy = TransportPolicy {
        require_resolved_addresses: true,
        ..TransportPolicy::default()
    };
    assert_download_fallback(
        invalid,
        DownloadFailureKind::MissingResolvedAddresses,
        policy,
    )
    .await;
}

#[tokio::test]
async fn disallowed_resolved_address_falls_back_to_valid_alternate() {
    for addresses in [
        vec!["127.0.0.1"],
        vec!["10.0.0.1"],
        vec!["169.254.1.1"],
        vec!["0.0.0.0"],
        vec!["192.0.2.1"],
        vec!["93.184.216.34", "::1"],
        vec!["::"],
        vec!["fc00::1"],
        vec!["fe80::1"],
        vec!["2001:db8::1"],
    ] {
        let mut invalid = downloaded(fixture().raw_log);
        invalid.resolved_addresses = addresses
            .into_iter()
            .map(|address| address.parse().unwrap())
            .collect();
        assert_download_fallback(
            invalid,
            DownloadFailureKind::DisallowedResolvedAddress,
            TransportPolicy::default(),
        )
        .await;
    }
}

#[tokio::test]
async fn missing_content_length_complete_body_is_accepted() {
    let input = fixture();
    let mut evidence = downloaded(input.raw_log);
    evidence.content_length = None;
    let fetcher = CountingFetcher {
        calls: Cell::new(0),
        result: Ok(evidence),
    };
    let output = WebvhResolver
        .resolve_via(
            DID,
            &fetcher,
            &TransportPolicy::default(),
            Freshness::default(),
        )
        .await
        .unwrap();
    assert_eq!(fetcher.calls.get(), 1);
    assert_eq!(output.evidence.source_attempts.len(), 1);
    assert!(matches!(
        output.evidence.source_attempts[0].outcome,
        SourceAttemptOutcome::LocallyVerified
    ));
}

#[tokio::test]
async fn all_transport_failures_return_complete_attempt_provenance() {
    let fetcher = ScriptedFetcher::new([
        Err(FetchError::Dns),
        Err(FetchError::Timeout),
        Err(FetchError::Tls),
        Err(FetchError::Cors),
    ]);
    let sources = [
        source("one", SourceKind::Watcher),
        source("two", SourceKind::DirectHttps),
    ];
    let error = WebvhResolver
        .resolve_via_sources(
            DID,
            &fetcher,
            &sources,
            &TransportPolicy::default(),
            Freshness::default(),
        )
        .await
        .unwrap_err();
    fetcher.assert_exhausted();
    assert_calls(&fetcher, &sources, &[0, 0, 1, 1]);
    let attempts = error.source_attempts();
    assert_eq!(attempts.len(), 4);
    for (index, attempt_number, outcome) in [
        (0, 1, TransportFailureKind::Dns),
        (0, 2, TransportFailureKind::Timeout),
        (1, 1, TransportFailureKind::Tls),
        (1, 2, TransportFailureKind::Cors),
    ] {
        let attempt = &attempts[usize::from(attempt_number - 1) + index * 2];
        assert_attempt(
            attempt,
            &sources[index],
            index,
            attempt_number,
            SourceAttemptPhase::Transport,
            SourceAttemptOutcome::TransportRejected(outcome),
            false,
        );
    }
    assert!(matches!(error, ResolutionError::SourcesExhausted { .. }));
    assert!(!error.to_string().contains("did.jsonl"));
}

#[tokio::test]
async fn all_invalid_downloads_return_complete_attempt_provenance() {
    let input = fixture();
    let mut partial = downloaded(input.raw_log.clone());
    partial.complete = false;
    let mut mismatch = downloaded(input.raw_log);
    mismatch.content_length = Some(mismatch.raw_log.len() + 1);
    let fetcher = ScriptedFetcher::new([Ok(partial), Ok(mismatch)]);
    let sources = [
        source("partial", SourceKind::RemoteResolver),
        source("mismatch", SourceKind::Watcher),
    ];
    let policy = TransportPolicy {
        retries: 2,
        ..TransportPolicy::default()
    };
    let error = WebvhResolver
        .resolve_via_sources(DID, &fetcher, &sources, &policy, Freshness::default())
        .await
        .unwrap_err();
    fetcher.assert_exhausted();
    assert_calls(&fetcher, &sources, &[0, 1]);
    assert_eq!(error.source_attempts().len(), 2);
    assert_attempt(
        &error.source_attempts()[0],
        &sources[0],
        0,
        1,
        SourceAttemptPhase::DownloadValidation,
        SourceAttemptOutcome::DownloadRejected(DownloadFailureKind::Incomplete),
        false,
    );
    assert_attempt(
        &error.source_attempts()[1],
        &sources[1],
        1,
        1,
        SourceAttemptPhase::DownloadValidation,
        SourceAttemptOutcome::DownloadRejected(DownloadFailureKind::DeclaredLengthMismatch),
        false,
    );
    assert!(matches!(error, ResolutionError::SourcesExhausted { .. }));
}

#[tokio::test]
async fn all_locally_invalid_histories_return_complete_attempt_provenance() {
    let input = fixture();
    let invalid_one = input.raw_log.replacen("z2gbCNg9", "z2gbCNh9", 1);
    let invalid_two = input.raw_log.replacen("z2gbCNg9", "z2gbCNi9", 1);
    let fetcher = ScriptedFetcher::new([Ok(downloaded(invalid_one)), Ok(downloaded(invalid_two))]);
    let sources = [
        source("invalid-one", SourceKind::RemoteResolver),
        source("invalid-two", SourceKind::Watcher),
    ];
    let policy = TransportPolicy {
        retries: 0,
        ..TransportPolicy::default()
    };
    let error = WebvhResolver
        .resolve_via_sources(DID, &fetcher, &sources, &policy, Freshness::default())
        .await
        .unwrap_err();
    fetcher.assert_exhausted();
    assert_calls(&fetcher, &sources, &[0, 1]);
    assert_eq!(error.source_attempts().len(), 2);
    for (index, attempt) in error.source_attempts().iter().enumerate() {
        assert_eq!(attempt.source_index, index);
        assert_eq!(attempt.attempt_number, 1);
        assert_eq!(attempt.phase, SourceAttemptPhase::LocalMethodVerification);
        assert!(matches!(
            attempt.outcome,
            SourceAttemptOutcome::LocalMethodRejected(_)
        ));
        assert!(!attempt.locally_verified);
    }
    assert!(matches!(error, ResolutionError::SourcesExhausted { .. }));
}

#[tokio::test]
async fn mixed_failures_return_ordered_complete_attempt_provenance() {
    let input = fixture();
    let mut partial = downloaded(input.raw_log.clone());
    partial.complete = false;
    let malicious = input.raw_log.replacen("z2gbCNg9", "z2gbCNh9", 1);
    let fetcher =
        ScriptedFetcher::new([Err(FetchError::Dns), Ok(partial), Ok(downloaded(malicious))]);
    let sources = [
        source("transport", SourceKind::DirectHttps),
        source("download", SourceKind::Watcher),
        source("method", SourceKind::RemoteResolver),
    ];
    let policy = TransportPolicy {
        retries: 0,
        ..TransportPolicy::default()
    };
    let error = WebvhResolver
        .resolve_via_sources(DID, &fetcher, &sources, &policy, Freshness::default())
        .await
        .unwrap_err();
    fetcher.assert_exhausted();
    assert_calls(&fetcher, &sources, &[0, 1, 2]);
    let attempts = error.source_attempts();
    assert_eq!(attempts.len(), 3);
    assert!(matches!(
        attempts[0].outcome,
        SourceAttemptOutcome::TransportRejected(TransportFailureKind::Dns)
    ));
    assert!(matches!(
        attempts[1].outcome,
        SourceAttemptOutcome::DownloadRejected(DownloadFailureKind::Incomplete)
    ));
    assert!(matches!(
        attempts[2].outcome,
        SourceAttemptOutcome::LocalMethodRejected(_)
    ));
    assert_eq!(
        attempts
            .iter()
            .map(|attempt| attempt.source_index)
            .collect::<Vec<_>>(),
        vec![0, 1, 2]
    );
    assert!(matches!(error, ResolutionError::SourcesExhausted { .. }));
    assert!(!error.to_string().contains("proofValue"));
}

#[tokio::test]
async fn invalid_later_source_is_preflight_rejected_before_traffic() {
    let fetcher = CountingFetcher {
        calls: Cell::new(0),
        result: Err(FetchError::Unavailable),
    };
    let sources = [
        source("valid", SourceKind::Watcher),
        EvidenceSource {
            log_url: "http://invalid.example/did.jsonl".into(),
            witness_url: "https://invalid.example/did-witness.json".into(),
            source_kind: SourceKind::Watcher,
        },
    ];
    let error = WebvhResolver
        .resolve_via_sources(
            DID,
            &fetcher,
            &sources,
            &TransportPolicy::default(),
            Freshness::default(),
        )
        .await
        .unwrap_err();
    assert!(matches!(error, ResolutionError::NetworkUnavailable(_)));
    assert!(error.source_attempts().is_empty());
    assert_eq!(fetcher.calls.get(), 0);
}

#[tokio::test]
async fn one_source_zero_retries_attempt_budget_is_exact() {
    let fetcher = ScriptedFetcher::new([Err(FetchError::Dns)]);
    let sources = [source("only", SourceKind::Watcher)];
    let policy = TransportPolicy {
        retries: 0,
        ..TransportPolicy::default()
    };
    let error = WebvhResolver
        .resolve_via_sources(DID, &fetcher, &sources, &policy, Freshness::default())
        .await
        .unwrap_err();
    fetcher.assert_exhausted();
    assert_eq!(fetcher.calls().len(), 1);
    assert_eq!(error.source_attempts().len(), 1);
    assert_eq!(error.source_attempts()[0].attempt_number, 1);
}

#[tokio::test]
async fn one_source_maximum_retries_attempt_budget_is_exact() {
    let fetcher = ScriptedFetcher::new([
        Err(FetchError::Dns),
        Err(FetchError::Timeout),
        Err(FetchError::Tls),
    ]);
    let sources = [source("only", SourceKind::Watcher)];
    let policy = TransportPolicy {
        retries: 2,
        ..TransportPolicy::default()
    };
    let error = WebvhResolver
        .resolve_via_sources(DID, &fetcher, &sources, &policy, Freshness::default())
        .await
        .unwrap_err();
    fetcher.assert_exhausted();
    assert_eq!(fetcher.calls().len(), 3);
    assert_eq!(error.source_attempts().len(), 3);
    assert_eq!(
        error
            .source_attempts()
            .iter()
            .map(|attempt| attempt.attempt_number)
            .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
}

#[tokio::test]
async fn last_permitted_attempt_can_succeed() {
    let input = fixture();
    let fetcher = ScriptedFetcher::new([
        Err(FetchError::Dns),
        Err(FetchError::Timeout),
        Err(FetchError::Tls),
        Err(FetchError::Cors),
        Err(FetchError::Unavailable),
        Ok(downloaded(input.raw_log)),
    ]);
    let sources = [
        source("one", SourceKind::Watcher),
        source("two", SourceKind::DirectHttps),
    ];
    let policy = TransportPolicy {
        retries: 2,
        ..TransportPolicy::default()
    };
    let output = WebvhResolver
        .resolve_via_sources(DID, &fetcher, &sources, &policy, Freshness::default())
        .await
        .unwrap();
    fetcher.assert_exhausted();
    assert_calls(&fetcher, &sources, &[0, 0, 0, 1, 1, 1]);
    assert!(fetcher.calls().iter().all(|call| call.policy == policy));
    assert_eq!(output.evidence.source_attempts.len(), 6);
    assert_eq!(output.evidence.source_uri, sources[1].log_url);
    assert_eq!(output.evidence.source_attempts[5].attempt_number, 3);
    assert!(output.evidence.source_attempts[5].locally_verified);
}

#[tokio::test]
async fn configuration_exceeding_total_attempt_budget_is_preflight_rejected() {
    let fetcher = CountingFetcher {
        calls: Cell::new(0),
        result: Err(FetchError::Unavailable),
    };
    let sources = [
        source("one", SourceKind::Watcher),
        source("two", SourceKind::Watcher),
        source("three", SourceKind::Watcher),
    ];
    let policy = TransportPolicy {
        retries: 2,
        ..TransportPolicy::default()
    };
    assert!(matches!(
        WebvhResolver
            .resolve_via_sources(DID, &fetcher, &sources, &policy, Freshness::default())
            .await,
        Err(ResolutionError::NetworkUnavailable(_))
    ));
    assert_eq!(fetcher.calls.get(), 0);
}

#[tokio::test]
async fn configuration_exceeding_total_timeout_budget_is_preflight_rejected() {
    let fetcher = CountingFetcher {
        calls: Cell::new(0),
        result: Err(FetchError::Unavailable),
    };
    let sources = [
        source("one", SourceKind::Watcher),
        source("two", SourceKind::Watcher),
    ];
    let policy = TransportPolicy {
        timeout_millis: 30_000,
        retries: 1,
        ..TransportPolicy::default()
    };
    let error = WebvhResolver
        .resolve_via_sources(DID, &fetcher, &sources, &policy, Freshness::default())
        .await
        .unwrap_err();
    assert!(matches!(error, ResolutionError::NetworkUnavailable(_)));
    assert!(error.source_attempts().is_empty());
    assert_eq!(fetcher.calls.get(), 0);
}

#[tokio::test]
async fn first_matching_verified_source_is_selected_deterministically() {
    let input = fixture();
    let fetcher = ScriptedFetcher::new([
        Ok(downloaded(input.raw_log.clone())),
        Ok(downloaded(input.raw_log)),
    ]);
    let sources = [
        source("first", SourceKind::Watcher),
        source("second", SourceKind::DirectHttps),
    ];
    let policy = TransportPolicy {
        retries: 0,
        ..TransportPolicy::default()
    };
    let output = WebvhResolver
        .resolve_via_sources(DID, &fetcher, &sources, &policy, Freshness::default())
        .await
        .unwrap();
    fetcher.assert_exhausted();
    assert_calls(&fetcher, &sources, &[0, 1]);
    assert_eq!(output.evidence.source_uri, sources[0].log_url);
    assert_eq!(output.evidence.source_kind, sources[0].source_kind);
    assert_eq!(output.evidence.source_attempts.len(), 2);
    assert!(
        output
            .evidence
            .source_attempts
            .iter()
            .all(|attempt| attempt.locally_verified)
    );
}

#[tokio::test]
async fn safe_transport_can_supply_untrusted_bytes_for_local_verification() {
    let input = fixture();
    let fetcher = CountingFetcher {
        calls: Cell::new(0),
        result: Ok(FetchedEvidence {
            raw_log: input.raw_log,
            raw_witnesses: None,
            observed_at: input.observed_at,
            resolved_addresses: vec!["93.184.216.34".parse().unwrap()],
            content_length: None,
            complete: true,
        }),
    };
    let output = WebvhResolver
        .resolve_via(
            DID,
            &fetcher,
            &TransportPolicy::default(),
            Freshness::default(),
        )
        .await
        .unwrap();
    assert_eq!(
        output.evidence.source_uri,
        "https://example.com/.well-known/did.jsonl"
    );
    assert_eq!(fetcher.calls.get(), 1);
}

#[tokio::test]
async fn rejects_unsafe_policy_and_transport_bound_violation() {
    let input = fixture();
    let fetcher = StubFetcher {
        result: Ok(FetchedEvidence {
            raw_log: input.raw_log,
            raw_witnesses: None,
            observed_at: input.observed_at,
            resolved_addresses: vec!["93.184.216.34".parse().unwrap()],
            content_length: None,
            complete: true,
        }),
    };
    let unsafe_policy = TransportPolicy {
        max_redirects: 1,
        ..TransportPolicy::default()
    };
    assert!(matches!(
        WebvhResolver
            .resolve_via(DID, &fetcher, &unsafe_policy, Freshness::default())
            .await,
        Err(ResolutionError::NetworkUnavailable(_))
    ));

    let tiny_policy = TransportPolicy {
        max_response_bytes: 10,
        ..TransportPolicy::default()
    };
    assert!(matches!(
        WebvhResolver
            .resolve_via(DID, &fetcher, &tiny_policy, Freshness::default())
            .await,
        Err(ResolutionError::SourcesExhausted { attempts })
            if attempts.len() == 1
                && matches!(
                    attempts[0].outcome,
                    SourceAttemptOutcome::DownloadRejected(DownloadFailureKind::LogTooLarge)
                )
    ));
}

#[tokio::test]
async fn deterministic_signature_mutations_never_resolve() {
    let base = fixture();
    let marker = base.raw_log.find("\"proofValue\":\"").unwrap() + "\"proofValue\":\"".len();
    for offset in 0..64 {
        let mut bytes = base.raw_log.as_bytes().to_vec();
        let index = marker + offset;
        bytes[index] = if bytes[index] == b'1' { b'2' } else { b'1' };
        let mut input = base.clone();
        input.raw_log = String::from_utf8(bytes).unwrap();
        assert!(
            WebvhResolver.resolve(input).await.is_err(),
            "signature mutation {offset} unexpectedly resolved"
        );
    }
}

#[tokio::test]
async fn deeply_nested_and_invalid_utf8_equivalent_json_fail_without_panic() {
    let mut nested = fixture();
    nested.raw_log = format!("{}0{}", "[".repeat(300), "]".repeat(300));
    assert!(WebvhResolver.resolve(nested).await.is_err());

    let mut invalid_escape = fixture();
    invalid_escape.raw_log = r#"{"parameters":{"method":"did:webvh:1.0"},"state":"\uD800"}"#.into();
    assert!(WebvhResolver.resolve(invalid_escape).await.is_err());
}

#[tokio::test]
async fn all_untrusted_envelope_fields_have_explicit_bounds() {
    let base = fixture();
    let mut cases = Vec::new();
    let mut did = base.clone();
    did.did = format!("did:webvh:{}", "a".repeat(2_100));
    cases.push(did);
    let mut source = base.clone();
    source.source_uri = "s".repeat(2_100);
    cases.push(source);
    let mut timestamp = base.clone();
    timestamp.observed_at = "t".repeat(65);
    cases.push(timestamp);
    let mut version_time = base.clone();
    version_time.raw_log =
        version_time
            .raw_log
            .replacen("2000-01-01T00:00:00Z", &"2".repeat(65), 1);
    cases.push(version_time);
    let mut long_string = base.clone();
    long_string.raw_log = long_string.raw_log.replacen(
        "\"authentication\"",
        &format!("\"{}\"", "x".repeat(16_385)),
        1,
    );
    cases.push(long_string);
    for input in cases {
        assert!(matches!(
            WebvhResolver.resolve(input).await,
            Err(ResolutionError::ResourceLimit(_))
        ));
    }
}

#[test]
fn deterministic_url_transformation_campaign_never_emits_an_unsafe_fetch() {
    const SEED: u64 = 0x524f_422d_3255_524c;
    let scid = "QmUy89VrfryQ254CeHZzQfmcKqByPoKNGqYykP3SeXuegQ";
    let tokens = [
        "..",
        "%2e%2e",
        "%2F",
        "%5c",
        "127.0.0.1",
        "[::1]",
        "localhost",
        "ｅxample.com",
        "example.com%3a443",
        "example.com#@127.0.0.1",
    ];
    let mut state = SEED;
    for case in 0..256usize {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let token = tokens[usize::try_from(state).unwrap_or(0) % tokens.len()];
        let did = format!("did:webvh:{scid}:{token}:segment-{case}");
        if let Ok((log, witness)) = WebvhResolver::evidence_urls(&did) {
            for url in [log, witness] {
                assert!(url.starts_with("https://"), "seed {SEED:#x}, case {case}");
                let lower = url.to_ascii_lowercase();
                let authority = lower
                    .trim_start_matches("https://")
                    .split('/')
                    .next()
                    .unwrap();
                assert_ne!(authority, "localhost");
                assert_ne!(authority, "127.0.0.1");
                assert!(!lower.contains("%2f"));
                assert!(!lower.contains("%5c"));
                assert!(!lower.contains("/../"), "unsafe transformed URL: {url}");
            }
        }
    }
}

#[tokio::test]
async fn repeated_json_keys_and_unknown_method_parameters_fail_closed() {
    let base = fixture();
    let mut repeated = base.clone();
    repeated.raw_log = repeated.raw_log.replacen(
        "\"versionId\":",
        "\"versionId\":\"1-QmAttacker\",\"versionId\":",
        1,
    );
    assert!(matches!(
        WebvhResolver.resolve(repeated).await,
        Err(ResolutionError::MalformedInput(message)) if message.contains("repeated JSON key")
    ));

    let mut unknown = base;
    unknown.raw_log =
        unknown
            .raw_log
            .replacen("\"method\":", "\"unreviewedOption\":true,\"method\":", 1);
    assert!(matches!(
        WebvhResolver.resolve(unknown).await,
        Err(ResolutionError::MalformedInput(message)) if message.contains("unknown did:webvh parameter")
    ));
}

#[tokio::test]
async fn independent_typescript_vectors_interoperate_across_lifecycle_features() {
    let cases = [
        (
            "did:webvh:QmUy89VrfryQ254CeHZzQfmcKqByPoKNGqYykP3SeXuegQ:example.com",
            include_str!("fixtures/basic-update/did.jsonl"),
            None,
            2,
        ),
        (
            "did:webvh:QmVo7guGd8Fq4vGmCTcAuZWBFw8ipW8HNoJ8g7XFKmP4bS:example.com",
            include_str!("fixtures/pre-rotation-consume/did.jsonl"),
            None,
            3,
        ),
        (
            "did:webvh:QmZTne7vT227kcwn27tt1rSPvPKy1iQs6SgJA8dhwJBnbS:example.com",
            include_str!("fixtures/witness-threshold/did.jsonl"),
            Some(include_str!("fixtures/witness-threshold/did-witness.json")),
            1,
        ),
    ];
    for (did, raw_log, raw_witnesses, expected_version) in cases {
        let mut input = fixture();
        input.did = did.into();
        input.raw_log = raw_log.into();
        input.raw_witnesses = raw_witnesses.map(Into::into);
        assert_eq!(
            WebvhResolver
                .resolve(input)
                .await
                .unwrap()
                .metadata
                .version_number,
            expected_version
        );
    }
}
