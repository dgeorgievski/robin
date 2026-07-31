use async_trait::async_trait;
use robin_did_resolver_spike::{
    DidResolver, EvidenceFetcher, EvidenceSource, FetchError, FetchedEvidence, Freshness,
    ResolutionError, ResolutionInput, SourceKind, TransportPolicy, WebvhResolver,
};
use std::cell::RefCell;
use std::collections::VecDeque;

const DID: &str = "did:webvh:QmUy89VrfryQ254CeHZzQfmcKqByPoKNGqYykP3SeXuegQ:example.com";

fn fixture() -> ResolutionInput {
    serde_json::from_str(include_str!("fixtures/basic-create/input.json")).unwrap()
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
    for error in [
        FetchError::Dns,
        FetchError::Tls,
        FetchError::Cors,
        FetchError::Timeout,
        FetchError::Http(404),
        FetchError::Http(500),
        FetchError::Redirect,
        FetchError::TooLarge,
        FetchError::Unavailable,
        FetchError::DnsRebinding,
        FetchError::Truncated,
        FetchError::SlowStream,
    ] {
        let fetcher = StubFetcher { result: Err(error) };
        assert!(matches!(
            WebvhResolver
                .resolve_via(
                    DID,
                    &fetcher,
                    &TransportPolicy::default(),
                    Freshness::default()
                )
                .await,
            Err(ResolutionError::NetworkUnavailable(_))
        ));
    }
}

struct ScriptedFetcher {
    results: RefCell<VecDeque<Result<FetchedEvidence, FetchError>>>,
}

#[async_trait(?Send)]
impl EvidenceFetcher for ScriptedFetcher {
    async fn fetch(
        &self,
        _log_url: &str,
        _witness_url: &str,
        _policy: &TransportPolicy,
    ) -> Result<FetchedEvidence, FetchError> {
        self.results.borrow_mut().pop_front().unwrap()
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

#[tokio::test]
async fn bounded_source_fallback_records_every_attempt() {
    let input = fixture();
    let fetcher = ScriptedFetcher {
        results: RefCell::new(VecDeque::from([
            Err(FetchError::Dns),
            Err(FetchError::Timeout),
            Ok(downloaded(input.raw_log)),
        ])),
    };
    let sources = [
        EvidenceSource {
            log_url: "https://unavailable.example/did.jsonl".into(),
            witness_url: "https://unavailable.example/did-witness.json".into(),
            source_kind: SourceKind::Watcher,
        },
        EvidenceSource {
            log_url: "https://alternate.example/did.jsonl".into(),
            witness_url: "https://alternate.example/did-witness.json".into(),
            source_kind: SourceKind::Watcher,
        },
    ];
    let policy = TransportPolicy::default();
    let output = WebvhResolver
        .resolve_via_sources(DID, &fetcher, &sources, &policy, Freshness::default())
        .await
        .unwrap();
    assert_eq!(output.evidence.source_attempts.len(), 3);
    assert!(output.evidence.source_attempts[0].outcome.contains("DNS"));
    assert_eq!(output.evidence.source_uri, sources[1].log_url);
}

#[tokio::test]
async fn conflicting_locally_valid_sources_fail_closed() {
    let fetcher = ScriptedFetcher {
        results: RefCell::new(VecDeque::from([
            Ok(downloaded(
                include_str!("fixtures/basic-update/did.jsonl").into(),
            )),
            Ok(downloaded(
                include_str!("fixtures/key-rotation/did.jsonl").into(),
            )),
        ])),
    };
    let sources = [
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
    ];
    let policy = TransportPolicy {
        retries: 0,
        ..TransportPolicy::default()
    };
    assert!(matches!(
        WebvhResolver
            .resolve_via_sources(DID, &fetcher, &sources, &policy, Freshness::default())
            .await,
        Err(ResolutionError::Conflict(_))
    ));
}

#[tokio::test]
async fn malicious_remote_assertion_is_rejected_before_valid_alternate() {
    let input = fixture();
    let malicious = input.raw_log.replacen("z2gbCNg9", "z2gbCNh9", 1);
    let fetcher = ScriptedFetcher {
        results: RefCell::new(VecDeque::from([
            Ok(downloaded(malicious)),
            Ok(downloaded(input.raw_log)),
        ])),
    };
    let sources = [
        EvidenceSource {
            log_url: "https://resolver.example/did.jsonl".into(),
            witness_url: "https://resolver.example/did-witness.json".into(),
            source_kind: SourceKind::RemoteResolver,
        },
        EvidenceSource {
            log_url: "https://direct.example/did.jsonl".into(),
            witness_url: "https://direct.example/did-witness.json".into(),
            source_kind: SourceKind::DirectHttps,
        },
    ];
    let policy = TransportPolicy {
        retries: 0,
        ..TransportPolicy::default()
    };
    let output = WebvhResolver
        .resolve_via_sources(DID, &fetcher, &sources, &policy, Freshness::default())
        .await
        .unwrap();
    assert!(
        output.evidence.source_attempts[0]
            .outcome
            .contains("locally rejected")
    );
    assert_eq!(output.evidence.source_uri, sources[1].log_url);
}

#[tokio::test]
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
                Err(ResolutionError::NetworkUnavailable(_))
            ),
            "disallowed address accepted: {address}"
        );
    }
}

#[tokio::test]
async fn partial_length_mismatch_and_missing_native_addresses_fail_closed() {
    let input = fixture();
    let mut partial = downloaded(input.raw_log.clone());
    partial.complete = false;
    let mut mismatched = downloaded(input.raw_log.clone());
    mismatched.content_length = Some(mismatched.raw_log.len() + 1);
    for evidence in [partial, mismatched] {
        let fetcher = StubFetcher {
            result: Ok(evidence),
        };
        assert!(
            WebvhResolver
                .resolve_via(
                    DID,
                    &fetcher,
                    &TransportPolicy::default(),
                    Freshness::default()
                )
                .await
                .is_err()
        );
    }
    let mut missing = downloaded(input.raw_log);
    missing.resolved_addresses.clear();
    let fetcher = StubFetcher {
        result: Ok(missing),
    };
    let policy = TransportPolicy {
        require_resolved_addresses: true,
        ..TransportPolicy::default()
    };
    assert!(
        WebvhResolver
            .resolve_via(DID, &fetcher, &policy, Freshness::default())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn safe_transport_can_supply_untrusted_bytes_for_local_verification() {
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
        Err(ResolutionError::ResourceLimit(_))
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
