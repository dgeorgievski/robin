use async_trait::async_trait;
use robin_did_resolver_spike::{
    DidResolver, EvidenceFetcher, FetchError, FetchedEvidence, Freshness, ResolutionError,
    ResolutionInput, TransportPolicy, WebvhResolver,
};

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

#[tokio::test]
async fn safe_transport_can_supply_untrusted_bytes_for_local_verification() {
    let input = fixture();
    let fetcher = StubFetcher {
        result: Ok(FetchedEvidence {
            raw_log: input.raw_log,
            raw_witnesses: None,
            observed_at: input.observed_at,
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
