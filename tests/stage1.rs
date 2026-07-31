use robin_did_resolver_spike::{
    DidResolver, Freshness, ResolutionError, ResolutionInput, WebvhResolver,
};
use serde_json::Value;

fn fixture() -> ResolutionInput {
    serde_json::from_str(include_str!("fixtures/basic-create/input.json")).unwrap()
}

fn update_fixture() -> ResolutionInput {
    let mut input = fixture();
    input.raw_log = include_str!("fixtures/basic-update/did.jsonl").into();
    input.source_uri =
        "didwebvh-test-suite@f792ce4568c8c3efb3b6a055a1c2ba963dc00c35/vectors/basic-update/ts"
            .into();
    input
}

fn normalize_service_endpoint_slashes(mut document: Value) -> Value {
    if let Some(services) = document.get_mut("service").and_then(Value::as_array_mut) {
        for service in services {
            if let Some(endpoint) = service.get_mut("serviceEndpoint")
                && endpoint.as_str().is_some_and(|value| value.ends_with('/'))
            {
                *endpoint = Value::String(endpoint.as_str().unwrap().trim_end_matches('/').into());
            }
        }
    }
    document
}

#[tokio::test]
async fn resolves_authoritative_typescript_inception_and_returns_evidence() {
    let input = fixture();
    let expected_did = input.did.clone();
    let output = WebvhResolver.resolve(input).await.unwrap();

    assert_eq!(output.did_document()["id"], expected_did);
    assert_eq!(
        output.metadata.version_id,
        "1-QmRqMp6AtLbWzMyLa6ZdCjiQXo1HaLpUStJFwqAMY7pVfo"
    );
    assert_eq!(output.metadata.method_version, "did:webvh:1.0");
    assert!(output.metadata.complete_history_verified);
    assert_eq!(output.evidence.log_sha256.len(), 64);
    assert!(output.evidence.raw_log.ends_with('\n'));
    let expected: Value = serde_json::from_str(include_str!(
        "fixtures/basic-create/expected-did-document.json"
    ))
    .unwrap();
    assert_eq!(
        normalize_service_endpoint_slashes(output.did_document_copy()),
        normalize_service_endpoint_slashes(expected)
    );
}

#[tokio::test]
async fn rejects_altered_method_identifier_and_document_identifier() {
    let mut wrong_method = fixture();
    wrong_method.did = wrong_method.did.replacen("did:webvh:", "did:web:", 1);
    assert!(matches!(
        WebvhResolver.resolve(wrong_method).await,
        Err(ResolutionError::UnsupportedMethod(_))
    ));

    let mut wrong_document = fixture();
    wrong_document.raw_log = wrong_document.raw_log.replacen(
        ":example.com\",\"controller\"",
        ":attacker.example\",\"controller\"",
        1,
    );
    assert!(WebvhResolver.resolve(wrong_document).await.is_err());
}

#[tokio::test]
async fn rejects_unsupported_method_before_method_engine() {
    let mut input = fixture();
    input.did = "did:key:z6Mkh".into();
    assert_eq!(
        WebvhResolver.resolve(input).await.unwrap_err(),
        ResolutionError::UnsupportedMethod("key".into())
    );
}

#[tokio::test]
async fn rejects_unsupported_version_without_downgrade() {
    let mut input = fixture();
    input.raw_log = input.raw_log.replace("did:webvh:1.0", "did:webvh:99.0");
    assert_eq!(
        WebvhResolver.resolve(input).await.unwrap_err(),
        ResolutionError::UnsupportedVersion("did:webvh:99.0".into())
    );
}

#[tokio::test]
async fn rejects_malformed_json_with_typed_failure() {
    let mut input = fixture();
    input.raw_log = "{".into();
    assert!(matches!(
        WebvhResolver.resolve(input).await,
        Err(ResolutionError::MalformedInput(_))
    ));
}

#[tokio::test]
async fn rejects_altered_scid_and_inception_content() {
    for needle in [
        "QmUy89VrfryQ254CeHZzQfmcKqByPoKNGqYykP3SeXuegQ",
        "2000-01-01T00:00:00Z",
    ] {
        let mut input = fixture();
        input.raw_log = input.raw_log.replacen(needle, "QmBadState", 1);
        assert!(WebvhResolver.resolve(input).await.is_err());
    }
}

#[tokio::test]
async fn rejects_removed_or_wrong_authorization_proof() {
    let mut missing = fixture();
    let mut value: Value = serde_json::from_str(missing.raw_log.trim()).unwrap();
    value.as_object_mut().unwrap().remove("proof");
    missing.raw_log = format!("{}\n", serde_json::to_string(&value).unwrap());
    assert!(WebvhResolver.resolve(missing).await.is_err());

    let mut wrong = fixture();
    wrong.raw_log = wrong.raw_log.replace("z2gbCNg9", "z2gbCNh9");
    assert!(matches!(
        WebvhResolver.resolve(wrong).await,
        Err(ResolutionError::InvalidHistory(_) | ResolutionError::InvalidProof(_))
    ));
}

#[tokio::test]
async fn validates_complete_authorized_update_history() {
    let output = WebvhResolver.resolve(update_fixture()).await.unwrap();
    assert_eq!(output.metadata.version_number, 2);
    assert_eq!(
        output.metadata.version_id,
        "2-QmbcnNJZ7EvsbU9ogcsGdYrqKBH1YjVy5nEjs1rxznXxBe"
    );
    assert_eq!(
        output.did_document()["alsoKnownAs"][0],
        "did:web:example.com"
    );
}

#[tokio::test]
async fn rejects_skipped_duplicate_reordered_modified_or_unsigned_updates() {
    let base = update_fixture();
    let lines: Vec<String> = base.raw_log.lines().map(str::to_owned).collect();
    let mutations = [
        lines[1].clone(),
        format!("{}\n{}", lines[0], lines[0]),
        format!("{}\n{}", lines[1], lines[0]),
        format!(
            "{}\n{}",
            lines[0],
            lines[1].replace("did:web:example.com", "did:web:attacker.example")
        ),
        {
            let mut value: Value = serde_json::from_str(&lines[1]).unwrap();
            value.as_object_mut().unwrap().remove("proof");
            format!("{}\n{}", lines[0], serde_json::to_string(&value).unwrap())
        },
    ];
    for raw_log in mutations {
        let mut input = base.clone();
        input.raw_log = raw_log;
        assert!(
            WebvhResolver.resolve(input).await.is_err(),
            "mutation must fail"
        );
    }
}

#[tokio::test]
async fn rejects_non_monotonic_and_future_times() {
    for changed_time in ["2000-01-01T00:00:00Z", "2999-01-02T00:00:00Z"] {
        let mut input = update_fixture();
        input.raw_log = input
            .raw_log
            .replacen("2000-01-02T00:00:00Z", changed_time, 1);
        assert!(WebvhResolver.resolve(input).await.is_err());
    }
}

#[tokio::test]
async fn rejects_resource_exhaustion_envelopes() {
    let mut oversized = fixture();
    oversized.raw_log.push_str(&" ".repeat(210_000));
    assert!(matches!(
        WebvhResolver.resolve(oversized).await,
        Err(ResolutionError::ResourceLimit(_))
    ));

    let mut deep = fixture();
    let first = deep.raw_log.clone();
    deep.raw_log = first.repeat(1_025);
    assert!(matches!(
        WebvhResolver.resolve(deep).await,
        Err(ResolutionError::ResourceLimit(_))
    ));
}

#[tokio::test]
async fn detects_rollback_and_same_version_conflicts_from_cached_state() {
    let mut stale = fixture();
    stale.freshness = Freshness {
        known_version_id: Some("2-Qm11111111111111111111111111111111111111111111".into()),
        known_log_sha256: None,
        ..Freshness::default()
    };
    assert!(matches!(
        WebvhResolver.resolve(stale).await,
        Err(ResolutionError::StaleState(_))
    ));

    let mut conflict = fixture();
    conflict.freshness = Freshness {
        known_version_id: Some("1-Qm11111111111111111111111111111111111111111111".into()),
        known_log_sha256: None,
        ..Freshness::default()
    };
    assert!(matches!(
        WebvhResolver.resolve(conflict).await,
        Err(ResolutionError::Conflict(_))
    ));
}

#[tokio::test]
async fn cached_tip_requires_exact_prefix_before_accepting_an_extension() {
    let inception = WebvhResolver.resolve(fixture()).await.unwrap();
    let mut extension = update_fixture();
    extension.freshness = inception.freshness();
    let extended = WebvhResolver.resolve(extension).await.unwrap();
    assert_eq!(extended.metadata.version_number, 2);

    let mut stale_prefix = fixture();
    stale_prefix.freshness = extended.freshness();
    assert!(matches!(
        WebvhResolver.resolve(stale_prefix).await,
        Err(ResolutionError::StaleState(_))
    ));

    let mut higher_fork = fixture();
    higher_fork.did = "did:webvh:QmVo7guGd8Fq4vGmCTcAuZWBFw8ipW8HNoJ8g7XFKmP4bS:example.com".into();
    higher_fork.raw_log = include_str!("fixtures/pre-rotation-consume/did.jsonl").into();
    let mut simulated_cached_fork = extended.freshness();
    simulated_cached_fork.known_did = Some(higher_fork.did.clone());
    higher_fork.freshness = simulated_cached_fork;
    assert!(matches!(
        WebvhResolver.resolve(higher_fork).await,
        Err(ResolutionError::Conflict(_))
    ));
}

#[tokio::test]
async fn first_use_is_allowed_but_freshness_context_is_did_bound() {
    assert!(WebvhResolver.resolve(update_fixture()).await.is_ok());
    let cached = WebvhResolver.resolve(fixture()).await.unwrap();
    let mut wrong_did = update_fixture();
    wrong_did.freshness = cached.freshness();
    wrong_did.freshness.known_did = Some("did:webvh:other:example.com".into());
    assert!(matches!(
        WebvhResolver.resolve(wrong_did).await,
        Err(ResolutionError::Conflict(_))
    ));
}

#[tokio::test]
async fn complete_history_negative_matrix_rejects_transition_tampering() {
    let mut base = fixture();
    base.did = "did:webvh:QmVo7guGd8Fq4vGmCTcAuZWBFw8ipW8HNoJ8g7XFKmP4bS:example.com".into();
    base.raw_log = include_str!("fixtures/pre-rotation-consume/did.jsonl").into();
    let lines: Vec<String> = base.raw_log.lines().map(str::to_owned).collect();
    let foreign = update_fixture().raw_log.lines().nth(1).unwrap().to_owned();
    let cases = [
        (
            "valid-looking inserted entry",
            format!("{}\n{foreign}\n{}\n{}", lines[0], lines[1], lines[2]),
        ),
        (
            "removed middle entry",
            format!("{}\n{}", lines[0], lines[2]),
        ),
        (
            "duplicate entry",
            format!("{}\n{}\n{}\n{}", lines[0], lines[1], lines[1], lines[2]),
        ),
        (
            "reordered entries",
            format!("{}\n{}\n{}", lines[0], lines[2], lines[1]),
        ),
        (
            "duplicate version number",
            base.raw_log.replacen("3-QmRcx", "2-QmRcx", 1),
        ),
        (
            "duplicate version identifier",
            base.raw_log.replacen(
                "3-QmRcxKKNcQhYiktCShZWJkYbFikVfTkcSmtZSQwhaUhtYK",
                "2-QmT45hcbqr66W7uLPLqwy9QAoyxfi5HpmEemQfAntmjZWn",
                1,
            ),
        ),
        (
            "modified predecessor",
            base.raw_log.replacen("2-QmT45", "2-QmT46", 1),
        ),
        (
            "wrong authorized update key",
            base.raw_log.replacen("z6MknGc3ocHs3", "z6MknGc3ocHs4", 1),
        ),
        (
            "inserted state transition",
            base.raw_log.replacen(
                "\"authentication\":[",
                "\"alsoKnownAs\":[\"did:web:attacker.example\"],\"authentication\":[",
                1,
            ),
        ),
        (
            "removed state transition",
            base.raw_log
                .replacen("\"authentication\":[", "\"removedAuthentication\":[", 1),
        ),
    ];
    for (label, raw_log) in cases {
        let mut input = base.clone();
        input.raw_log = raw_log;
        assert!(
            WebvhResolver.resolve(input).await.is_err(),
            "accepted {label}"
        );
    }

    let full = WebvhResolver.resolve(base.clone()).await.unwrap();
    let mut removed_final = base;
    removed_final.raw_log = lines[..2].join("\n");
    removed_final.freshness = full.freshness();
    assert!(matches!(
        WebvhResolver.resolve(removed_final).await,
        Err(ResolutionError::StaleState(_))
    ));
}

#[tokio::test]
async fn deterministic_structured_mutation_campaign_rejects_256_cases() {
    const SEED: u64 = 0x524f_422d_3251_4153;
    let base = update_fixture();
    let mut state = SEED;
    for case in 0..256usize {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let mut bytes = base.raw_log.as_bytes().to_vec();
        let second = bytes.iter().position(|byte| *byte == b'\n').unwrap() + 1;
        let index = second + (usize::try_from(state).unwrap_or(0) % (bytes.len() - second - 1));
        bytes[index] = match bytes[index] {
            b'a'..=b'y' | b'A'..=b'Y' | b'0'..=b'8' => bytes[index] + 1,
            _ => b'!',
        };
        let mut input = base.clone();
        input.raw_log = String::from_utf8(bytes).unwrap();
        assert!(
            WebvhResolver.resolve(input).await.is_err(),
            "seed {SEED:#x}, case {case}"
        );
    }
}
