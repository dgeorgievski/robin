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

#[tokio::test]
async fn resolves_authoritative_typescript_inception_and_returns_evidence() {
    let input = fixture();
    let expected_did = input.did.clone();
    let output = WebvhResolver.resolve(input).await.unwrap();

    assert_eq!(output.did_document["id"], expected_did);
    assert_eq!(
        output.metadata.version_id,
        "1-QmRqMp6AtLbWzMyLa6ZdCjiQXo1HaLpUStJFwqAMY7pVfo"
    );
    assert_eq!(output.metadata.method_version, "did:webvh:1.0");
    assert!(output.metadata.complete_history_verified);
    assert_eq!(output.evidence.log_sha256.len(), 64);
    assert!(output.evidence.raw_log.ends_with('\n'));
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
    assert_eq!(output.did_document["alsoKnownAs"][0], "did:web:example.com");
}

#[tokio::test]
async fn rejects_skipped_duplicate_reordered_modified_or_unsigned_updates() {
    let base = update_fixture();
    let lines: Vec<&str> = base.raw_log.lines().collect();
    let mutations = [
        lines[1].to_owned(),
        format!("{}\n{}", lines[0], lines[0]),
        format!("{}\n{}", lines[1], lines[0]),
        format!(
            "{}\n{}",
            lines[0],
            lines[1].replace("did:web:example.com", "did:web:attacker.example")
        ),
        {
            let mut value: Value = serde_json::from_str(lines[1]).unwrap();
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
    };
    assert!(matches!(
        WebvhResolver.resolve(stale).await,
        Err(ResolutionError::StaleState(_))
    ));

    let mut conflict = fixture();
    conflict.freshness = Freshness {
        known_version_id: Some("1-Qm11111111111111111111111111111111111111111111".into()),
        known_log_sha256: None,
    };
    assert!(matches!(
        WebvhResolver.resolve(conflict).await,
        Err(ResolutionError::Conflict(_))
    ));
}
