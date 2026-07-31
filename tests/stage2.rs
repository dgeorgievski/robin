use robin_did_resolver_spike::{DidResolver, ResolutionError, ResolutionInput, WebvhResolver};
use serde_json::Value;

const DID_BASIC: &str = "did:webvh:QmUy89VrfryQ254CeHZzQfmcKqByPoKNGqYykP3SeXuegQ:example.com";
const DID_PREROTATION: &str =
    "did:webvh:QmVo7guGd8Fq4vGmCTcAuZWBFw8ipW8HNoJ8g7XFKmP4bS:example.com";
const DID_WITNESS: &str = "did:webvh:QmZTne7vT227kcwn27tt1rSPvPKy1iQs6SgJA8dhwJBnbS:example.com";

fn fixture() -> ResolutionInput {
    serde_json::from_str(include_str!("fixtures/basic-create/input.json")).unwrap()
}

fn with_log(did: &str, path: &str, raw_log: &str) -> ResolutionInput {
    let mut input = fixture();
    input.did = did.into();
    input.raw_log = raw_log.into();
    input.source_uri =
        format!("didwebvh-test-suite@f792ce4568c8c3efb3b6a055a1c2ba963dc00c35/{path}");
    input
}

#[tokio::test]
async fn selects_only_keys_cryptographically_bound_to_verified_state() {
    let output = WebvhResolver.resolve(fixture()).await.unwrap();
    let authentication = output.authorized_keys("authentication").unwrap();
    assert_eq!(authentication.len(), 1);
    assert!(authentication[0].id.ends_with("#P5RDjVJG"));

    let agreement_id = format!("{DID_BASIC}#agreement-1");
    let mut presentation = output.did_document_copy();
    presentation
        .get_mut("verificationMethod")
        .and_then(Value::as_array_mut)
        .unwrap()
        .push(serde_json::json!({
            "id": agreement_id,
            "type": "Multikey",
            "controller": DID_BASIC,
            "publicKeyMultibase": "z6LSkeyAgreementEvidenceOnly"
        }));
    presentation["keyAgreement"] = serde_json::json!([agreement_id]);
    assert!(output.did_document().get("keyAgreement").is_none());
    assert!(matches!(
        output.authorized_keys("keyAgreement"),
        Err(ResolutionError::MissingRelationship(_))
    ));
    assert!(matches!(
        output.authorized_keys("assertionMethod"),
        Err(ResolutionError::MissingRelationship(_))
    ));
}

#[tokio::test]
async fn rejects_dangling_or_malformed_relationship_entries() {
    let output = WebvhResolver.resolve(fixture()).await.unwrap();
    let mut detached = output.did_document_copy();
    detached["authentication"] = serde_json::json!(["#missing", 7]);
    assert_eq!(output.authorized_keys("authentication").unwrap().len(), 1);
}

#[tokio::test]
async fn verifies_pre_rotation_commitment_and_multiple_rotations() {
    let inception = with_log(
        DID_PREROTATION,
        "vectors/pre-rotation/ts",
        include_str!("fixtures/pre-rotation/did.jsonl"),
    );
    assert_eq!(
        WebvhResolver
            .resolve(inception)
            .await
            .unwrap()
            .metadata
            .version_number,
        1
    );

    let history = with_log(
        DID_PREROTATION,
        "vectors/pre-rotation-consume/ts",
        include_str!("fixtures/pre-rotation-consume/did.jsonl"),
    );
    assert_eq!(
        WebvhResolver
            .resolve(history)
            .await
            .unwrap()
            .metadata
            .version_number,
        3
    );
}

#[tokio::test]
async fn rejects_wrong_or_omitted_pre_rotation_reveal() {
    let base = with_log(
        DID_PREROTATION,
        "vectors/pre-rotation-consume/ts",
        include_str!("fixtures/pre-rotation-consume/did.jsonl"),
    );
    let mut wrong = base.clone();
    wrong.raw_log = wrong.raw_log.replacen(
        "z6MknGc3ocHs3zdPiJbnaaqDi58NGb4pk1Sp9WxWufuXSdxf",
        "z6MkWrongReveal",
        1,
    );
    assert!(WebvhResolver.resolve(wrong).await.is_err());

    let mut omitted = base;
    let lines: Vec<&str> = omitted.raw_log.lines().collect();
    let mut second: Value = serde_json::from_str(lines[1]).unwrap();
    second["parameters"]
        .as_object_mut()
        .unwrap()
        .remove("updateKeys");
    omitted.raw_log = format!(
        "{}\n{}\n{}",
        lines[0],
        serde_json::to_string(&second).unwrap(),
        lines[2]
    );
    assert!(WebvhResolver.resolve(omitted).await.is_err());
}

#[tokio::test]
async fn compromised_current_key_cannot_bypass_prior_commitment() {
    let input = with_log(
        "did:webvh:QmXpqXh9uM1rN2uBuHQB4qdGUMfJsEouwz8Yn8RaaTXgKq:example.com",
        "vectors/negative-pre-rotation-omit-updatekeys/ts",
        include_str!("fixtures/pre-rotation-compromised-current-key/did.jsonl"),
    );
    assert!(matches!(
        WebvhResolver.resolve(input).await,
        Err(ResolutionError::InvalidHistory(_) | ResolutionError::InvalidProof(_))
    ));
}

#[tokio::test]
async fn malformed_reused_and_missing_next_commitments_fail_closed() {
    let base = with_log(
        DID_PREROTATION,
        "vectors/pre-rotation-consume/ts",
        include_str!("fixtures/pre-rotation-consume/did.jsonl"),
    );
    for raw_log in [
        base.raw_log.replacen(
            "QmdP2WQEBfT4vht72FZ2p2X7airS3FxmaGuoHgHQoDW1u9",
            "malformed",
            1,
        ),
        base.raw_log.replacen(
            "QmdP2WQEBfT4vht72FZ2p2X7airS3FxmaGuoHgHQoDW1u9",
            "Qmf2V5jB2UwPcFL5bvmKed7VvY3CSQ1RXyDdtip7ufpQ3R",
            1,
        ),
        base.raw_log.replacen(
            "\"nextKeyHashes\":[\"QmdP2WQEBfT4vht72FZ2p2X7airS3FxmaGuoHgHQoDW1u9\"],",
            "",
            1,
        ),
    ] {
        let mut input = base.clone();
        input.raw_log = raw_log;
        assert!(WebvhResolver.resolve(input).await.is_err());
    }
}

fn witness_fixture() -> ResolutionInput {
    let mut input = with_log(
        DID_WITNESS,
        "vectors/witness-threshold/ts",
        include_str!("fixtures/witness-threshold/did.jsonl"),
    );
    input.raw_witnesses = Some(include_str!("fixtures/witness-threshold/did-witness.json").into());
    input
}

#[tokio::test]
async fn verifies_witness_proof_and_rejects_missing_or_bad_threshold_evidence() {
    assert_eq!(
        WebvhResolver
            .resolve(witness_fixture())
            .await
            .unwrap()
            .metadata
            .version_number,
        1
    );

    let mut missing = witness_fixture();
    missing.raw_witnesses = None;
    assert!(matches!(
        WebvhResolver.resolve(missing).await,
        Err(ResolutionError::InvalidWitness(_))
    ));

    let mut wrong_key = witness_fixture();
    wrong_key.raw_witnesses = wrong_key
        .raw_witnesses
        .map(|value| value.replace("z6Mkrv5Cm2XCLum", "z6Mkrv5Cm2XCLun"));
    assert!(matches!(
        WebvhResolver.resolve(wrong_key).await,
        Err(ResolutionError::InvalidWitness(_))
    ));
}

#[tokio::test]
async fn rejects_witness_replay_signature_tamper_and_body_fragment_mismatch() {
    let replacements = [
        (
            "1-QmVfm3PzDU95EkjbuFCj9T7znnrgE5sW2v2uT5gQ347gZK",
            "2-QmVfm3PzDU95EkjbuFCj9T7znnrgE5sW2v2uT5gQ347gZK",
        ),
        ("z2gPgyPS2JvQ", "z2gPgyPS2JvR"),
        (
            "#z6Mkrv5Cm2XCLumMPTqooLTCw6YDf421d7VdTziwrZ8vNf4L",
            "#z6Mkrv5Cm2XCLumMPTqooLTCw6YDf421d7VdTziwrZ8vNf4M",
        ),
    ];
    for (from, to) in replacements {
        let mut input = witness_fixture();
        input.raw_witnesses = input.raw_witnesses.map(|value| value.replacen(from, to, 1));
        assert!(WebvhResolver.resolve(input).await.is_err());
    }
}

#[tokio::test]
async fn duplicate_witness_proof_is_a_typed_profile_failure() {
    let mut input = witness_fixture();
    let mut witness: Value = serde_json::from_str(input.raw_witnesses.as_deref().unwrap()).unwrap();
    let proof = witness[0]["proof"][0].clone();
    witness[0]["proof"].as_array_mut().unwrap().push(proof);
    input.raw_witnesses = Some(serde_json::to_string(&witness).unwrap());
    assert!(matches!(
        WebvhResolver.resolve(input).await,
        Err(ResolutionError::InvalidWitness(message)) if message.contains("duplicate witness proof")
    ));
}

fn witness_update_fixture() -> ResolutionInput {
    let mut input = with_log(
        "did:webvh:QmR72NXg5DyrNL1PXwk4kiZEJxS1RJxvFEtSu9wPSZkp1u:example.com",
        "vectors/witness-update/ts",
        include_str!("fixtures/witness-update/did.jsonl"),
    );
    input.raw_witnesses = Some(include_str!("fixtures/witness-update/did-witness.json").into());
    input
}

#[tokio::test]
async fn witness_threshold_two_of_two_and_negative_matrix_are_enforced() {
    let base = witness_update_fixture();
    assert_eq!(
        WebvhResolver
            .resolve(base.clone())
            .await
            .unwrap()
            .metadata
            .version_number,
        2
    );

    let witness: Value = serde_json::from_str(base.raw_witnesses.as_deref().unwrap()).unwrap();
    let cases = [
        ("insufficient subset", {
            let mut value = witness.clone();
            value[0]["proof"].as_array_mut().unwrap().pop();
            value
        }),
        ("duplicate witness identity", {
            let mut value = witness.clone();
            value[0]["proof"][1]["verificationMethod"] =
                value[0]["proof"][0]["verificationMethod"].clone();
            value
        }),
        ("unsupported proof type", {
            let mut value = witness.clone();
            value[0]["proof"][0]["type"] = Value::String("UnsupportedProof".into());
            value
        }),
        ("forged proof", {
            let mut value = witness.clone();
            value[0]["proof"][0]["proofValue"] = Value::String("zForged".into());
            value
        }),
    ];
    for (label, value) in cases {
        let mut input = base.clone();
        input.raw_witnesses = Some(serde_json::to_string(&value).unwrap());
        assert!(
            WebvhResolver.resolve(input).await.is_err(),
            "accepted {label}"
        );
    }
}

#[tokio::test]
async fn malformed_zero_impossible_and_duplicate_witness_configuration_fail() {
    let base = witness_fixture();
    for raw_log in [
        base.raw_log.replacen("\"threshold\":1", "\"threshold\":0", 1),
        base.raw_log.replacen("\"threshold\":1", "\"threshold\":2", 1),
        base.raw_log.replacen(
            "]},\"deactivated\"",
            ",{\"id\":\"did:key:z6Mkrv5Cm2XCLumMPTqooLTCw6YDf421d7VdTziwrZ8vNf4L\"}]},\"deactivated\"",
            1,
        ),
    ] {
        let mut input = base.clone();
        input.raw_log = raw_log;
        assert!(WebvhResolver.resolve(input).await.is_err());
    }
}

#[tokio::test]
async fn deactivation_is_a_fail_closed_typed_result() {
    let input = with_log(
        DID_BASIC,
        "vectors/deactivate/ts",
        include_str!("fixtures/deactivate/did.jsonl"),
    );
    let error = WebvhResolver.resolve(input).await.unwrap_err();
    let ResolutionError::Deactivated(tip) = error else {
        panic!("expected typed deactivation")
    };
    assert_eq!(tip.version_number, 2);
    assert!(tip.deactivated);
}

#[tokio::test]
async fn deactivation_is_irreversible_against_appends_and_stale_restore() {
    let deactivation = with_log(
        DID_BASIC,
        "vectors/deactivate/ts",
        include_str!("fixtures/deactivate/did.jsonl"),
    );
    let ResolutionError::Deactivated(tip) = WebvhResolver
        .resolve(deactivation.clone())
        .await
        .unwrap_err()
    else {
        panic!("expected typed deactivation")
    };
    let freshness = robin_did_resolver_spike::Freshness {
        known_did: Some(DID_BASIC.into()),
        known_version_id: Some(tip.version_id.clone()),
        known_log_sha256: None,
        known_history_prefix_sha256: Some(tip.history_prefix_sha256.clone()),
        known_deactivated: true,
    };

    let mut stale = fixture();
    stale.freshness = freshness.clone();
    assert!(matches!(
        WebvhResolver.resolve(stale).await,
        Err(ResolutionError::StaleState(_))
    ));

    let mut appended = deactivation;
    let update = include_str!("fixtures/basic-update/did.jsonl")
        .lines()
        .nth(1)
        .unwrap();
    appended
        .raw_log
        .push_str(&update.replacen("2-Qmbcn", "3-Qmbcn", 1));
    appended.freshness = freshness;
    assert!(WebvhResolver.resolve(appended).await.is_err());
}
