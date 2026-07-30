use robin_did_resolver_spike::{DidResolver, ResolutionError, ResolutionInput, WebvhResolver};
use serde_json::{Value, json};

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
async fn selects_only_keys_in_the_requested_relationship() {
    let mut output = WebvhResolver.resolve(fixture()).await.unwrap();
    let authentication = output.authorized_keys("authentication").unwrap();
    assert_eq!(authentication.len(), 1);
    assert!(authentication[0].id.ends_with("#P5RDjVJG"));

    let agreement_id = format!("{DID_BASIC}#agreement-1");
    output
        .did_document
        .get_mut("verificationMethod")
        .and_then(Value::as_array_mut)
        .unwrap()
        .push(json!({
            "id": agreement_id,
            "type": "Multikey",
            "controller": DID_BASIC,
            "publicKeyMultibase": "z6LSkeyAgreementEvidenceOnly"
        }));
    output.did_document["keyAgreement"] = json!([agreement_id]);

    let agreement = output.authorized_keys("keyAgreement").unwrap();
    assert_eq!(agreement.len(), 1);
    assert!(agreement[0].id.ends_with("#agreement-1"));
    assert_ne!(authentication[0].id, agreement[0].id);

    output.did_document["keyAgreement"] = json!([authentication[0].id]);
    assert_eq!(
        output.authorized_keys("keyAgreement").unwrap()[0].id,
        authentication[0].id
    );
    assert!(matches!(
        output.authorized_keys("assertionMethod"),
        Err(ResolutionError::MissingRelationship(_))
    ));
}

#[tokio::test]
async fn rejects_dangling_or_malformed_relationship_entries() {
    let mut output = WebvhResolver.resolve(fixture()).await.unwrap();
    output.did_document["authentication"] = json!(["#missing"]);
    assert!(matches!(
        output.authorized_keys("authentication"),
        Err(ResolutionError::MissingRelationship(_))
    ));

    output.did_document["authentication"] = json!([7]);
    assert!(matches!(
        output.authorized_keys("authentication"),
        Err(ResolutionError::MalformedInput(_))
    ));
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
async fn duplicate_witness_proof_does_not_change_distinct_threshold_result() {
    let mut input = witness_fixture();
    let mut witness: Value = serde_json::from_str(input.raw_witnesses.as_deref().unwrap()).unwrap();
    let proof = witness[0]["proof"][0].clone();
    witness[0]["proof"].as_array_mut().unwrap().push(proof);
    input.raw_witnesses = Some(serde_json::to_string(&witness).unwrap());
    assert!(WebvhResolver.resolve(input).await.is_ok());
}

#[tokio::test]
async fn deactivation_is_a_fail_closed_typed_result() {
    let input = with_log(
        DID_BASIC,
        "vectors/deactivate/ts",
        include_str!("fixtures/deactivate/did.jsonl"),
    );
    assert_eq!(
        WebvhResolver.resolve(input).await.unwrap_err(),
        ResolutionError::Deactivated
    );
}
