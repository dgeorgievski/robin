mod support;

use robin_did_resolver_spike::{
    CompleteHistoryManifest, CompleteImportError, DidResolver, DiffClassification, Freshness,
    LifecycleProfileError, LifecycleSnapshot, ResolutionError, WebvhResolver,
    compare_lifecycle_snapshots, import_complete_history, validate_robin_creation_profile,
};
use serde_json::{Value, json};
use support::rob4_lifecycle::{
    OPERATIONS, assert_no_private_material, generate_creation, generate_lifecycle, input,
    line_count, multibase_values, parse_entries, public_key_ids, replace_once, serialize_entries,
};

const INDEPENDENT_DID: &str =
    "did:webvh:QmVo7guGd8Fq4vGmCTcAuZWBFw8ipW8HNoJ8g7XFKmP4bS:example.com";

#[tokio::test]
async fn robin_creation_is_portable_prerotated_private_and_metadata_minimal() {
    let output = generate_creation(true, false).await;
    validate_robin_creation_profile(&output).unwrap();
    assert_eq!(output.metadata.method_version, "did:webvh:1.0");
    assert_no_private_material(&output.evidence.raw_log);

    let non_portable = generate_creation(false, false).await;
    assert_eq!(
        validate_robin_creation_profile(&non_portable),
        Err(LifecycleProfileError::NonPortableCreation)
    );

    let metadata_incompatible = generate_creation(true, true).await;
    assert_eq!(
        validate_robin_creation_profile(&metadata_incompatible),
        Err(LifecycleProfileError::MetadataPolicy)
    );
}

#[tokio::test]
async fn complete_independent_history_import_verifies_every_transition() {
    let raw = include_str!("fixtures/pre-rotation-consume/did.jsonl");
    let manifest = CompleteHistoryManifest {
        expected_version_id: "3-QmRcxKKNcQhYiktCShZWJkYbFikVfTkcSmtZSQwhaUhtYK".into(),
        expected_entry_count: 3,
    };
    let output = import_complete_history(input(INDEPENDENT_DID, raw.into()), &manifest)
        .await
        .unwrap();
    assert_eq!(output.metadata.version_number, 3);
    assert!(output.metadata.complete_history_verified);
    assert_eq!(line_count(&output.evidence.raw_log), 3);
    assert_no_private_material(&output.evidence.raw_log);

    let lines: Vec<&str> = raw.lines().collect();
    let cases = [
        ("truncated history", lines[..2].join("\n")),
        ("missing entry", [lines[0], lines[2]].join("\n")),
        ("reordered entry", [lines[0], lines[2], lines[1]].join("\n")),
        (
            "modified entry",
            replace_once(raw, "2000-01-03T00:00:00Z", "2000-01-04T00:00:00Z"),
        ),
        ("incomplete import", lines[1..].join("\n")),
    ];
    for (name, mutated) in cases {
        let result = import_complete_history(input(INDEPENDENT_DID, mutated), &manifest).await;
        assert!(result.is_err(), "accepted {name}");
        assert!(matches!(
            result,
            Err(CompleteImportError::Incomplete | CompleteImportError::Verification(_))
        ));
    }
}

#[tokio::test]
async fn authorized_relationship_lifecycles_select_only_current_role_keys() {
    let lifecycle = generate_lifecycle().await;
    for operation in OPERATIONS {
        assert!(
            lifecycle.transitions.contains_key(operation),
            "missing {operation}"
        );
    }

    let auth_add = &lifecycle.transitions["authentication_add"];
    let output = WebvhResolver
        .resolve(input(&lifecycle.did, auth_add.log.clone()))
        .await
        .unwrap();
    assert_eq!(public_key_ids(&output, "authentication").len(), 2);
    assert!(multibase_values(&output, "keyAgreement").is_empty());

    let auth_rotate = &lifecycle.transitions["authentication_rotate"];
    let output = WebvhResolver
        .resolve(input(&lifecycle.did, auth_rotate.log.clone()))
        .await
        .unwrap();
    let ids = public_key_ids(&output, "authentication");
    assert_eq!(ids.len(), 2);
    assert!(ids.iter().all(|id| !id.ends_with("#auth-a1b2c3d4")));

    let auth_remove = &lifecycle.transitions["authentication_remove"];
    let output = WebvhResolver
        .resolve(input(&lifecycle.did, auth_remove.log.clone()))
        .await
        .unwrap();
    assert_eq!(public_key_ids(&output, "authentication").len(), 1);

    let agreement_add = &lifecycle.transitions["key_agreement_add"];
    let output = WebvhResolver
        .resolve(input(&lifecycle.did, agreement_add.log.clone()))
        .await
        .unwrap();
    assert_eq!(multibase_values(&output, "keyAgreement").len(), 1);
    assert_eq!(public_key_ids(&output, "authentication").len(), 1);

    let agreement_rotate = &lifecycle.transitions["key_agreement_rotate"];
    let output = WebvhResolver
        .resolve(input(&lifecycle.did, agreement_rotate.log.clone()))
        .await
        .unwrap();
    let ids = public_key_ids(&output, "keyAgreement");
    assert_eq!(ids.len(), 1);
    assert!(ids[0].ends_with("#agreement-b2c3d4e5"));

    let agreement_remove = &lifecycle.transitions["key_agreement_remove"];
    let output = WebvhResolver
        .resolve(input(&lifecycle.did, agreement_remove.log.clone()))
        .await
        .unwrap();
    assert!(multibase_values(&output, "keyAgreement").is_empty());
    assert_eq!(public_key_ids(&output, "authentication").len(), 1);
}

#[tokio::test]
async fn prerotation_commitment_is_consumed_and_replenished_until_explicit_teardown() {
    let lifecycle = generate_lifecycle().await;
    for operation in &OPERATIONS[..OPERATIONS.len() - 1] {
        let transition = &lifecycle.transitions[operation];
        let next = transition.parameters["nextKeyHashes"]
            .as_array()
            .expect("pre-rotation hash array");
        assert_eq!(next.len(), 1, "{operation} did not replenish commitment");
        assert_eq!(
            transition.parameters["updateKeys"]
                .as_array()
                .expect("update keys")
                .len(),
            1
        );
    }
    assert_eq!(
        lifecycle.transitions["prerotation_disable"].parameters["nextKeyHashes"],
        json!([])
    );

    let mut missing = parse_entries(&lifecycle.transitions["authentication_add"].log);
    missing[1]
        .get_mut("parameters")
        .and_then(Value::as_object_mut)
        .unwrap()
        .remove("updateKeys");
    assert!(
        WebvhResolver
            .resolve(input(&lifecycle.did, serialize_entries(&missing)))
            .await
            .is_err()
    );

    let mut mismatched = parse_entries(&lifecycle.transitions["authentication_add"].log);
    mismatched[1]["parameters"]["updateKeys"][0] = Value::String("z6MkMismatch".into());
    assert!(
        WebvhResolver
            .resolve(input(&lifecycle.did, serialize_entries(&mismatched)))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn opaque_device_representation_adds_and_removes_only_selected_material() {
    let lifecycle = generate_lifecycle().await;
    let added = WebvhResolver
        .resolve(input(
            &lifecycle.did,
            lifecycle.transitions["device_add"].log.clone(),
        ))
        .await
        .unwrap();
    let auth_ids = public_key_ids(&added, "authentication");
    let agreement_ids = public_key_ids(&added, "keyAgreement");
    assert!(auth_ids.iter().any(|id| id.ends_with("#device-a7c9e2f4")));
    assert!(
        agreement_ids
            .iter()
            .any(|id| id.ends_with("#agreement-a7c9e2f4"))
    );
    let public = serde_json::to_string(added.did_document()).unwrap();
    assert!(!public.contains("deviceName"));
    assert!(!public.contains("applicationId"));
    assert!(!public.contains("email"));

    let removed = WebvhResolver
        .resolve(input(
            &lifecycle.did,
            lifecycle.transitions["device_remove"].log.clone(),
        ))
        .await
        .unwrap();
    let auth_ids = public_key_ids(&removed, "authentication");
    assert_eq!(auth_ids.len(), 1);
    assert!(auth_ids[0].ends_with("#auth-c3d4e5f6"));
    assert!(public_key_ids(&removed, "keyAgreement").is_empty());
}

#[tokio::test]
async fn deactivation_is_terminal_and_exposes_no_authorized_state() {
    let lifecycle = generate_lifecycle().await;
    let result = WebvhResolver
        .resolve(input(&lifecycle.did, lifecycle.deactivated_log.clone()))
        .await;
    let Err(ResolutionError::Deactivated(tip)) = result else {
        panic!("expected typed deactivation")
    };
    assert!(tip.deactivated);

    let active = &lifecycle.transitions["prerotation_disable"];
    let mut stale = input(&lifecycle.did, active.log.clone());
    stale.freshness = Freshness {
        known_did: Some(lifecycle.did.clone()),
        known_version_id: Some(tip.version_id.clone()),
        known_history_prefix_sha256: Some(tip.history_prefix_sha256.clone()),
        known_deactivated: true,
        ..Freshness::default()
    };
    assert!(matches!(
        WebvhResolver.resolve(stale).await,
        Err(ResolutionError::StaleState(_))
    ));

    let mut appended = lifecycle.deactivated_log;
    appended.push_str(active.log.lines().last().expect("active public entry"));
    assert!(
        WebvhResolver
            .resolve(input(&lifecycle.did, appended))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn method_continuity_requires_committed_replacement_not_current_key_bypass() {
    let lifecycle = generate_lifecycle().await;
    let continuity = &lifecycle.transitions["continuity_replacement"];
    let output = WebvhResolver
        .resolve(input(&lifecycle.did, continuity.log.clone()))
        .await
        .unwrap();
    assert_eq!(output.metadata.version_number, 10);
    assert_eq!(public_key_ids(&output, "authentication").len(), 1);
    assert_eq!(public_key_ids(&output, "keyAgreement").len(), 1);

    let mut uncommitted = parse_entries(&continuity.log);
    let replacement = uncommitted[9]["parameters"]["updateKeys"][0].clone();
    uncommitted[8]["parameters"]["nextKeyHashes"] = json!([]);
    uncommitted[9]["parameters"]["updateKeys"] = json!([replacement]);
    assert!(
        WebvhResolver
            .resolve(input(&lifecycle.did, serialize_entries(&uncommitted)))
            .await
            .is_err()
    );
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn deterministic_adversarial_lifecycle_matrix_fails_closed_without_sensitive_diagnostics() {
    const SEED: u64 = 0x524f_422d_344c_4946;
    let lifecycle = generate_lifecycle().await;
    let full = lifecycle.transitions["continuity_replacement"].log.clone();
    let entries = parse_entries(&full);
    let mut cases: Vec<(&str, String)> = Vec::new();

    let mut wrong_update = entries.clone();
    wrong_update[1]["proof"][0]["verificationMethod"] =
        Value::String("did:key:z6MkWrong#z6MkWrong".into());
    cases.push(("wrong update key", serialize_entries(&wrong_update)));

    let mut removed_key = entries.clone();
    removed_key[3]["state"]["authentication"] = removed_key[1]["state"]["authentication"].clone();
    cases.push(("removed/revoked key", serialize_entries(&removed_key)));

    let mut wrong_relationship = entries.clone();
    wrong_relationship[5]["state"]["authentication"] =
        wrong_relationship[5]["state"]["keyAgreement"].clone();
    cases.push((
        "wrong verification relationship",
        serialize_entries(&wrong_relationship),
    ));

    let mut missing_reveal = entries.clone();
    missing_reveal[1]["parameters"]
        .as_object_mut()
        .unwrap()
        .remove("updateKeys");
    cases.push((
        "missing pre-rotation reveal",
        serialize_entries(&missing_reveal),
    ));

    let mut mismatched_reveal = entries.clone();
    mismatched_reveal[1]["parameters"]["updateKeys"] = json!(["z6MkMismatch"]);
    cases.push((
        "mismatched pre-rotation reveal",
        serialize_entries(&mismatched_reveal),
    ));

    let mut reused = entries.clone();
    reused[2]["parameters"]["nextKeyHashes"] = reused[0]["parameters"]["nextKeyHashes"].clone();
    cases.push(("invalid commitment reuse", serialize_entries(&reused)));

    let mut skipped = entries.clone();
    skipped.remove(4);
    cases.push(("skipped update", serialize_entries(&skipped)));

    let mut reordered = entries.clone();
    reordered.swap(4, 5);
    cases.push(("reordered update", serialize_entries(&reordered)));

    let mut conflicting = entries.clone();
    conflicting[7]["state"]["controller"] = Value::String("did:webvh:conflict:example.com".into());
    cases.push(("conflicting history", serialize_entries(&conflicting)));

    let mut retained = entries.clone();
    retained[8]["state"] = retained[7]["state"].clone();
    cases.push((
        "incorrect device-key retention",
        serialize_entries(&retained),
    ));

    let mut removed_other = entries.clone();
    removed_other[8]["state"]["authentication"] = json!([]);
    cases.push((
        "incorrect device-key removal",
        serialize_entries(&removed_other),
    ));

    let mut modified = entries.clone();
    modified[6]["versionTime"] = Value::String("2000-01-07T00:00:01Z".into());
    cases.push(("modified import", serialize_entries(&modified)));

    let mut compromised = entries.clone();
    compromised[1]["parameters"]["updateKeys"] = compromised[0]["parameters"]["updateKeys"].clone();
    cases.push((
        "compromised-current successor selection",
        serialize_entries(&compromised),
    ));

    let mut invalid_version = entries.clone();
    invalid_version[2]["versionId"] = Value::String("99-QmInvalid".into());
    cases.push(("invalid version", serialize_entries(&invalid_version)));

    let mut invalid_time = entries.clone();
    invalid_time[2]["versionTime"] = invalid_time[1]["versionTime"].clone();
    cases.push(("invalid time", serialize_entries(&invalid_time)));

    let mut unauthorized = entries.clone();
    unauthorized[4]["state"]["alsoKnownAs"] = json!(["did:web:attacker.example"]);
    cases.push((
        "unauthorized state mutation",
        serialize_entries(&unauthorized),
    ));

    assert_eq!(cases.len(), 16, "seed {SEED:#x}");
    for (name, raw) in cases {
        let error = WebvhResolver
            .resolve(input(&lifecycle.did, raw))
            .await
            .expect_err(name);
        let diagnostic = error.to_string();
        assert_no_private_material(&diagnostic);
        assert!(diagnostic.len() < 1_024, "unbounded diagnostic for {name}");
    }

    let import_manifest = CompleteHistoryManifest {
        expected_version_id: entries[9]["versionId"]
            .as_str()
            .expect("full public tip")
            .to_owned(),
        expected_entry_count: 10,
    };
    assert_eq!(
        import_complete_history(
            input(&lifecycle.did, serialize_entries(&entries[..9])),
            &import_manifest,
        )
        .await
        .unwrap_err(),
        CompleteImportError::Incomplete,
        "incomplete import"
    );

    let verified = WebvhResolver
        .resolve(input(&lifecycle.did, full.clone()))
        .await
        .unwrap();
    let mut stale = input(&lifecycle.did, serialize_entries(&entries[..9]));
    stale.freshness = verified.freshness();
    assert!(matches!(
        WebvhResolver.resolve(stale).await,
        Err(ResolutionError::StaleState(_))
    ));

    let mut after_deactivation = lifecycle.deactivated_log;
    after_deactivation.push_str(entries.last().unwrap().to_string().as_str());
    assert!(
        WebvhResolver
            .resolve(input(&lifecycle.did, after_deactivation))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn complete_snapshot_comparison_separates_byte_and_semantic_results() {
    let lifecycle = generate_lifecycle().await;
    let transition = &lifecycle.transitions["authentication_add"];
    let mut output = WebvhResolver
        .resolve(input(&lifecycle.did, transition.log.clone()))
        .await
        .unwrap();
    let left = LifecycleSnapshot::from_verified(&output).unwrap();
    output.evidence.raw_log = "{\"parameters\":{\"portable\":false}}\n".into();
    assert_eq!(
        LifecycleSnapshot::from_verified(&output)
            .unwrap()
            .method_parameters,
        left.method_parameters,
        "caller-visible evidence mutation changed verified lifecycle parameters"
    );
    assert_eq!(left.did_document, transition.document);
    assert_eq!(left.version_id, transition.version_id);
    assert_eq!(left.version_number, transition.version_number);
    assert_eq!(left.version_time, transition.version_time);
    let right = left.clone();
    let identical = compare_lifecycle_snapshots(&left, &right).unwrap();
    assert!(identical.byte_match);
    assert!(identical.semantic_match);
    assert_eq!(identical.classification, None);

    let mut different = left;
    different.version_time = "2000-01-02T00:00:01Z".into();
    let comparison = compare_lifecycle_snapshots(&different, &right).unwrap();
    assert!(!comparison.byte_match);
    assert!(!comparison.semantic_match);
    assert_eq!(comparison.classification, None);
    assert_ne!(
        comparison.classification,
        Some(DiffClassification::EquivalentRepresentation)
    );
}
