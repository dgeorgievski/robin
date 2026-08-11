use didwebvh_rs::create::{CreateDIDConfig, create_did};
use didwebvh_rs::prelude::{DIDWebVHState, KeyType, Parameters, Secret, generate_did_key};
use robin_did_resolver_spike::{
    DidResolver, Freshness, ResolutionError, ResolutionInput, ResolutionOutput, SourceKind,
    WebvhResolver,
};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const OPERATIONS: &[&str] = &[
    "inception",
    "authentication_add",
    "authentication_rotate",
    "authentication_remove",
    "key_agreement_add",
    "key_agreement_rotate",
    "key_agreement_remove",
    "device_add",
    "device_remove",
    "continuity_replacement",
    "prerotation_disable",
];

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicTransition {
    pub log: String,
    pub document: Value,
    pub version_id: String,
    pub version_number: u32,
    pub version_time: String,
    pub parameters: Value,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GeneratedLifecycle {
    pub did: String,
    pub transitions: BTreeMap<&'static str, PublicTransition>,
    pub deactivated_log: String,
}

struct UpdateMaterial {
    public: String,
    secret: Secret,
}

impl UpdateMaterial {
    fn generate() -> Self {
        let (_, secret) = generate_did_key(KeyType::Ed25519).expect("ephemeral update key");
        let public = secret
            .get_public_keymultibase()
            .expect("generated key has public multibase");
        Self { public, secret }
    }
}

fn ed25519_public() -> String {
    let (_, secret) = generate_did_key(KeyType::Ed25519).expect("ephemeral Ed25519 key");
    secret
        .get_public_keymultibase()
        .expect("generated key has public multibase")
}

fn x25519_public() -> String {
    let (_, secret) = generate_did_key(KeyType::X25519).expect("ephemeral X25519 key");
    secret
        .get_public_keymultibase()
        .expect("generated key has public multibase")
}

fn next_key_hash(public: &str) -> String {
    let digest = Sha256::digest(public.as_bytes());
    let mut multihash = Vec::with_capacity(34);
    multihash.extend_from_slice(&[0x12, 0x20]);
    multihash.extend_from_slice(&digest);
    multibase::encode(multibase::Base::Base58Btc, multihash)
        .strip_prefix('z')
        .expect("base58btc has z prefix")
        .to_owned()
}

fn parameters(update: &[String], next: &[String], portable: bool, deactivated: bool) -> Parameters {
    let mut builder = Parameters::new();
    builder
        .with_update_keys(update.to_vec())
        .with_next_key_hashes(next.to_vec())
        .with_portable(portable)
        .with_deactivated(deactivated);
    builder.build()
}

fn method(did: &str, fragment: &str, material: &str) -> Value {
    json!({
        "id": format!("{did}#{fragment}"),
        "type": "Multikey",
        "controller": did,
        "publicKeyMultibase": material
    })
}

fn document(did: &str, authentication: &[(&str, &str)], agreements: &[(&str, &str)]) -> Value {
    let mut verification_methods = Vec::new();
    let mut authentication_refs = Vec::new();
    let mut agreement_refs = Vec::new();
    for (fragment, material) in authentication {
        verification_methods.push(method(did, fragment, material));
        authentication_refs.push(Value::String(format!("{did}#{fragment}")));
    }
    for (fragment, material) in agreements {
        verification_methods.push(method(did, fragment, material));
        agreement_refs.push(Value::String(format!("{did}#{fragment}")));
    }
    json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/multikey/v1"
        ],
        "id": did,
        "controller": did,
        "verificationMethod": verification_methods,
        "authentication": authentication_refs,
        "keyAgreement": agreement_refs
    })
}

pub fn serialize_log(state: &DIDWebVHState) -> String {
    let mut raw = state
        .log_entries()
        .iter()
        .map(|entry| serde_json::to_string(&entry.log_entry).expect("public log serializes"))
        .collect::<Vec<_>>()
        .join("\n");
    raw.push('\n');
    raw
}

pub fn input(did: &str, raw_log: String) -> ResolutionInput {
    ResolutionInput {
        did: did.into(),
        raw_log,
        raw_witnesses: None,
        source_kind: SourceKind::ImportedPackage,
        source_uri: "ephemeral-memory://ROB-4/public-history".into(),
        observed_at: "2026-08-10T00:00:00Z".into(),
        freshness: Freshness::default(),
    }
}

async fn resolve(did: &str, state: &DIDWebVHState) -> ResolutionOutput {
    WebvhResolver
        .resolve(input(did, serialize_log(state)))
        .await
        .expect("generated lifecycle must resolve")
}

fn tip_parameters(raw_log: &str) -> Value {
    serde_json::from_str::<Value>(raw_log.lines().last().expect("history tip")).expect("tip parses")
        ["parameters"]
        .clone()
}

async fn record(
    lifecycle: &mut GeneratedLifecycle,
    operation: &'static str,
    state: &DIDWebVHState,
) {
    let output = resolve(&lifecycle.did, state).await;
    let log = serialize_log(state);
    lifecycle.transitions.insert(
        operation,
        PublicTransition {
            parameters: tip_parameters(&log),
            log,
            document: output.did_document_copy(),
            version_id: output.metadata.version_id,
            version_number: output.metadata.version_number,
            version_time: output.metadata.version_time,
        },
    );
}

async fn append(
    state: &mut DIDWebVHState,
    signer: &UpdateMaterial,
    next: Option<&UpdateMaterial>,
    document: &Value,
    timestamp: &str,
) {
    let next_hashes = next
        .map(|material| vec![next_key_hash(&material.public)])
        .unwrap_or_default();
    let params = parameters(
        std::slice::from_ref(&signer.public),
        &next_hashes,
        true,
        false,
    );
    state
        .create_log_entry(
            Some(timestamp.parse().expect("fixed timestamp")),
            document,
            &params,
            &signer.secret,
        )
        .await
        .expect("authorized lifecycle update");
}

#[allow(clippy::too_many_lines)]
pub async fn generate_lifecycle() -> GeneratedLifecycle {
    let updates: Vec<UpdateMaterial> = (0..12).map(|_| UpdateMaterial::generate()).collect();
    let auth_a = ed25519_public();
    let auth_b = ed25519_public();
    let auth_c = ed25519_public();
    let agreement_a = x25519_public();
    let agreement_b = x25519_public();
    let agreement_c = x25519_public();
    let device_auth = ed25519_public();
    let device_agreement = x25519_public();

    let genesis_document = document("{DID}", &[("auth-a1b2c3d4", &auth_a)], &[]);
    let genesis_parameters = parameters(
        std::slice::from_ref(&updates[0].public),
        &[next_key_hash(&updates[1].public)],
        true,
        false,
    );
    let created = create_did(
        CreateDIDConfig::builder()
            .address("https://example.com/")
            .authorization_key(updates[0].secret.clone())
            .did_document(genesis_document)
            .parameters(genesis_parameters)
            .version_time("2000-01-01T00:00:00Z".parse().expect("fixed timestamp"))
            .build()
            .expect("creation config"),
    )
    .await
    .expect("portable identity creation");
    let did = created.did().to_owned();
    let mut state = DIDWebVHState::from_log_entries(vec![created.log_entry().clone()]);
    state
        .validate()
        .expect("created history validates")
        .assert_complete()
        .expect("created history is complete");
    let mut lifecycle = GeneratedLifecycle {
        did: did.clone(),
        transitions: BTreeMap::new(),
        deactivated_log: String::new(),
    };
    record(&mut lifecycle, "inception", &state).await;

    let auth_add = document(
        &did,
        &[("auth-a1b2c3d4", &auth_a), ("auth-b2c3d4e5", &auth_b)],
        &[],
    );
    append(
        &mut state,
        &updates[1],
        Some(&updates[2]),
        &auth_add,
        "2000-01-02T00:00:00Z",
    )
    .await;
    record(&mut lifecycle, "authentication_add", &state).await;

    let auth_rotate = document(
        &did,
        &[("auth-b2c3d4e5", &auth_b), ("auth-c3d4e5f6", &auth_c)],
        &[],
    );
    append(
        &mut state,
        &updates[2],
        Some(&updates[3]),
        &auth_rotate,
        "2000-01-03T00:00:00Z",
    )
    .await;
    record(&mut lifecycle, "authentication_rotate", &state).await;

    let auth_remove = document(&did, &[("auth-c3d4e5f6", &auth_c)], &[]);
    append(
        &mut state,
        &updates[3],
        Some(&updates[4]),
        &auth_remove,
        "2000-01-04T00:00:00Z",
    )
    .await;
    record(&mut lifecycle, "authentication_remove", &state).await;

    let agreement_add = document(
        &did,
        &[("auth-c3d4e5f6", &auth_c)],
        &[("agreement-a1b2c3d4", &agreement_a)],
    );
    append(
        &mut state,
        &updates[4],
        Some(&updates[5]),
        &agreement_add,
        "2000-01-05T00:00:00Z",
    )
    .await;
    record(&mut lifecycle, "key_agreement_add", &state).await;

    let agreement_rotate = document(
        &did,
        &[("auth-c3d4e5f6", &auth_c)],
        &[("agreement-b2c3d4e5", &agreement_b)],
    );
    append(
        &mut state,
        &updates[5],
        Some(&updates[6]),
        &agreement_rotate,
        "2000-01-06T00:00:00Z",
    )
    .await;
    record(&mut lifecycle, "key_agreement_rotate", &state).await;

    let agreement_remove = document(&did, &[("auth-c3d4e5f6", &auth_c)], &[]);
    append(
        &mut state,
        &updates[6],
        Some(&updates[7]),
        &agreement_remove,
        "2000-01-07T00:00:00Z",
    )
    .await;
    record(&mut lifecycle, "key_agreement_remove", &state).await;

    let device_add = document(
        &did,
        &[
            ("auth-c3d4e5f6", &auth_c),
            ("device-a7c9e2f4", &device_auth),
        ],
        &[("agreement-a7c9e2f4", &device_agreement)],
    );
    append(
        &mut state,
        &updates[7],
        Some(&updates[8]),
        &device_add,
        "2000-01-08T00:00:00Z",
    )
    .await;
    record(&mut lifecycle, "device_add", &state).await;

    let device_remove = document(&did, &[("auth-c3d4e5f6", &auth_c)], &[]);
    append(
        &mut state,
        &updates[8],
        Some(&updates[9]),
        &device_remove,
        "2000-01-09T00:00:00Z",
    )
    .await;
    record(&mut lifecycle, "device_remove", &state).await;

    let continuity = document(
        &did,
        &[("auth-c3d4e5f6", &auth_c)],
        &[("agreement-c3d4e5f6", &agreement_c)],
    );
    append(
        &mut state,
        &updates[9],
        Some(&updates[10]),
        &continuity,
        "2000-01-10T00:00:00Z",
    )
    .await;
    record(&mut lifecycle, "continuity_replacement", &state).await;

    append(
        &mut state,
        &updates[10],
        None,
        &continuity,
        "2000-01-11T00:00:00Z",
    )
    .await;
    record(&mut lifecycle, "prerotation_disable", &state).await;

    let deactivate_parameters = parameters(&[], &[], true, true);
    state
        .create_log_entry(
            Some("2000-01-12T00:00:00Z".parse().expect("fixed timestamp")),
            &continuity,
            &deactivate_parameters,
            &updates[10].secret,
        )
        .await
        .expect("authorized deactivation");
    lifecycle.deactivated_log = serialize_log(&state);
    let result = WebvhResolver
        .resolve(input(&did, lifecycle.deactivated_log.clone()))
        .await;
    assert!(matches!(result, Err(ResolutionError::Deactivated(_))));
    export_public_evidence_if_requested(&lifecycle);
    lifecycle
}

fn export_public_evidence_if_requested(lifecycle: &GeneratedLifecycle) {
    let Ok(path) = std::env::var("ROB4_PUBLIC_EXPORT") else {
        return;
    };
    let bytes = serde_json::to_vec_pretty(lifecycle).expect("public lifecycle serializes");
    assert_no_private_material(std::str::from_utf8(&bytes).expect("public evidence is UTF-8"));
    std::fs::write(path, bytes).expect("write public lifecycle to caller-selected temporary path");
}

pub async fn generate_creation(
    portable: bool,
    include_incompatible_metadata: bool,
) -> ResolutionOutput {
    let update = UpdateMaterial::generate();
    let next = UpdateMaterial::generate();
    let auth = ed25519_public();
    let mut doc = document("{DID}", &[("auth-a1b2c3d4", &auth)], &[]);
    if include_incompatible_metadata {
        doc["service"] = json!([{
            "id": "{DID}#application-data",
            "type": "ApplicationMetadata",
            "serviceEndpoint": "https://application.example/data"
        }]);
    }
    let created = create_did(
        CreateDIDConfig::builder()
            .address("https://example.com/")
            .authorization_key(update.secret)
            .did_document(doc)
            .parameters(parameters(
                &[update.public],
                &[next_key_hash(&next.public)],
                portable,
                false,
            ))
            .version_time("2000-01-01T00:00:00Z".parse().expect("fixed timestamp"))
            .build()
            .expect("creation config"),
    )
    .await
    .expect("identity creation");
    let did = created.did().to_owned();
    let mut state = DIDWebVHState::from_log_entries(vec![created.log_entry().clone()]);
    state
        .validate()
        .expect("created history validates")
        .assert_complete()
        .expect("created history is complete");
    resolve(&did, &state).await
}

pub fn assert_no_private_material(value: &str) {
    for forbidden in [
        "secretKeyMultibase",
        "privateKeyJwk",
        "privateKeyMultibase",
        "recoverySecret",
        "seed",
    ] {
        assert!(
            !value.contains(forbidden),
            "public evidence contains {forbidden}"
        );
    }
}

pub fn replace_once(raw: &str, needle: &str, replacement: &str) -> String {
    assert!(raw.contains(needle), "mutation needle must select one case");
    raw.replacen(needle, replacement, 1)
}

pub fn line_count(raw: &str) -> usize {
    raw.lines().filter(|line| !line.trim().is_empty()).count()
}

pub fn public_key_ids(output: &ResolutionOutput, relationship: &str) -> Vec<String> {
    match output.authorized_keys(relationship) {
        Ok(keys) => keys,
        Err(ResolutionError::MissingRelationship(_)) => return Vec::new(),
        Err(error) => panic!("relationship selection failed: {error}"),
    }
    .into_iter()
    .map(|key| key.id)
    .collect()
}

pub fn multibase_values(output: &ResolutionOutput, relationship: &str) -> Vec<String> {
    match output.authorized_keys(relationship) {
        Ok(keys) => keys,
        Err(ResolutionError::MissingRelationship(_)) => return Vec::new(),
        Err(error) => panic!("relationship selection failed: {error}"),
    }
    .into_iter()
    .map(|key| {
        key.verification_method["publicKeyMultibase"]
            .as_str()
            .expect("selected Multikey")
            .to_owned()
    })
    .collect()
}

pub fn serialize_entries(entries: &[Value]) -> String {
    let mut raw = entries
        .iter()
        .map(|value| serde_json::to_string(value).expect("entry serializes"))
        .collect::<Vec<_>>()
        .join("\n");
    raw.push('\n');
    raw
}

pub fn parse_entries(raw: &str) -> Vec<Value> {
    raw.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("entry JSON"))
        .collect()
}
