//! ROB-4 lifecycle-profile and comparison helpers.
//!
//! These helpers operate only after local `did:webvh` verification. They do
//! not sign updates, hold private material, or make a remote implementation's
//! interpretation authoritative.

use crate::{DidResolver, ResolutionError, ResolutionInput, ResolutionOutput, WebvhResolver};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;

/// Exact classification vocabulary required by ROB-4.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiffClassification {
    /// Different serialization of the same normalized value.
    #[serde(rename = "EQUIVALENT REPRESENTATION")]
    EquivalentRepresentation,
    /// A difference permitted by the pinned method specification.
    #[serde(rename = "SPEC-PERMITTED DIFFERENCE")]
    SpecPermittedDifference,
    /// A behavior believed to be an implementation defect.
    #[serde(rename = "IMPLEMENTATION DEFECT")]
    ImplementationDefect,
    /// A difference for which the specification does not provide one answer.
    #[serde(rename = "SPECIFICATION AMBIGUITY")]
    SpecificationAmbiguity,
    /// A direction or field the compared implementation does not support.
    #[serde(rename = "UNSUPPORTED CAPABILITY")]
    UnsupportedCapability,
}

/// Method and method-neutral state compared after one lifecycle transition.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LifecycleSnapshot {
    pub did_document: Value,
    pub method_version: String,
    pub version_id: String,
    pub version_number: u32,
    pub version_time: String,
    pub method_parameters: Value,
    pub deactivated: bool,
}

impl LifecycleSnapshot {
    /// Build a snapshot only from Robin's locally verified output and the
    /// exact verified log tip retained with it.
    ///
    /// # Errors
    ///
    /// Returns a typed profile error if the retained tip cannot be parsed or
    /// does not contain an object-valued parameters block.
    pub fn from_verified(output: &ResolutionOutput) -> Result<Self, LifecycleProfileError> {
        let parameters = output.method_parameters_copy();
        if !parameters.is_object() {
            return Err(LifecycleProfileError::MalformedParameters);
        }
        Ok(Self {
            did_document: output.did_document_copy(),
            method_version: output.metadata.method_version.clone(),
            version_id: output.metadata.version_id.clone(),
            version_number: output.metadata.version_number,
            version_time: output.metadata.version_time.clone(),
            method_parameters: parameters,
            deactivated: output.metadata.deactivated,
        })
    }
}

/// Byte-level and semantic comparison result for a transition.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LifecycleComparison {
    pub byte_match: bool,
    pub semantic_match: bool,
    /// Classification is populated only when the helper can establish exact
    /// semantic equivalence. Security-relevant semantic differences require
    /// explicit evidence-ledger classification by the caller.
    pub classification: Option<DiffClassification>,
}

/// Public completeness commitment supplied alongside an imported history.
///
/// A valid `did:webvh` prefix is independently resolvable, so completeness
/// cannot be inferred from JSONL bytes alone. Import packages must commit to
/// their expected terminal version and entry count.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompleteHistoryManifest {
    pub expected_version_id: String,
    pub expected_entry_count: usize,
}

/// Typed complete-import failure with no accepted output on error.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CompleteImportError {
    #[error("complete-history manifest is malformed")]
    MalformedManifest,
    #[error("imported history is incomplete")]
    Incomplete,
    #[error("imported history failed local method verification")]
    Verification(#[source] ResolutionError),
}

/// Verify an import against its public completeness manifest before exposing
/// any accepted current state.
///
/// # Errors
///
/// Returns a typed failure for a malformed manifest, count/tip mismatch, or
/// local method-verification failure. No `ResolutionOutput` exists on error.
pub async fn import_complete_history(
    input: ResolutionInput,
    manifest: &CompleteHistoryManifest,
) -> Result<ResolutionOutput, CompleteImportError> {
    if manifest.expected_entry_count == 0 || manifest.expected_version_id.is_empty() {
        return Err(CompleteImportError::MalformedManifest);
    }
    let entries = parse_log(&input.raw_log).map_err(|_| CompleteImportError::Incomplete)?;
    if entries.len() != manifest.expected_entry_count
        || entries
            .last()
            .and_then(|entry| entry.get("versionId"))
            .and_then(Value::as_str)
            != Some(manifest.expected_version_id.as_str())
    {
        return Err(CompleteImportError::Incomplete);
    }
    let output = WebvhResolver
        .resolve(input)
        .await
        .map_err(CompleteImportError::Verification)?;
    if output.metadata.version_id != manifest.expected_version_id
        || usize::try_from(output.metadata.version_number).ok()
            != Some(manifest.expected_entry_count)
    {
        return Err(CompleteImportError::Incomplete);
    }
    Ok(output)
}

/// Compare complete lifecycle snapshots without silently normalizing fields.
///
/// Object member order is ignored only for the semantic comparison. Array
/// order and every value remain significant.
///
/// # Errors
///
/// Returns a typed error if either snapshot cannot be serialized.
pub fn compare_lifecycle_snapshots(
    left: &LifecycleSnapshot,
    right: &LifecycleSnapshot,
) -> Result<LifecycleComparison, LifecycleProfileError> {
    let left_bytes = serde_json::to_vec(left).map_err(|_| LifecycleProfileError::Serialization)?;
    let right_bytes =
        serde_json::to_vec(right).map_err(|_| LifecycleProfileError::Serialization)?;
    let semantic_match = left == right;
    Ok(LifecycleComparison {
        byte_match: left_bytes == right_bytes,
        semantic_match,
        classification: (semantic_match && left_bytes != right_bytes)
            .then_some(DiffClassification::EquivalentRepresentation),
    })
}

/// Stable, non-sensitive lifecycle/profile failure taxonomy.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum LifecycleProfileError {
    #[error("lifecycle history is incomplete")]
    IncompleteHistory,
    #[error("lifecycle history is malformed")]
    MalformedHistory,
    #[error("lifecycle parameters are malformed")]
    MalformedParameters,
    #[error("Robin-created identity must use did:webvh v1.0")]
    UnsupportedMethodVersion,
    #[error("Robin-created identity must set portable=true at inception")]
    NonPortableCreation,
    #[error("Robin-created identity must enable and seed pre-rotation")]
    MissingPreRotation,
    #[error("Robin public DID state violates the experimental metadata profile")]
    MetadataPolicy,
    #[error("lifecycle comparison serialization failed")]
    Serialization,
}

/// Enforce the adopted minimum Robin creation profile after local method
/// verification.
///
/// The check intentionally examines the signed inception `state`, not implied
/// method services added to a resolved DID Document. This is a minimum policy
/// for the spike, not a complete production privacy budget.
///
/// # Errors
///
/// Rejects non-v1.0, non-portable, non-pre-rotated, incomplete, malformed, or
/// metadata-policy-incompatible creation evidence.
pub fn validate_robin_creation_profile(
    output: &ResolutionOutput,
) -> Result<(), LifecycleProfileError> {
    if output.metadata.method_version != "did:webvh:1.0" {
        return Err(LifecycleProfileError::UnsupportedMethodVersion);
    }
    let entries = parse_log(&output.evidence.raw_log)?;
    let inception = entries
        .first()
        .ok_or(LifecycleProfileError::IncompleteHistory)?;
    let parameters = inception
        .get("parameters")
        .and_then(Value::as_object)
        .ok_or(LifecycleProfileError::MalformedParameters)?;
    if parameters.get("portable").and_then(Value::as_bool) != Some(true) {
        return Err(LifecycleProfileError::NonPortableCreation);
    }
    let next_hashes = parameters
        .get("nextKeyHashes")
        .and_then(Value::as_array)
        .ok_or(LifecycleProfileError::MissingPreRotation)?;
    if next_hashes.is_empty() || next_hashes.iter().any(|value| !value.is_string()) {
        return Err(LifecycleProfileError::MissingPreRotation);
    }
    let state = inception
        .get("state")
        .and_then(Value::as_object)
        .ok_or(LifecycleProfileError::MalformedHistory)?;
    validate_public_state(state)
}

fn parse_log(raw_log: &str) -> Result<Vec<Value>, LifecycleProfileError> {
    let mut entries = Vec::new();
    for line in raw_log.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let value: Value =
            serde_json::from_str(line).map_err(|_| LifecycleProfileError::MalformedHistory)?;
        if !value.is_object() {
            return Err(LifecycleProfileError::MalformedHistory);
        }
        entries.push(value);
    }
    if entries.is_empty() {
        return Err(LifecycleProfileError::IncompleteHistory);
    }
    Ok(entries)
}

fn validate_public_state(state: &Map<String, Value>) -> Result<(), LifecycleProfileError> {
    const ALLOWED_TOP_LEVEL: &[&str] = &[
        "@context",
        "id",
        "controller",
        "alsoKnownAs",
        "verificationMethod",
        "authentication",
        "assertionMethod",
        "keyAgreement",
        "capabilityInvocation",
        "capabilityDelegation",
    ];
    if state
        .keys()
        .any(|key| !ALLOWED_TOP_LEVEL.contains(&key.as_str()))
    {
        return Err(LifecycleProfileError::MetadataPolicy);
    }
    validate_metadata_value(&Value::Object(state.clone()))
}

fn validate_metadata_value(value: &Value) -> Result<(), LifecycleProfileError> {
    const FORBIDDEN_KEYS: &[&str] = &[
        "name",
        "email",
        "phone",
        "label",
        "devicename",
        "applicationid",
        "appid",
        "contact",
        "contactgraph",
        "service",
        "serviceendpoint",
    ];
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                let normalized = key.to_ascii_lowercase().replace(['-', '_'], "");
                if FORBIDDEN_KEYS.contains(&normalized.as_str()) {
                    return Err(LifecycleProfileError::MetadataPolicy);
                }
                validate_metadata_value(child)?;
            }
        }
        Value::Array(values) => {
            for child in values {
                validate_metadata_value(child)?;
            }
        }
        Value::String(text) if text.to_ascii_lowercase().contains("robin") => {
            return Err(LifecycleProfileError::MetadataPolicy);
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semantic_comparison_does_not_hide_value_differences() {
        let left = LifecycleSnapshot {
            did_document: serde_json::json!({"id": "did:webvh:a:example.com"}),
            method_version: "did:webvh:1.0".into(),
            version_id: "1-a".into(),
            version_number: 1,
            version_time: "2000-01-01T00:00:00Z".into(),
            method_parameters: serde_json::json!({"portable": true}),
            deactivated: false,
        };
        let mut right = left.clone();
        right.version_number = 2;
        let comparison = compare_lifecycle_snapshots(&left, &right).unwrap();
        assert!(!comparison.byte_match);
        assert!(!comparison.semantic_match);
        assert_eq!(comparison.classification, None);
    }
}
