use async_trait::async_trait;
use didwebvh_rs::url::WebVHURL;
use didwebvh_rs::{DIDWebVHError, DIDWebVHState, log_entry::LogEntryMethods};
use ed25519_dalek::VerifyingKey;
use multibase::Base;
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fmt::Write;
use std::net::IpAddr;
use thiserror::Error;
use x25519_dalek::PublicKey as X25519PublicKey;

const ED25519_PUB_MULTICODEC: u64 = 0xed;
const X25519_PUB_MULTICODEC: u64 = 0xec;
const CURVE25519_PUBLIC_KEY_BYTES: usize = 32;

/// Maximum accepted `did.jsonl` size for the deterministic client verifier.
pub const MAX_LOG_BYTES: usize = 200 * 1024;
/// Maximum accepted witness file size.
pub const MAX_WITNESS_BYTES: usize = 200 * 1024;
pub const MAX_TOTAL_EVIDENCE_BYTES: usize = 300 * 1024;
/// Maximum history entries accepted in one resolution.
pub const MAX_HISTORY_ENTRIES: usize = 1_024;
/// Maximum bytes accepted in one JSONL entry.
pub const MAX_ENTRY_BYTES: usize = 64 * 1024;
/// Provisional spike-policy limit for method-neutral DID inputs.
///
/// This is an experimental host-contract value, not a stable production API;
/// Security and UX review may change it.
pub const MAX_DID_BYTES: usize = 2_048;
/// Provisional spike-policy limit for method-neutral evidence-source URIs.
///
/// This is an experimental host-contract value, not a stable production API;
/// Security and UX review may change it.
pub const MAX_SOURCE_URI_BYTES: usize = 2_048;
pub const MAX_TIMESTAMP_BYTES: usize = 64;
pub const MAX_JSON_DEPTH: usize = 64;
pub const MAX_JSON_STRING_BYTES: usize = 16 * 1024;
pub const MAX_VERIFICATION_METHODS: usize = 64;
pub const MAX_RELATIONSHIP_KEYS: usize = 64;
pub const MAX_WITNESSES: usize = 32;
pub const MAX_WITNESSED_VERSIONS: usize = 64;
pub const MAX_SOURCES: usize = 3;
pub const MAX_RETRIES: u8 = 2;
pub const MIN_TIMEOUT_MILLIS: u64 = 100;
pub const MAX_TIMEOUT_MILLIS: u64 = 30_000;
pub const MAX_TOTAL_ATTEMPTS: usize = 6;
pub const MAX_TOTAL_TIMEOUT_MILLIS: u64 = 60_000;

/// Browser/native transport requirements imposed before method verification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransportPolicy {
    pub timeout_millis: u64,
    pub retries: u8,
    pub max_redirects: u8,
    pub max_response_bytes: usize,
    pub max_concurrency: u8,
    /// Native hosts set this when they can expose post-DNS addresses. Browser
    /// WASM cannot obtain that information and must rely on a trusted host.
    pub require_resolved_addresses: bool,
}

impl Default for TransportPolicy {
    fn default() -> Self {
        Self {
            timeout_millis: 10_000,
            retries: 1,
            max_redirects: 0,
            max_response_bytes: MAX_LOG_BYTES,
            max_concurrency: 2,
            require_resolved_addresses: false,
        }
    }
}

/// Transport failures stay distinct from invalid DID state.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum FetchError {
    #[error("DNS resolution failed")]
    Dns,
    #[error("TLS validation failed")]
    Tls,
    #[error("browser CORS policy denied the response")]
    Cors,
    #[error("request timed out")]
    Timeout,
    #[error("HTTP status {0}")]
    Http(u16),
    #[error("redirect was refused")]
    Redirect,
    #[error("response exceeded the configured byte limit")]
    TooLarge,
    #[error("transport is unavailable")]
    Unavailable,
    #[error("DNS rebinding or a disallowed resolved address was detected")]
    DnsRebinding,
    #[error("response was truncated or incomplete")]
    Truncated,
    #[error("response stream exceeded its time budget")]
    SlowStream,
}

/// Untrusted bytes returned by a policy-enforcing host transport.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetchedEvidence {
    pub raw_log: String,
    pub raw_witnesses: Option<String>,
    pub observed_at: String,
    /// All addresses returned by the host's final DNS lookup. Empty is only
    /// allowed when the policy explicitly permits browser-style opacity.
    pub resolved_addresses: Vec<IpAddr>,
    /// Declared length when the host exposes it. Actual bytes remain bounded
    /// and authoritative.
    pub content_length: Option<usize>,
    pub complete: bool,
}

#[async_trait(?Send)]
pub trait EvidenceFetcher {
    async fn fetch(
        &self,
        log_url: &str,
        witness_url: &str,
        policy: &TransportPolicy,
    ) -> Result<FetchedEvidence, FetchError>;
}

/// How the caller obtained the raw method evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SourceKind {
    LocalFixture,
    DirectHttps,
    Watcher,
    RemoteResolver,
    ImportedPackage,
}

/// Raw, independently verifiable evidence and its provenance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Evidence {
    pub source_kind: SourceKind,
    pub source_uri: String,
    pub observed_at: String,
    pub log_sha256: String,
    pub witness_sha256: Option<String>,
    pub raw_log: String,
    pub raw_witnesses: Option<String>,
    #[serde(default)]
    pub source_attempts: Vec<SourceAttempt>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceAttempt {
    pub source_uri: String,
    pub outcome: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceSource {
    pub log_url: String,
    pub witness_url: String,
    pub source_kind: SourceKind,
}

/// Caller-provided freshness and rollback context.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Freshness {
    #[serde(default)]
    pub known_did: Option<String>,
    #[serde(default)]
    pub known_version_id: Option<String>,
    #[serde(default)]
    pub known_log_sha256: Option<String>,
    /// Digest of the exact verified JSONL prefix ending at `known_version_id`.
    #[serde(default)]
    pub known_history_prefix_sha256: Option<String>,
    /// Once true, no later active state is accepted.
    #[serde(default)]
    pub known_deactivated: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedTip {
    pub version_id: String,
    pub version_number: u32,
    pub history_prefix_sha256: String,
    pub deactivated: bool,
}

/// Method-neutral input to resolution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolutionInput {
    pub did: String,
    pub raw_log: String,
    pub raw_witnesses: Option<String>,
    pub source_kind: SourceKind,
    pub source_uri: String,
    pub observed_at: String,
    #[serde(default)]
    pub freshness: Freshness,
}

/// Method-neutral DID resolution metadata required by Robin.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolutionMetadata {
    pub method: String,
    pub method_version: String,
    pub version_id: String,
    pub version_number: u32,
    pub version_time: String,
    pub created: String,
    pub updated: String,
    pub deactivated: bool,
    pub complete_history_verified: bool,
    pub conflict_detected: bool,
}

/// Successful method-neutral resolution result.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolutionOutput {
    #[serde(rename = "didDocument")]
    verified_did_document: Value,
    #[serde(skip)]
    resolved_did: String,
    pub metadata: ResolutionMetadata,
    pub evidence: Evidence,
    pub verified_tip: VerifiedTip,
}

/// A DID Document verification method selected for one exact relationship.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizedKey {
    pub id: String,
    pub relationship: String,
    pub verification_method: Value,
}

/// Stable failure taxonomy at Robin's method boundary.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ResolutionError {
    #[error("unsupported DID method: {0}")]
    UnsupportedMethod(String),
    #[error("unsupported DID method version: {0}")]
    UnsupportedVersion(String),
    #[error("malformed input: {0}")]
    MalformedInput(String),
    #[error("resource limit exceeded: {0}")]
    ResourceLimit(String),
    #[error("SCID validation failed: {0}")]
    InvalidScid(String),
    #[error("history validation failed: {0}")]
    InvalidHistory(String),
    #[error("authorization proof failed: {0}")]
    InvalidProof(String),
    #[error("witness validation failed: {0}")]
    InvalidWitness(String),
    #[error("DID is deactivated at {0:?}")]
    Deactivated(VerifiedTip),
    #[error("stale or rolled-back DID state: {0}")]
    StaleState(String),
    #[error("conflicting DID state: {0}")]
    Conflict(String),
    #[error("required verification relationship is absent or invalid: {0}")]
    MissingRelationship(String),
    #[error("invalid Multikey material: {0}")]
    InvalidKeyMaterial(String),
    #[error("network retrieval unavailable or unsafe: {0}")]
    NetworkUnavailable(String),
}

#[async_trait(?Send)]
pub trait DidResolver {
    async fn resolve(&self, input: ResolutionInput) -> Result<ResolutionOutput, ResolutionError>;
}

/// `did:webvh:1.0` adapter backed by the pinned upstream Rust verifier.
#[derive(Clone, Debug, Default)]
pub struct WebvhResolver;

impl WebvhResolver {
    /// Produce the spec-defined HTTPS endpoints after hostile-DID validation.
    ///
    /// # Errors
    ///
    /// Rejects malformed DIDs, IP literals, localhost, traversal, smuggled
    /// separators, or any transformation that does not yield HTTPS.
    pub fn evidence_urls(did: &str) -> Result<(String, String), ResolutionError> {
        validate_did_envelope(did)?;
        let parsed = WebVHURL::parse_did_url(did).map_err(map_webvh_error)?;
        validate_remote_domain(&parsed.domain)?;
        if parsed.domain.eq_ignore_ascii_case("localhost") {
            return Err(ResolutionError::NetworkUnavailable(
                "localhost is test-only and forbidden by the Robin remote policy".into(),
            ));
        }
        let log = parsed
            .get_http_url(Some("did.jsonl"))
            .map_err(map_webvh_error)?;
        let witness = parsed
            .get_http_url(Some("did-witness.json"))
            .map_err(map_webvh_error)?;
        if log.scheme() != "https" || witness.scheme() != "https" {
            return Err(ResolutionError::NetworkUnavailable(
                "remote evidence must use HTTPS".into(),
            ));
        }
        let log = log.to_string();
        let witness = witness.to_string();
        validate_transformed_url_bounds(&log, &witness)?;
        Ok((log, witness))
    }

    /// Fetch untrusted evidence using a separately supplied policy-enforcing
    /// transport and then verify it locally.
    ///
    /// # Errors
    ///
    /// Fails closed on URL-policy, transport, size, or method verification
    /// failures.
    pub async fn resolve_via<F: EvidenceFetcher>(
        &self,
        did: &str,
        fetcher: &F,
        policy: &TransportPolicy,
        freshness: Freshness,
    ) -> Result<ResolutionOutput, ResolutionError> {
        validate_did_envelope(did)?;
        let (log_url, witness_url) = Self::evidence_urls(did)?;
        self.resolve_via_sources(
            did,
            fetcher,
            &[EvidenceSource {
                log_url,
                witness_url,
                source_kind: SourceKind::DirectHttps,
            }],
            policy,
            freshness,
        )
        .await
    }

    /// Try a bounded set of independent sources and accept only locally
    /// verified, mutually consistent method evidence.
    ///
    /// # Errors
    ///
    /// Fails on unsafe policy/source configuration, exhausted transports,
    /// invalid method evidence, freshness conflicts, or source disagreement.
    pub async fn resolve_via_sources<F: EvidenceFetcher>(
        &self,
        did: &str,
        fetcher: &F,
        sources: &[EvidenceSource],
        policy: &TransportPolicy,
        freshness: Freshness,
    ) -> Result<ResolutionOutput, ResolutionError> {
        validate_did_envelope(did)?;
        validate_transport_policy(policy, sources)?;
        let mut attempts = Vec::new();
        let mut valid = Vec::new();
        for source in sources {
            validate_source(source)?;
            for _ in 0..=policy.retries {
                match fetcher
                    .fetch(&source.log_url, &source.witness_url, policy)
                    .await
                {
                    Ok(downloaded) => {
                        validate_download(&downloaded, policy)?;
                        let input = ResolutionInput {
                            did: did.into(),
                            raw_log: downloaded.raw_log,
                            raw_witnesses: downloaded.raw_witnesses,
                            source_kind: source.source_kind.clone(),
                            source_uri: source.log_url.clone(),
                            observed_at: downloaded.observed_at,
                            freshness: freshness.clone(),
                        };
                        match self.resolve(input).await {
                            Ok(output) => {
                                attempts.push(SourceAttempt {
                                    source_uri: source.log_url.clone(),
                                    outcome: "locally verified".into(),
                                });
                                valid.push(output);
                            }
                            Err(error) => attempts.push(SourceAttempt {
                                source_uri: source.log_url.clone(),
                                outcome: format!("locally rejected: {error}"),
                            }),
                        }
                        break;
                    }
                    Err(error) => attempts.push(SourceAttempt {
                        source_uri: source.log_url.clone(),
                        outcome: format!("transport rejected: {error}"),
                    }),
                }
            }
        }
        let mut accepted = valid.pop().ok_or_else(|| {
            ResolutionError::NetworkUnavailable("no source produced valid method evidence".into())
        })?;
        if valid.iter().any(|candidate| {
            candidate.verified_tip.version_id != accepted.verified_tip.version_id
                || candidate.verified_tip.history_prefix_sha256
                    != accepted.verified_tip.history_prefix_sha256
        }) {
            return Err(ResolutionError::Conflict(
                "independent sources returned conflicting valid DID histories".into(),
            ));
        }
        accepted.evidence.source_attempts = attempts;
        Ok(accepted)
    }
}

#[allow(clippy::needless_as_bytes)]
fn validate_did_envelope(did: &str) -> Result<(), ResolutionError> {
    if did.is_empty() {
        return Err(ResolutionError::ResourceLimit("DID is empty".into()));
    }
    if did.as_bytes().len() > MAX_DID_BYTES {
        return Err(ResolutionError::ResourceLimit(
            "DID exceeds the configured byte limit".into(),
        ));
    }
    Ok(())
}

fn validate_transformed_url_bounds(
    log_url: &str,
    witness_url: &str,
) -> Result<(), ResolutionError> {
    if log_url.len() > MAX_SOURCE_URI_BYTES || witness_url.len() > MAX_SOURCE_URI_BYTES {
        return Err(ResolutionError::ResourceLimit(
            "transformed evidence URL exceeds the configured byte limit".into(),
        ));
    }
    Ok(())
}

fn validate_remote_domain(domain: &str) -> Result<(), ResolutionError> {
    if domain.is_empty()
        || domain.len() > 253
        || !domain.is_ascii()
        || domain.contains('%')
        || domain.parse::<IpAddr>().is_ok()
        || domain.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(ResolutionError::NetworkUnavailable(
            "remote DID domain is not a safe DNS hostname".into(),
        ));
    }
    Ok(())
}

#[async_trait(?Send)]
impl DidResolver for WebvhResolver {
    async fn resolve(&self, input: ResolutionInput) -> Result<ResolutionOutput, ResolutionError> {
        validate_envelope(&input)?;
        verify_every_witnessed_prefix(&input).await?;

        let log_digest = sha256_hex(input.raw_log.as_bytes());
        let witness_digest = input
            .raw_witnesses
            .as_deref()
            .map(|value| sha256_hex(value.as_bytes()));

        let (envelope_version_id, envelope_version_number) = history_tip(&input.raw_log)?;
        enforce_freshness(
            &input.freshness,
            &input.did,
            &envelope_version_id,
            envelope_version_number,
            &log_digest,
            &input.raw_log,
        )?;

        let mut state = DIDWebVHState::default();
        let (entry, metadata) = match state
            .resolve_log_owned(&input.did, &input.raw_log, input.raw_witnesses.as_deref())
            .await
        {
            Ok(result) => result,
            Err(DIDWebVHError::DeactivatedError(_)) => {
                return Err(ResolutionError::Deactivated(VerifiedTip {
                    version_id: envelope_version_id,
                    version_number: envelope_version_number,
                    history_prefix_sha256: history_prefix_sha256(
                        &input.raw_log,
                        envelope_version_number,
                    )?,
                    deactivated: true,
                }));
            }
            Err(error) => return Err(map_webvh_error(error)),
        };

        let prefix_digest = history_prefix_sha256(&input.raw_log, metadata.version_number)?;
        if metadata.deactivated {
            return Err(ResolutionError::Deactivated(VerifiedTip {
                version_id: metadata.version_id,
                version_number: metadata.version_number,
                history_prefix_sha256: prefix_digest,
                deactivated: true,
            }));
        }

        let did_document = entry
            .get_did_document()
            .map_err(|error| ResolutionError::InvalidHistory(error.to_string()))?;
        let version_id = metadata.version_id.clone();
        let version_number = metadata.version_number;

        Ok(ResolutionOutput {
            verified_did_document: did_document,
            resolved_did: input.did,
            metadata: ResolutionMetadata {
                method: "webvh".into(),
                method_version: "did:webvh:1.0".into(),
                version_id: metadata.version_id,
                version_number: metadata.version_number,
                version_time: metadata.version_time,
                created: metadata.created,
                updated: metadata.updated,
                deactivated: metadata.deactivated,
                complete_history_verified: true,
                conflict_detected: false,
            },
            evidence: Evidence {
                source_kind: input.source_kind,
                source_uri: input.source_uri,
                observed_at: input.observed_at,
                log_sha256: log_digest,
                witness_sha256: witness_digest,
                raw_log: input.raw_log,
                raw_witnesses: input.raw_witnesses,
                source_attempts: Vec::new(),
            },
            verified_tip: VerifiedTip {
                version_id,
                version_number,
                history_prefix_sha256: prefix_digest,
                deactivated: false,
            },
        })
    }
}

fn validate_selected_method(
    method: &Value,
    resolved_did: &str,
    relationship: &str,
) -> Result<DecodedMultikey, ResolutionError> {
    let object = method.as_object().ok_or_else(|| {
        ResolutionError::MalformedInput("verification method is not an object".into())
    })?;
    if object.get("controller").and_then(Value::as_str) != Some(resolved_did) {
        return Err(ResolutionError::MissingRelationship(
            "verification method controller does not match the resolved DID".into(),
        ));
    }
    if object.get("type").and_then(Value::as_str) != Some("Multikey") {
        return Err(ResolutionError::MissingRelationship(
            "unsupported verification method type in experimental profile".into(),
        ));
    }
    let method_id = object.get("id").and_then(Value::as_str).ok_or_else(|| {
        ResolutionError::MalformedInput("verification method is missing a string id".into())
    })?;
    let fragment = method_id
        .strip_prefix(resolved_did)
        .and_then(|suffix| suffix.strip_prefix('#'));
    if fragment.is_none_or(|fragment| {
        fragment.is_empty()
            || fragment.contains(['#', '?', '/'])
            || fragment.chars().any(char::is_whitespace)
    }) {
        return Err(ResolutionError::MissingRelationship(
            "verification method id is not an unambiguous fragment of the resolved DID".into(),
        ));
    }
    if object.contains_key("revoked") {
        return Err(ResolutionError::MissingRelationship(
            "revoked verification methods are unsupported by the experimental profile".into(),
        ));
    }
    let material_fields = [
        "publicKeyMultibase",
        "publicKeyJwk",
        "publicKeyBase58",
        "publicKeyHex",
        "publicKeyBase64",
        "publicKeyPem",
        "publicKeyDer",
        "privateKeyJwk",
        "privateKeyMultibase",
        "secretKeyMultibase",
        "blockchainAccountId",
    ];
    let present: Vec<&str> = material_fields
        .iter()
        .copied()
        .filter(|field| object.contains_key(*field))
        .collect();
    if present.as_slice() != ["publicKeyMultibase"] {
        return Err(ResolutionError::MissingRelationship(
            "verification method must contain exactly one supported key-material representation"
                .into(),
        ));
    }
    let key = object
        .get("publicKeyMultibase")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            ResolutionError::InvalidKeyMaterial("publicKeyMultibase is empty or malformed".into())
        })?;
    let decoded = decode_multikey(key)?;
    let expected_codec = match relationship {
        "authentication" => ED25519_PUB_MULTICODEC,
        "keyAgreement" => X25519_PUB_MULTICODEC,
        _ => {
            return Err(ResolutionError::MissingRelationship(format!(
                "unsupported verification relationship: {relationship}"
            )));
        }
    };
    if decoded.multicodec != expected_codec {
        return Err(ResolutionError::MissingRelationship(format!(
            "decoded Multicodec is unsupported for {relationship} by the test-only profile"
        )));
    }
    Ok(decoded)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DecodedMultikey {
    multicodec: u64,
    public_key: [u8; CURVE25519_PUBLIC_KEY_BYTES],
}

fn decode_multikey(value: &str) -> Result<DecodedMultikey, ResolutionError> {
    let (base, decoded) = multibase::decode(value).map_err(|error| {
        ResolutionError::InvalidKeyMaterial(format!("Multibase decoding failed: {error}"))
    })?;
    if base != Base::Base58Btc {
        return Err(ResolutionError::InvalidKeyMaterial(
            "experimental profile requires Base58BTC Multibase encoding".into(),
        ));
    }
    if decoded.is_empty() {
        return Err(ResolutionError::InvalidKeyMaterial(
            "decoded Multikey payload is empty and has no Multicodec".into(),
        ));
    }
    let (multicodec, public_key) = unsigned_varint::decode::u64(&decoded).map_err(|error| {
        ResolutionError::InvalidKeyMaterial(format!(
            "Multicodec unsigned-varint is missing or malformed: {error}"
        ))
    })?;
    let prefix_length = decoded.len() - public_key.len();
    let mut canonical_buffer = unsigned_varint::encode::u64_buffer();
    let canonical = unsigned_varint::encode::u64(multicodec, &mut canonical_buffer);
    if decoded.get(..prefix_length) != Some(canonical) {
        return Err(ResolutionError::InvalidKeyMaterial(
            "Multicodec unsigned-varint is non-canonical".into(),
        ));
    }
    if !matches!(multicodec, ED25519_PUB_MULTICODEC | X25519_PUB_MULTICODEC) {
        return Err(ResolutionError::InvalidKeyMaterial(format!(
            "unsupported public-key Multicodec 0x{multicodec:x}"
        )));
    }
    let public_key: [u8; CURVE25519_PUBLIC_KEY_BYTES] = public_key.try_into().map_err(|_| {
        ResolutionError::InvalidKeyMaterial(format!(
            "Multicodec 0x{multicodec:x} requires exactly {CURVE25519_PUBLIC_KEY_BYTES} raw public-key bytes"
        ))
    })?;
    match multicodec {
        ED25519_PUB_MULTICODEC => {
            VerifyingKey::from_bytes(&public_key).map_err(|error| {
                ResolutionError::InvalidKeyMaterial(format!(
                    "Ed25519 public-key import failed: {error}"
                ))
            })?;
        }
        X25519_PUB_MULTICODEC => {
            let imported = X25519PublicKey::from(public_key);
            if imported.as_bytes().iter().all(|byte| *byte == 0) {
                return Err(ResolutionError::InvalidKeyMaterial(
                    "X25519 all-zero public key is not permitted by the experimental profile"
                        .into(),
                ));
            }
        }
        _ => unreachable!("unsupported Multicodecs returned above"),
    }
    Ok(DecodedMultikey {
        multicodec,
        public_key,
    })
}

impl ResolutionOutput {
    /// Read-only view of the method-verified DID Document.
    #[must_use]
    pub fn did_document(&self) -> &Value {
        &self.verified_did_document
    }

    /// Detached presentation copy. Mutating it cannot change authorization.
    #[must_use]
    pub fn did_document_copy(&self) -> Value {
        self.verified_did_document.clone()
    }

    /// Cache context required to prove that a future result extends this tip.
    #[must_use]
    pub fn freshness(&self) -> Freshness {
        Freshness {
            known_did: Some(self.resolved_did.clone()),
            known_version_id: Some(self.verified_tip.version_id.clone()),
            known_log_sha256: Some(self.evidence.log_sha256.clone()),
            known_history_prefix_sha256: Some(self.verified_tip.history_prefix_sha256.clone()),
            known_deactivated: self.verified_tip.deactivated,
        }
    }

    /// Select keys authorized for one exact DID Core verification relationship.
    ///
    /// # Errors
    ///
    /// Returns a typed failure when the relationship is unsupported, absent,
    /// malformed, empty, or references an unknown verification method.
    pub fn authorized_keys(
        &self,
        relationship: &str,
    ) -> Result<Vec<AuthorizedKey>, ResolutionError> {
        if !matches!(relationship, "authentication" | "keyAgreement") {
            return Err(ResolutionError::MissingRelationship(
                relationship.to_owned(),
            ));
        }

        let document = self.verified_did_document.as_object().ok_or_else(|| {
            ResolutionError::MalformedInput("DID Document is not an object".into())
        })?;
        if document.get("id").and_then(Value::as_str) != Some(self.resolved_did.as_str()) {
            return Err(ResolutionError::MalformedInput(
                "verified DID Document id does not match the resolved DID".into(),
            ));
        }
        let methods = document
            .get("verificationMethod")
            .and_then(Value::as_array)
            .ok_or_else(|| ResolutionError::MissingRelationship("verificationMethod".into()))?;
        if methods.len() > MAX_VERIFICATION_METHODS {
            return Err(ResolutionError::ResourceLimit(
                "too many verification methods".into(),
            ));
        }
        let authorized = document
            .get(relationship)
            .and_then(Value::as_array)
            .ok_or_else(|| ResolutionError::MissingRelationship(relationship.into()))?;
        if authorized.len() > MAX_RELATIONSHIP_KEYS {
            return Err(ResolutionError::ResourceLimit(format!(
                "too many {relationship} references"
            )));
        }

        let mut methods_by_id = std::collections::HashMap::new();
        for method in methods {
            let id = method.get("id").and_then(Value::as_str).ok_or_else(|| {
                ResolutionError::MalformedInput("verification method is missing a string id".into())
            })?;
            if methods_by_id.insert(id, method).is_some() {
                return Err(ResolutionError::MalformedInput(format!(
                    "duplicate verification method id: {id}"
                )));
            }
        }

        let mut seen = HashSet::new();
        let mut selected = Vec::new();
        for item in authorized {
            let method = if let Some(reference) = item.as_str() {
                methods_by_id
                    .get(reference)
                    .ok_or_else(|| {
                        ResolutionError::MissingRelationship(format!(
                            "{relationship} references unknown verification method {reference}"
                        ))
                    })?
                    .to_owned()
                    .clone()
            } else if item.is_object() {
                return Err(ResolutionError::MalformedInput(format!(
                    "embedded {relationship} methods are unsupported by the experimental profile"
                )));
            } else {
                return Err(ResolutionError::MalformedInput(format!(
                    "{relationship} contains a non-object, non-reference value"
                )));
            };
            let id = method
                .get("id")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    ResolutionError::MalformedInput(
                        "verification method is missing a string id".into(),
                    )
                })?
                .to_owned();
            if !seen.insert(id.clone()) {
                return Err(ResolutionError::MalformedInput(format!(
                    "duplicate {relationship} reference: {id}"
                )));
            }
            validate_selected_method(&method, &self.resolved_did, relationship)?;
            selected.push(AuthorizedKey {
                id,
                relationship: relationship.into(),
                verification_method: method,
            });
        }
        if selected.is_empty() {
            return Err(ResolutionError::MissingRelationship(relationship.into()));
        }
        Ok(selected)
    }
}

fn validate_envelope(input: &ResolutionInput) -> Result<(), ResolutionError> {
    validate_input_bounds(input)?;
    let mut count = 0usize;
    let mut first = None;
    let mut history = Vec::new();
    for line in input.raw_log.lines() {
        count += 1;
        if count > MAX_HISTORY_ENTRIES {
            return Err(ResolutionError::ResourceLimit(format!(
                "history exceeds {MAX_HISTORY_ENTRIES} entries"
            )));
        }
        if line.len() > MAX_ENTRY_BYTES {
            return Err(ResolutionError::ResourceLimit(format!(
                "entry exceeds {MAX_ENTRY_BYTES} bytes"
            )));
        }
        let parsed = parse_no_duplicates(line)?;
        validate_history_entry(&parsed)?;
        if first.is_none() {
            first = Some(parsed.clone());
        }
        history.push(parsed);
    }
    if count == 0 {
        return Err(ResolutionError::MalformedInput("empty DID log".into()));
    }
    if let Some(witnesses) = input.raw_witnesses.as_deref() {
        validate_witness_envelope(witnesses)?;
    }
    validate_witness_policy(&history, input.raw_witnesses.as_deref())?;

    let first = first.expect("non-empty history has a first entry");
    let method_version = first
        .pointer("/parameters/method")
        .and_then(Value::as_str)
        .ok_or_else(|| ResolutionError::MalformedInput("missing inception method".into()))?;
    if method_version != "did:webvh:1.0" {
        return Err(ResolutionError::UnsupportedVersion(method_version.into()));
    }
    Ok(())
}

fn validate_input_bounds(input: &ResolutionInput) -> Result<(), ResolutionError> {
    validate_did_envelope(&input.did)?;
    for (name, value, limit) in [
        (
            "source URI",
            input.source_uri.as_str(),
            MAX_SOURCE_URI_BYTES,
        ),
        ("timestamp", input.observed_at.as_str(), MAX_TIMESTAMP_BYTES),
    ] {
        if value.is_empty() || value.len() > limit {
            return Err(ResolutionError::ResourceLimit(format!(
                "{name} length is outside the supported bound"
            )));
        }
    }
    if !input.did.starts_with("did:") {
        return Err(ResolutionError::MalformedInput(
            "identifier does not use DID syntax".into(),
        ));
    }
    let method = input.did.split(':').nth(1).unwrap_or_default();
    if method != "webvh" {
        return Err(ResolutionError::UnsupportedMethod(method.into()));
    }
    if input.raw_log.len() > MAX_LOG_BYTES {
        return Err(ResolutionError::ResourceLimit(format!(
            "log exceeds {MAX_LOG_BYTES} bytes"
        )));
    }
    if input
        .raw_witnesses
        .as_ref()
        .is_some_and(|value| value.len() > MAX_WITNESS_BYTES)
    {
        return Err(ResolutionError::ResourceLimit(format!(
            "witness file exceeds {MAX_WITNESS_BYTES} bytes"
        )));
    }
    let total_evidence = input
        .raw_log
        .len()
        .checked_add(
            input
                .raw_witnesses
                .as_ref()
                .map_or(0, std::string::String::len),
        )
        .ok_or_else(|| ResolutionError::ResourceLimit("evidence size overflow".into()))?;
    if total_evidence > MAX_TOTAL_EVIDENCE_BYTES {
        return Err(ResolutionError::ResourceLimit(format!(
            "combined evidence exceeds {MAX_TOTAL_EVIDENCE_BYTES} bytes"
        )));
    }
    Ok(())
}

fn validate_history_entry(parsed: &Value) -> Result<(), ResolutionError> {
    let allowed_entry = ["versionId", "versionTime", "parameters", "state", "proof"];
    let allowed_parameters = [
        "method",
        "scid",
        "updateKeys",
        "portable",
        "nextKeyHashes",
        "witness",
        "watchers",
        "deactivated",
        "ttl",
    ];
    validate_json_shape(parsed)?;
    let object = parsed
        .as_object()
        .ok_or_else(|| ResolutionError::MalformedInput("log entry is not a JSON object".into()))?;
    let version_time = object
        .get("versionTime")
        .and_then(Value::as_str)
        .ok_or_else(|| ResolutionError::MalformedInput("versionTime is not a string".into()))?;
    if version_time.len() > MAX_TIMESTAMP_BYTES {
        return Err(ResolutionError::ResourceLimit(
            "versionTime exceeds the supported bound".into(),
        ));
    }
    if let Some(unknown) = object
        .keys()
        .find(|key| !allowed_entry.contains(&key.as_str()))
    {
        return Err(ResolutionError::MalformedInput(format!(
            "unknown log-entry property: {unknown}"
        )));
    }
    let parameters = object
        .get("parameters")
        .and_then(Value::as_object)
        .ok_or_else(|| ResolutionError::MalformedInput("parameters is not an object".into()))?;
    if let Some(unknown) = parameters
        .keys()
        .find(|key| !allowed_parameters.contains(&key.as_str()))
    {
        return Err(ResolutionError::MalformedInput(format!(
            "unknown did:webvh parameter: {unknown}"
        )));
    }
    validate_state_limits(object.get("state"))?;
    Ok(())
}

fn validate_state_limits(state: Option<&Value>) -> Result<(), ResolutionError> {
    let state = state
        .and_then(Value::as_object)
        .ok_or_else(|| ResolutionError::MalformedInput("state is not an object".into()))?;
    if state
        .get("verificationMethod")
        .and_then(Value::as_array)
        .is_some_and(|methods| methods.len() > MAX_VERIFICATION_METHODS)
    {
        return Err(ResolutionError::ResourceLimit(
            "too many verification methods".into(),
        ));
    }
    for relationship in [
        "authentication",
        "assertionMethod",
        "keyAgreement",
        "capabilityInvocation",
        "capabilityDelegation",
    ] {
        if state
            .get(relationship)
            .and_then(Value::as_array)
            .is_some_and(|methods| methods.len() > MAX_RELATIONSHIP_KEYS)
        {
            return Err(ResolutionError::ResourceLimit(format!(
                "too many {relationship} entries"
            )));
        }
    }
    Ok(())
}

fn validate_transport_policy(
    policy: &TransportPolicy,
    sources: &[EvidenceSource],
) -> Result<(), ResolutionError> {
    if sources.is_empty()
        || sources.len() > MAX_SOURCES
        || policy.timeout_millis < MIN_TIMEOUT_MILLIS
        || policy.timeout_millis > MAX_TIMEOUT_MILLIS
        || policy.retries > MAX_RETRIES
        || policy.max_redirects != 0
        || policy.max_response_bytes == 0
        || policy.max_response_bytes > MAX_LOG_BYTES
        || policy.max_concurrency == 0
        || policy.max_concurrency > 2
    {
        return Err(ResolutionError::NetworkUnavailable(
            "transport policy exceeds Robin safety bounds".into(),
        ));
    }
    let attempts = sources
        .len()
        .checked_mul(usize::from(policy.retries) + 1)
        .ok_or_else(|| ResolutionError::ResourceLimit("attempt budget overflow".into()))?;
    let total_timeout = policy
        .timeout_millis
        .checked_mul(u64::try_from(attempts).unwrap_or(u64::MAX))
        .ok_or_else(|| ResolutionError::ResourceLimit("timeout budget overflow".into()))?;
    if attempts > MAX_TOTAL_ATTEMPTS || total_timeout > MAX_TOTAL_TIMEOUT_MILLIS {
        return Err(ResolutionError::NetworkUnavailable(
            "total transport attempt budget exceeds Robin safety bounds".into(),
        ));
    }
    Ok(())
}

fn validate_source(source: &EvidenceSource) -> Result<(), ResolutionError> {
    for endpoint in [&source.log_url, &source.witness_url] {
        let Some(authority) = endpoint
            .strip_prefix("https://")
            .and_then(|rest| rest.split('/').next())
            .filter(|authority| !authority.is_empty())
        else {
            return Err(ResolutionError::NetworkUnavailable(
                "source endpoint violates HTTPS URL policy".into(),
            ));
        };
        if endpoint.len() > MAX_SOURCE_URI_BYTES
            || endpoint.contains('@')
            || endpoint.contains('#')
            || endpoint.contains("/../")
            || endpoint.to_ascii_lowercase().contains("%2f")
            || endpoint.to_ascii_lowercase().contains("%5c")
        {
            return Err(ResolutionError::NetworkUnavailable(
                "source endpoint violates HTTPS URL policy".into(),
            ));
        }
        validate_remote_domain(authority)?;
    }
    Ok(())
}

fn validate_download(
    downloaded: &FetchedEvidence,
    policy: &TransportPolicy,
) -> Result<(), ResolutionError> {
    if !downloaded.complete {
        return Err(ResolutionError::NetworkUnavailable(
            "transport returned a partial response".into(),
        ));
    }
    if downloaded.raw_log.len() > policy.max_response_bytes
        || downloaded
            .raw_witnesses
            .as_ref()
            .is_some_and(|value| value.len() > MAX_WITNESS_BYTES)
        || downloaded
            .content_length
            .is_some_and(|length| length != downloaded.raw_log.len())
    {
        return Err(ResolutionError::ResourceLimit(
            "transport returned evidence beyond or inconsistent with declared bounds".into(),
        ));
    }
    if policy.require_resolved_addresses && downloaded.resolved_addresses.is_empty() {
        return Err(ResolutionError::NetworkUnavailable(
            "native host did not expose post-DNS addresses".into(),
        ));
    }
    if downloaded.resolved_addresses.iter().any(disallowed_address) {
        return Err(ResolutionError::NetworkUnavailable(
            "post-DNS address is disallowed by Robin transport policy".into(),
        ));
    }
    Ok(())
}

fn disallowed_address(address: &IpAddr) -> bool {
    match address {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || ip.is_multicast()
                || ip.is_broadcast()
                || octets[0] == 0
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
                || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
                || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
                || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
                || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
                || octets[0] >= 240
        }
        IpAddr::V6(ip) => {
            let segments = ip.segments();
            ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_multicast()
                || (segments[0] & 0xfe00) == 0xfc00
                || (segments[0] & 0xffc0) == 0xfe80
                || (segments[0] == 0x2001 && segments[1] == 0x0db8)
        }
    }
}

struct NoDuplicateJson(Value);

impl<'de> Deserialize<'de> for NoDuplicateJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(NoDuplicateVisitor)
    }
}

struct NoDuplicateVisitor;

impl<'de> Visitor<'de> for NoDuplicateVisitor {
    type Value = NoDuplicateJson;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("JSON without repeated object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(NoDuplicateJson(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(NoDuplicateJson(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(NoDuplicateJson(Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Number::from_f64(value)
            .map(|number| NoDuplicateJson(Value::Number(number)))
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(NoDuplicateJson(Value::String(value.into())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(NoDuplicateJson(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(NoDuplicateJson(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(NoDuplicateJson(Value::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(NoDuplicateJson(value)) = sequence.next_element()? {
            values.push(value);
        }
        Ok(NoDuplicateJson(Value::Array(values)))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom(format!("repeated JSON key: {key}")));
            }
            let NoDuplicateJson(value) = map.next_value()?;
            values.insert(key, value);
        }
        Ok(NoDuplicateJson(Value::Object(values)))
    }
}

fn parse_no_duplicates(raw: &str) -> Result<Value, ResolutionError> {
    serde_json::from_str::<NoDuplicateJson>(raw)
        .map(|value| value.0)
        .map_err(|error| ResolutionError::MalformedInput(error.to_string()))
}

fn enforce_freshness(
    freshness: &Freshness,
    resolved_did: &str,
    resolved_version_id: &str,
    resolved_version_number: u32,
    resolved_digest: &str,
    raw_log: &str,
) -> Result<(), ResolutionError> {
    if let Some(known_did) = freshness.known_did.as_deref()
        && known_did != resolved_did
    {
        return Err(ResolutionError::Conflict(
            "freshness state belongs to a different DID".into(),
        ));
    }
    if let Some(known) = freshness.known_version_id.as_deref() {
        let known_number = known
            .split_once('-')
            .and_then(|(number, _)| number.parse::<u32>().ok())
            .ok_or_else(|| {
                ResolutionError::MalformedInput("known_version_id is malformed".into())
            })?;
        if resolved_version_number < known_number {
            return Err(ResolutionError::StaleState(format!(
                "resolved version {resolved_version_number} is older than known version {known_number}"
            )));
        }
        if resolved_version_number == known_number && resolved_version_id != known {
            return Err(ResolutionError::Conflict(format!(
                "version {known_number} has two version identifiers"
            )));
        }
        if freshness.known_deactivated && resolved_version_number > known_number {
            return Err(ResolutionError::Conflict(
                "an irreversible cached deactivation cannot be extended".into(),
            ));
        }
        if resolved_version_number > known_number {
            let lines: Vec<&str> = raw_log.lines().collect();
            let cached_line = lines
                .get(known_number.saturating_sub(1) as usize)
                .ok_or_else(|| {
                    ResolutionError::Conflict("new history omits the cached tip".into())
                })?;
            let cached: Value = parse_no_duplicates(cached_line)?;
            if cached.get("versionId").and_then(Value::as_str) != Some(known) {
                return Err(ResolutionError::Conflict(
                    "higher-version history does not contain the exact cached tip".into(),
                ));
            }
            let expected_prefix = freshness
                .known_history_prefix_sha256
                .as_deref()
                .ok_or_else(|| {
                    ResolutionError::MalformedInput(
                        "higher-version continuity requires known_history_prefix_sha256".into(),
                    )
                })?;
            let actual_prefix = history_prefix_sha256(raw_log, known_number)?;
            if actual_prefix != expected_prefix {
                return Err(ResolutionError::Conflict(
                    "higher-version history replaces previously verified evidence".into(),
                ));
            }
        }
    }
    if let Some(known_digest) = freshness.known_log_sha256.as_deref()
        && freshness.known_version_id.as_deref() == Some(resolved_version_id)
        && known_digest != resolved_digest
    {
        return Err(ResolutionError::Conflict(
            "same version identifier arrived with different raw evidence".into(),
        ));
    }
    Ok(())
}

fn history_prefix_sha256(raw_log: &str, entries: u32) -> Result<String, ResolutionError> {
    let lines: Vec<&str> = raw_log.lines().collect();
    let count = usize::try_from(entries)
        .map_err(|_| ResolutionError::ResourceLimit("version number overflow".into()))?;
    if count == 0 || count > lines.len() {
        return Err(ResolutionError::InvalidHistory(
            "version number does not identify a history prefix".into(),
        ));
    }
    let mut prefix = lines[..count].join("\n");
    prefix.push('\n');
    Ok(sha256_hex(prefix.as_bytes()))
}

fn history_tip(raw_log: &str) -> Result<(String, u32), ResolutionError> {
    let line = raw_log
        .lines()
        .last()
        .ok_or_else(|| ResolutionError::MalformedInput("empty DID log".into()))?;
    let value = parse_no_duplicates(line)?;
    let version_id = value
        .get("versionId")
        .and_then(Value::as_str)
        .ok_or_else(|| ResolutionError::InvalidHistory("missing final version id".into()))?
        .to_owned();
    let number = version_id
        .split_once('-')
        .and_then(|(number, _)| number.parse().ok())
        .ok_or_else(|| ResolutionError::InvalidHistory("malformed final version id".into()))?;
    Ok((version_id, number))
}

fn validate_json_shape(root: &Value) -> Result<(), ResolutionError> {
    let mut stack = vec![(root, 1usize)];
    while let Some((value, depth)) = stack.pop() {
        if depth > MAX_JSON_DEPTH {
            return Err(ResolutionError::ResourceLimit(
                "JSON nesting is too deep".into(),
            ));
        }
        match value {
            Value::String(string) if string.len() > MAX_JSON_STRING_BYTES => {
                return Err(ResolutionError::ResourceLimit(
                    "JSON string exceeds the supported bound".into(),
                ));
            }
            Value::Array(values) => {
                stack.extend(values.iter().map(|value| (value, depth + 1)));
            }
            Value::Object(values) => {
                for (key, value) in values {
                    if key.len() > MAX_JSON_STRING_BYTES {
                        return Err(ResolutionError::ResourceLimit(
                            "JSON object key exceeds the supported bound".into(),
                        ));
                    }
                    stack.push((value, depth + 1));
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn validate_witness_envelope(raw: &str) -> Result<(), ResolutionError> {
    let value = parse_no_duplicates(raw)?;
    validate_json_shape(&value)?;
    let entries = value.as_array().ok_or_else(|| {
        ResolutionError::InvalidWitness("witness evidence is not an array".into())
    })?;
    if entries.len() > MAX_WITNESSED_VERSIONS {
        return Err(ResolutionError::ResourceLimit(
            "too many witnessed versions".into(),
        ));
    }
    for entry in entries {
        let proofs = entry
            .get("proof")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                ResolutionError::InvalidWitness("witness entry has no proof array".into())
            })?;
        if proofs.len() > MAX_WITNESSES {
            return Err(ResolutionError::ResourceLimit(
                "too many witness proofs".into(),
            ));
        }
        let mut seen = HashSet::new();
        let mut seen_identities = HashSet::new();
        for proof in proofs {
            let identity = (
                proof.get("verificationMethod").and_then(Value::as_str),
                proof.get("proofValue").and_then(Value::as_str),
            );
            if identity.0.is_none() || identity.1.is_none() {
                return Err(ResolutionError::InvalidWitness(
                    "witness proof is missing identity or proof material".into(),
                ));
            }
            if !seen.insert(identity) {
                return Err(ResolutionError::InvalidWitness(
                    "duplicate witness proof is forbidden by the experimental profile".into(),
                ));
            }
            if !seen_identities.insert(identity.0) {
                return Err(ResolutionError::InvalidWitness(
                    "duplicate witness identity is forbidden by the experimental profile".into(),
                ));
            }
        }
    }
    Ok(())
}

async fn verify_every_witnessed_prefix(input: &ResolutionInput) -> Result<(), ResolutionError> {
    let Some(witnesses) = input.raw_witnesses.as_deref() else {
        return Ok(());
    };
    let lines: Vec<&str> = input.raw_log.lines().collect();
    if lines.len() > MAX_WITNESSED_VERSIONS {
        return Err(ResolutionError::ResourceLimit(format!(
            "witnessed history exceeds {MAX_WITNESSED_VERSIONS} versions"
        )));
    }
    for end in 1..=lines.len() {
        let mut prefix = lines[..end].join("\n");
        prefix.push('\n');
        let mut state = DIDWebVHState::default();
        state
            .resolve_log_owned(&input.did, &prefix, Some(witnesses))
            .await
            .map_err(map_webvh_error)?;
    }
    Ok(())
}

#[derive(Clone)]
struct WitnessPolicy {
    threshold: usize,
    identities: HashSet<String>,
}

fn validate_witness_policy(
    history: &[Value],
    raw_witnesses: Option<&str>,
) -> Result<(), ResolutionError> {
    let witness_entries = raw_witnesses
        .map(parse_no_duplicates)
        .transpose()?
        .unwrap_or_else(|| Value::Array(Vec::new()));
    let witness_entries = witness_entries.as_array().ok_or_else(|| {
        ResolutionError::InvalidWitness("witness evidence is not an array".into())
    })?;
    let mut active: Option<WitnessPolicy> = None;
    for (index, entry) in history.iter().enumerate() {
        let declared = parse_witness_policy(entry.pointer("/parameters/witness"))?;
        let required = if index == 0 {
            declared.as_ref()
        } else {
            active.as_ref()
        };
        if let Some(policy) = required {
            let version_id = entry
                .get("versionId")
                .and_then(Value::as_str)
                .ok_or_else(|| ResolutionError::InvalidWitness("missing version id".into()))?;
            let evidence = witness_entries
                .iter()
                .find(|candidate| {
                    candidate.get("versionId").and_then(Value::as_str) == Some(version_id)
                })
                .ok_or_else(|| {
                    ResolutionError::InvalidWitness(format!(
                        "missing witness evidence for {version_id}"
                    ))
                })?;
            let proofs = evidence
                .get("proof")
                .and_then(Value::as_array)
                .ok_or_else(|| {
                    ResolutionError::InvalidWitness("missing witness proof array".into())
                })?;
            let mut distinct = HashSet::new();
            for proof in proofs {
                if proof.get("type").and_then(Value::as_str) != Some("DataIntegrityProof")
                    || proof.get("cryptosuite").and_then(Value::as_str) != Some("eddsa-jcs-2022")
                    || proof.get("proofPurpose").and_then(Value::as_str) != Some("assertionMethod")
                {
                    return Err(ResolutionError::InvalidWitness(
                        "unsupported witness proof profile".into(),
                    ));
                }
                let method = proof
                    .get("verificationMethod")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        ResolutionError::InvalidWitness(
                            "witness proof has no verification method".into(),
                        )
                    })?;
                let identity = method.split_once('#').map_or(method, |(body, _)| body);
                if !policy.identities.contains(identity) {
                    return Err(ResolutionError::InvalidWitness(format!(
                        "unauthorized witness identity: {identity}"
                    )));
                }
                if !distinct.insert(identity) {
                    return Err(ResolutionError::InvalidWitness(
                        "duplicate witness identity is forbidden".into(),
                    ));
                }
            }
            if distinct.len() < policy.threshold {
                return Err(ResolutionError::InvalidWitness(format!(
                    "witness threshold {} not met by {} distinct proofs",
                    policy.threshold,
                    distinct.len()
                )));
            }
        }
        if declared.is_some() {
            active = declared;
        }
    }
    Ok(())
}

fn parse_witness_policy(value: Option<&Value>) -> Result<Option<WitnessPolicy>, ResolutionError> {
    let Some(object) = value.and_then(Value::as_object) else {
        return Ok(None);
    };
    if object.is_empty() {
        return Ok(None);
    }
    let threshold = object
        .get("threshold")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| ResolutionError::InvalidWitness("malformed witness threshold".into()))?;
    let witnesses = object
        .get("witnesses")
        .and_then(Value::as_array)
        .ok_or_else(|| ResolutionError::InvalidWitness("malformed witness list".into()))?;
    if threshold == 0 || threshold > witnesses.len() || witnesses.len() > MAX_WITNESSES {
        return Err(ResolutionError::InvalidWitness(
            "zero, impossible, or oversized witness threshold".into(),
        ));
    }
    let mut identities = HashSet::new();
    for witness in witnesses {
        let id = witness
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| ResolutionError::InvalidWitness("witness has no string id".into()))?;
        if !id.starts_with("did:key:z6Mk") || !identities.insert(id.to_owned()) {
            return Err(ResolutionError::InvalidWitness(
                "unsupported or duplicate witness identity".into(),
            ));
        }
    }
    Ok(Some(WitnessPolicy {
        threshold,
        identities,
    }))
}

fn sha256_hex(value: &[u8]) -> String {
    Sha256::digest(value)
        .iter()
        .fold(String::with_capacity(64), |mut output, byte| {
            write!(output, "{byte:02x}").expect("writing to a String cannot fail");
            output
        })
}

fn map_webvh_error(error: DIDWebVHError) -> ResolutionError {
    match error {
        DIDWebVHError::UnsupportedMethod(message) => ResolutionError::UnsupportedMethod(message),
        DIDWebVHError::InvalidMethodIdentifier(message) => ResolutionError::MalformedInput(message),
        DIDWebVHError::SCIDError(message) => ResolutionError::InvalidScid(message),
        DIDWebVHError::WitnessProofError(message) => ResolutionError::InvalidWitness(message),
        DIDWebVHError::DeactivatedError(_) => ResolutionError::InvalidHistory(
            "unexpected deactivation state without verified tip context".into(),
        ),
        DIDWebVHError::ParametersError(message) if message.contains("method") => {
            ResolutionError::UnsupportedVersion(message)
        }
        DIDWebVHError::ValidationError(message)
        | DIDWebVHError::LogEntryError(message)
        | DIDWebVHError::ParametersError(message)
        | DIDWebVHError::DIDError(message) => ResolutionError::InvalidHistory(message),
        other => ResolutionError::InvalidProof(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn synthetic_output(document: Value) -> ResolutionOutput {
        let did = "did:webvh:QmSynthetic:example.com";
        ResolutionOutput {
            verified_did_document: document,
            resolved_did: did.into(),
            metadata: ResolutionMetadata {
                method: "webvh".into(),
                method_version: "did:webvh:1.0".into(),
                version_id: "1-QmSynthetic".into(),
                version_number: 1,
                version_time: "2000-01-01T00:00:00Z".into(),
                created: "2000-01-01T00:00:00Z".into(),
                updated: "2000-01-01T00:00:00Z".into(),
                deactivated: false,
                complete_history_verified: true,
                conflict_detected: false,
            },
            evidence: Evidence {
                source_kind: SourceKind::LocalFixture,
                source_uri: "test".into(),
                observed_at: "2000-01-01T00:00:00Z".into(),
                log_sha256: "00".repeat(32),
                witness_sha256: None,
                raw_log: String::new(),
                raw_witnesses: None,
                source_attempts: Vec::new(),
            },
            verified_tip: VerifiedTip {
                version_id: "1-QmSynthetic".into(),
                version_number: 1,
                history_prefix_sha256: "00".repeat(32),
                deactivated: false,
            },
        }
    }

    fn document(method: &Value, relationship: &str) -> Value {
        json!({
            "id": "did:webvh:QmSynthetic:example.com",
            "verificationMethod": [method.clone()],
            "authentication": [relationship]
        })
    }

    fn encoded_multikey(multicodec: u64, public_key: &[u8]) -> String {
        let mut buffer = unsigned_varint::encode::u64_buffer();
        let mut payload = unsigned_varint::encode::u64(multicodec, &mut buffer).to_vec();
        payload.extend_from_slice(public_key);
        multibase::encode(Base::Base58Btc, payload)
    }

    fn valid_ed25519_multikey() -> &'static str {
        "z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG"
    }

    fn x25519_public_key() -> [u8; CURVE25519_PUBLIC_KEY_BYTES] {
        [
            0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e,
            0xf7, 0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e,
            0xaa, 0x9b, 0x4e, 0x6a,
        ]
    }

    #[test]
    fn evidence_urls_reject_transformed_urls_over_source_uri_limit() {
        let oversized = format!("https://example.com/{}", "a".repeat(MAX_SOURCE_URI_BYTES));
        assert!(oversized.len() > MAX_SOURCE_URI_BYTES);
        assert!(matches!(
            validate_transformed_url_bounds("https://example.com/did.jsonl", &oversized),
            Err(ResolutionError::ResourceLimit(message))
                if message == "transformed evidence URL exceeds the configured byte limit"
        ));
    }

    #[test]
    fn decoded_multikey_profile_accepts_valid_ed25519_and_x25519() {
        let ed25519 = decode_multikey(valid_ed25519_multikey()).unwrap();
        assert_eq!(ed25519.multicodec, ED25519_PUB_MULTICODEC);
        assert_eq!(ed25519.public_key.len(), CURVE25519_PUBLIC_KEY_BYTES);

        let x25519_value = encoded_multikey(X25519_PUB_MULTICODEC, &x25519_public_key());
        let x25519 = decode_multikey(&x25519_value).unwrap();
        assert_eq!(x25519.multicodec, X25519_PUB_MULTICODEC);
        assert_eq!(x25519.public_key, x25519_public_key());
    }

    #[test]
    fn decoded_multikey_profile_rejects_prefixes_malformed_data_and_unsupported_codecs() {
        let incomplete = multibase::encode(Base::Base58Btc, [0x80]);
        let unsupported = encoded_multikey(0x1200, &[7; CURVE25519_PUBLIC_KEY_BYTES]);
        let non_base58 = {
            let (_, payload) = multibase::decode(valid_ed25519_multikey()).unwrap();
            multibase::encode(Base::Base64, payload)
        };
        let noncanonical = {
            let mut payload = vec![0xed, 0x81, 0x00];
            payload.extend_from_slice(
                &decode_multikey(valid_ed25519_multikey())
                    .unwrap()
                    .public_key,
            );
            multibase::encode(Base::Base58Btc, payload)
        };
        for value in [
            "z6MkTestOnlyMaterial".to_owned(),
            "z6LSTestOnlyMaterial".to_owned(),
            "z0".to_owned(),
            "z".to_owned(),
            incomplete,
            unsupported,
            non_base58,
            noncanonical,
        ] {
            assert!(
                matches!(
                    decode_multikey(&value),
                    Err(ResolutionError::InvalidKeyMaterial(_))
                ),
                "accepted invalid material {value}"
            );
        }
    }

    #[test]
    fn fake_prefix_material_is_rejected() {
        for value in ["z6MkTestOnlyMaterial", "z6LSTestOnlyMaterial"] {
            assert!(matches!(
                decode_multikey(value),
                Err(ResolutionError::InvalidKeyMaterial(_))
            ));
        }
    }

    #[test]
    fn all_zero_x25519_multikey_is_rejected() {
        let value = encoded_multikey(X25519_PUB_MULTICODEC, &[0; CURVE25519_PUBLIC_KEY_BYTES]);
        let (base, payload) = multibase::decode(&value).unwrap();
        assert_eq!(base, Base::Base58Btc);
        let (multicodec, public_key) = unsigned_varint::decode::u64(&payload).unwrap();
        assert_eq!(multicodec, X25519_PUB_MULTICODEC);
        assert_eq!(public_key.len(), CURVE25519_PUBLIC_KEY_BYTES);
        assert!(public_key.iter().all(|byte| *byte == 0));

        assert!(matches!(
            decode_multikey(&value),
            Err(ResolutionError::InvalidKeyMaterial(message))
                if message == "X25519 all-zero public key is not permitted by the experimental profile"
        ));
    }

    #[test]
    fn decoded_multikey_profile_enforces_raw_key_length_after_multicodec() {
        for (codec, length) in [
            (ED25519_PUB_MULTICODEC, 31),
            (ED25519_PUB_MULTICODEC, 33),
            (X25519_PUB_MULTICODEC, 31),
            (X25519_PUB_MULTICODEC, 33),
        ] {
            let value = encoded_multikey(codec, &vec![7; length]);
            assert!(matches!(
                decode_multikey(&value),
                Err(ResolutionError::InvalidKeyMaterial(_))
            ));
        }
    }

    #[test]
    fn ac4_malformed_material_matrix_returns_typed_errors() {
        let did = "did:webvh:QmSynthetic:example.com";
        let id = format!("{did}#key-1");
        let method = |material: String| {
            json!({
                "id": id,
                "controller": did,
                "type": "Multikey",
                "publicKeyMultibase": material
            })
        };
        let valid_ed = valid_ed25519_multikey().to_owned();
        let valid_x = encoded_multikey(X25519_PUB_MULTICODEC, &x25519_public_key());
        let non_base58 = {
            let (_, payload) = multibase::decode(&valid_ed).unwrap();
            multibase::encode(Base::Base64, payload)
        };
        let incomplete = multibase::encode(Base::Base58Btc, [0x80]);
        let unsupported = encoded_multikey(0x1200, &[7; CURVE25519_PUBLIC_KEY_BYTES]);

        for (label, material) in [
            ("fake Ed25519 prefix", "z6MkTestOnlyMaterial".to_owned()),
            ("fake X25519 prefix", "z6LSTestOnlyMaterial".to_owned()),
            ("unsupported Multibase", non_base58),
            ("invalid Base58BTC character", "z0".to_owned()),
            ("empty encoded payload", "z".to_owned()),
            ("incomplete Multicodec", incomplete),
            ("unsupported Multicodec", unsupported),
            (
                "Ed25519 one byte short",
                encoded_multikey(ED25519_PUB_MULTICODEC, &[7; 31]),
            ),
            (
                "Ed25519 one byte long",
                encoded_multikey(ED25519_PUB_MULTICODEC, &[7; 33]),
            ),
            (
                "X25519 one byte short",
                encoded_multikey(X25519_PUB_MULTICODEC, &[7; 31]),
            ),
            (
                "X25519 one byte long",
                encoded_multikey(X25519_PUB_MULTICODEC, &[7; 33]),
            ),
        ] {
            assert!(
                matches!(
                    validate_selected_method(&method(material), did, "authentication"),
                    Err(ResolutionError::InvalidKeyMaterial(_))
                ),
                "{label} did not return InvalidKeyMaterial"
            );
        }

        assert!(matches!(
            validate_selected_method(&method(valid_x), did, "authentication"),
            Err(ResolutionError::MissingRelationship(_))
        ));
        assert!(matches!(
            validate_selected_method(&method(valid_ed), did, "keyAgreement"),
            Err(ResolutionError::MissingRelationship(_))
        ));

        for invalid in [
            json!({ "id": id, "controller": 7, "type": "Multikey", "publicKeyMultibase": valid_ed25519_multikey() }),
            json!({ "id": id, "controller": "did:webvh:attacker:example.com", "type": "Multikey", "publicKeyMultibase": valid_ed25519_multikey() }),
            json!({ "id": id, "controller": did, "type": "JsonWebKey2020", "publicKeyMultibase": valid_ed25519_multikey() }),
            json!({ "id": id, "controller": did, "type": "Multikey", "publicKeyMultibase": valid_ed25519_multikey(), "publicKeyJwk": {} }),
            json!({ "id": id, "controller": did, "type": "Multikey", "publicKeyMultibase": valid_ed25519_multikey(), "publicKeyBase58": "not-used" }),
            json!({ "id": id, "controller": did, "type": "Multikey", "publicKeyMultibase": valid_ed25519_multikey(), "secretKeyMultibase": "must-never-be-accepted" }),
            json!({ "id": id, "controller": did, "type": "Multikey", "publicKeyMultibase": valid_ed25519_multikey(), "revoked": "2000-01-01T00:00:00Z" }),
        ] {
            assert!(matches!(
                validate_selected_method(&invalid, did, "authentication"),
                Err(ResolutionError::MissingRelationship(_))
            ));
        }
    }

    #[test]
    fn experimental_key_profile_rejects_wrong_controller_type_and_material() {
        let id = "did:webvh:QmSynthetic:example.com#key-1";
        let valid = json!({
            "id": id,
            "controller": "did:webvh:QmSynthetic:example.com",
            "type": "Multikey",
            "publicKeyMultibase": valid_ed25519_multikey()
        });
        assert_eq!(
            synthetic_output(document(&valid, id))
                .authorized_keys("authentication")
                .unwrap()
                .len(),
            1
        );
        for invalid in [
            json!({ "id": id, "controller": "did:webvh:attacker:example.com", "type": "Multikey", "publicKeyMultibase": "z6MkTestOnlyMaterial" }),
            json!({ "id": id, "controller": "did:webvh:QmSynthetic:example.com", "type": "JsonWebKey2020", "publicKeyMultibase": "z6MkTestOnlyMaterial" }),
            json!({ "id": "did:webvh:other:example.com#key-1", "controller": "did:webvh:QmSynthetic:example.com", "type": "Multikey", "publicKeyMultibase": valid_ed25519_multikey() }),
            json!({ "id": id, "controller": "did:webvh:QmSynthetic:example.com", "type": "Multikey", "publicKeyJwk": {} }),
            json!({ "id": id, "controller": "did:webvh:QmSynthetic:example.com", "type": "Multikey", "publicKeyMultibase": "", "publicKeyJwk": {} }),
        ] {
            assert!(
                synthetic_output(document(&invalid, id))
                    .authorized_keys("authentication")
                    .is_err()
            );
        }
    }

    #[test]
    fn experimental_key_profile_rejects_duplicate_ids_references_and_substitution() {
        let did = "did:webvh:QmSynthetic:example.com";
        let id = format!("{did}#key-1");
        let method = json!({
            "id": id,
            "controller": did,
            "type": "Multikey",
            "publicKeyMultibase": valid_ed25519_multikey()
        });
        let duplicate_id = json!({
            "id": did,
            "verificationMethod": [method.clone(), method.clone()],
            "authentication": [id]
        });
        assert!(
            synthetic_output(duplicate_id)
                .authorized_keys("authentication")
                .is_err()
        );
        let duplicate_reference = json!({
            "id": did,
            "verificationMethod": [method.clone()],
            "authentication": [id, id]
        });
        assert!(
            synthetic_output(duplicate_reference)
                .authorized_keys("authentication")
                .is_err()
        );
        let wrong_relationship = json!({
            "id": did,
            "verificationMethod": [method],
            "keyAgreement": [format!("{did}#key-1")]
        });
        assert!(
            synthetic_output(wrong_relationship)
                .authorized_keys("keyAgreement")
                .is_err()
        );
    }

    #[test]
    fn authoritative_dangling_relationship_reference_is_rejected() {
        let did = "did:webvh:QmSynthetic:example.com";
        let method_id = format!("{did}#key-1");
        let dangling_id = format!("{did}#missing-key");
        let authoritative_document = json!({
            "id": did,
            "verificationMethod": [{
                "id": method_id,
                "controller": did,
                "type": "Multikey",
                "publicKeyMultibase": valid_ed25519_multikey()
            }],
            "authentication": [dangling_id]
        });

        // This module-private test constructor installs the document directly
        // as private authoritative state; no public forged-state constructor or
        // detached presentation-copy mutation is involved.
        let output = synthetic_output(authoritative_document);
        assert!(
            output.did_document()["verificationMethod"]
                .as_array()
                .unwrap()
                .iter()
                .all(|method| method["id"] != dangling_id)
        );
        assert!(matches!(
            output.authorized_keys("authentication"),
            Err(ResolutionError::MissingRelationship(message))
                if message == format!(
                    "authentication references unknown verification method {dangling_id}"
                )
        ));
    }

    fn witness_identity(index: usize) -> String {
        format!("did:key:z6MkWitness{index}")
    }

    fn structural_witness_case(
        threshold: usize,
        witness_count: usize,
        proof_indexes: &[usize],
    ) -> Result<(), ResolutionError> {
        let witnesses: Vec<Value> = (0..witness_count)
            .map(|index| json!({ "id": witness_identity(index) }))
            .collect();
        let history = vec![json!({
            "versionId": "1-QmWitnessMatrix",
            "parameters": { "witness": { "threshold": threshold, "witnesses": witnesses } }
        })];
        let proofs: Vec<Value> = proof_indexes
            .iter()
            .map(|index| {
                let identity = witness_identity(*index);
                json!({
                    "type": "DataIntegrityProof",
                    "cryptosuite": "eddsa-jcs-2022",
                    "verificationMethod": format!("{identity}#z6MkWitness{index}"),
                    "proofPurpose": "assertionMethod",
                    "proofValue": format!("zProof{index}")
                })
            })
            .collect();
        let evidence = serde_json::to_string(&json!([{
            "versionId": "1-QmWitnessMatrix",
            "proof": proofs
        }]))
        .unwrap();
        validate_witness_policy(&history, Some(&evidence))
    }

    #[test]
    fn witness_threshold_structural_matrix_counts_distinct_authorized_identities() {
        for (threshold, witnesses, proofs) in [
            (1, 1, vec![0]),
            (1, 3, vec![1]),
            (1, 3, vec![0, 1, 2]),
            (2, 2, vec![0, 1]),
            (2, 3, vec![0, 2]),
            (2, 3, vec![0, 1, 2]),
        ] {
            assert!(structural_witness_case(threshold, witnesses, &proofs).is_ok());
        }
        for (threshold, witnesses, proofs) in [
            (2, 3, vec![0]),
            (0, 1, vec![]),
            (2, 1, vec![0]),
            (1, 2, vec![0, 0]),
            (1, 1, vec![1]),
        ] {
            assert!(structural_witness_case(threshold, witnesses, &proofs).is_err());
        }
    }
}
