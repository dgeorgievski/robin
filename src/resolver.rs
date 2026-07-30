use async_trait::async_trait;
use didwebvh_rs::url::WebVHURL;
use didwebvh_rs::{DIDWebVHError, DIDWebVHState, log_entry::LogEntryMethods};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fmt::Write;
use thiserror::Error;

/// Maximum accepted `did.jsonl` size for the deterministic client verifier.
pub const MAX_LOG_BYTES: usize = 200 * 1024;
/// Maximum accepted witness file size.
pub const MAX_WITNESS_BYTES: usize = 200 * 1024;
/// Maximum history entries accepted in one resolution.
pub const MAX_HISTORY_ENTRIES: usize = 1_024;
/// Maximum bytes accepted in one JSONL entry.
pub const MAX_ENTRY_BYTES: usize = 64 * 1024;

/// Browser/native transport requirements imposed before method verification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransportPolicy {
    pub timeout_millis: u64,
    pub retries: u8,
    pub max_redirects: u8,
    pub max_response_bytes: usize,
    pub max_concurrency: u8,
}

impl Default for TransportPolicy {
    fn default() -> Self {
        Self {
            timeout_millis: 10_000,
            retries: 1,
            max_redirects: 0,
            max_response_bytes: MAX_LOG_BYTES,
            max_concurrency: 2,
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
}

/// Untrusted bytes returned by a policy-enforcing host transport.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetchedEvidence {
    pub raw_log: String,
    pub raw_witnesses: Option<String>,
    pub observed_at: String,
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
}

/// Caller-provided freshness and rollback context.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Freshness {
    pub known_version_id: Option<String>,
    pub known_log_sha256: Option<String>,
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
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolutionOutput {
    pub did_document: Value,
    pub metadata: ResolutionMetadata,
    pub evidence: Evidence,
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
    #[error("DID is deactivated")]
    Deactivated,
    #[error("stale or rolled-back DID state: {0}")]
    StaleState(String),
    #[error("conflicting DID state: {0}")]
    Conflict(String),
    #[error("required verification relationship is absent or invalid: {0}")]
    MissingRelationship(String),
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
        let parsed = WebVHURL::parse_did_url(did).map_err(map_webvh_error)?;
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
        Ok((log.into(), witness.into()))
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
        if policy.max_redirects != 0
            || policy.max_response_bytes > MAX_LOG_BYTES
            || policy.max_concurrency == 0
            || policy.max_concurrency > 2
        {
            return Err(ResolutionError::NetworkUnavailable(
                "transport policy exceeds Robin safety bounds".into(),
            ));
        }
        let (log_url, witness_url) = Self::evidence_urls(did)?;
        let downloaded = fetcher
            .fetch(&log_url, &witness_url, policy)
            .await
            .map_err(|error| ResolutionError::NetworkUnavailable(error.to_string()))?;
        if downloaded.raw_log.len() > policy.max_response_bytes
            || downloaded
                .raw_witnesses
                .as_ref()
                .is_some_and(|value| value.len() > MAX_WITNESS_BYTES)
        {
            return Err(ResolutionError::ResourceLimit(
                "transport returned evidence beyond its declared bounds".into(),
            ));
        }
        self.resolve(ResolutionInput {
            did: did.into(),
            raw_log: downloaded.raw_log,
            raw_witnesses: downloaded.raw_witnesses,
            source_kind: SourceKind::DirectHttps,
            source_uri: log_url,
            observed_at: downloaded.observed_at,
            freshness,
        })
        .await
    }
}

#[async_trait(?Send)]
impl DidResolver for WebvhResolver {
    async fn resolve(&self, input: ResolutionInput) -> Result<ResolutionOutput, ResolutionError> {
        validate_envelope(&input)?;

        let log_digest = sha256_hex(input.raw_log.as_bytes());
        let witness_digest = input
            .raw_witnesses
            .as_deref()
            .map(|value| sha256_hex(value.as_bytes()));

        let mut state = DIDWebVHState::default();
        let (entry, metadata) = state
            .resolve_log_owned(&input.did, &input.raw_log, input.raw_witnesses.as_deref())
            .await
            .map_err(map_webvh_error)?;

        enforce_freshness(
            &input.freshness,
            &metadata.version_id,
            metadata.version_number,
            &log_digest,
        )?;

        if metadata.deactivated {
            return Err(ResolutionError::Deactivated);
        }

        let did_document = entry
            .get_did_document()
            .map_err(|error| ResolutionError::InvalidHistory(error.to_string()))?;

        Ok(ResolutionOutput {
            did_document,
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
            },
        })
    }
}

impl ResolutionOutput {
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

        let document = self.did_document.as_object().ok_or_else(|| {
            ResolutionError::MalformedInput("DID Document is not an object".into())
        })?;
        let methods = document
            .get("verificationMethod")
            .and_then(Value::as_array)
            .ok_or_else(|| ResolutionError::MissingRelationship("verificationMethod".into()))?;
        let authorized = document
            .get(relationship)
            .and_then(Value::as_array)
            .ok_or_else(|| ResolutionError::MissingRelationship(relationship.into()))?;

        let mut seen = HashSet::new();
        let mut selected = Vec::new();
        for item in authorized {
            let method = if let Some(reference) = item.as_str() {
                methods
                    .iter()
                    .find(|candidate| {
                        candidate.get("id").and_then(Value::as_str) == Some(reference)
                    })
                    .ok_or_else(|| {
                        ResolutionError::MissingRelationship(format!(
                            "{relationship} references unknown verification method {reference}"
                        ))
                    })?
                    .clone()
            } else if item.is_object() {
                item.clone()
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
            if seen.insert(id.clone()) {
                selected.push(AuthorizedKey {
                    id,
                    relationship: relationship.into(),
                    verification_method: method,
                });
            }
        }
        if selected.is_empty() {
            return Err(ResolutionError::MissingRelationship(relationship.into()));
        }
        Ok(selected)
    }
}

fn validate_envelope(input: &ResolutionInput) -> Result<(), ResolutionError> {
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
    let mut count = 0usize;
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
    let mut first = None;
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
        let object = parsed.as_object().ok_or_else(|| {
            ResolutionError::MalformedInput("log entry is not a JSON object".into())
        })?;
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
        if first.is_none() {
            first = Some(parsed);
        }
    }
    if count == 0 {
        return Err(ResolutionError::MalformedInput("empty DID log".into()));
    }

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
    resolved_version_id: &str,
    resolved_version_number: u32,
    resolved_digest: &str,
) -> Result<(), ResolutionError> {
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
        DIDWebVHError::DeactivatedError(_) => ResolutionError::Deactivated,
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
