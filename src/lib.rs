//! Experimental, method-independent DID resolution and lifecycle boundary.
//!
//! This crate is evidence-gathering code for ROB-2 and ROB-4. It is not a
//! production resolver or identity writer and does not approve any
//! cryptographic suite for Robin. Cryptographic and method validation is
//! delegated to the pinned `didwebvh-rs` implementation.

mod lifecycle;
mod resolver;

pub use lifecycle::{
    CompleteHistoryManifest, CompleteImportError, DiffClassification, LifecycleComparison,
    LifecycleProfileError, LifecycleSnapshot, compare_lifecycle_snapshots, import_complete_history,
    validate_robin_creation_profile,
};

pub use resolver::{
    AuthorizedKey, DidResolver, DownloadFailureKind, Evidence, EvidenceFetcher, EvidenceSource,
    FetchError, FetchedEvidence, Freshness, LocalFailureKind, MAX_DID_BYTES, MAX_SOURCE_URI_BYTES,
    ResolutionError, ResolutionInput, ResolutionMetadata, ResolutionOutput, SourceAttempt,
    SourceAttemptOutcome, SourceAttemptPhase, SourceKind, TransportFailureKind, TransportPolicy,
    VerifiedTip, WebvhResolver,
};

#[cfg(feature = "wasm")]
mod wasm;
