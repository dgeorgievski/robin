//! Experimental, method-independent DID resolution boundary.
//!
//! This crate is evidence-gathering code for ROB-2. It is not a production
//! resolver and does not approve `did:webvh` or any cryptographic suite for
//! Robin. Cryptographic and method validation is delegated to the pinned
//! `didwebvh-rs` implementation.

mod resolver;

pub use resolver::{
    AuthorizedKey, DidResolver, Evidence, EvidenceFetcher, EvidenceSource, FetchError,
    FetchedEvidence, Freshness, MAX_DID_BYTES, MAX_SOURCE_URI_BYTES, ResolutionError,
    ResolutionInput, ResolutionMetadata, ResolutionOutput, SourceAttempt, SourceKind,
    TransportPolicy, VerifiedTip, WebvhResolver,
};

#[cfg(feature = "wasm")]
mod wasm;
