use robin_did_resolver_spike::{
    CompleteHistoryManifest, DidResolver, Freshness, LifecycleSnapshot, ResolutionError,
    ResolutionInput, WebvhResolver, import_complete_history,
};
use serde::Deserialize;
use serde_json::json;
use std::io::{self, Read};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImportRequest {
    did: String,
    raw_log: String,
    expected_version_id: String,
    expected_entry_count: usize,
    #[serde(default)]
    deactivated: bool,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let mut request = String::new();
    io::stdin()
        .read_to_string(&mut request)
        .expect("read public lifecycle request from stdin");
    let request: ImportRequest = serde_json::from_str(&request).expect("parse public request");
    let input = ResolutionInput {
        did: request.did,
        raw_log: request.raw_log,
        raw_witnesses: None,
        source_kind: robin_did_resolver_spike::SourceKind::ImportedPackage,
        source_uri: "pinned-independent-runtime://ROB-4/public-history".into(),
        observed_at: "2026-08-10T00:00:00Z".into(),
        freshness: Freshness::default(),
    };
    if request.deactivated {
        match WebvhResolver.resolve(input).await {
            Err(ResolutionError::Deactivated(tip)) => {
                println!(
                    "{}",
                    serde_json::to_string(&json!({
                        "deactivated": true,
                        "versionId": tip.version_id,
                        "versionNumber": tip.version_number
                    }))
                    .expect("serialize deactivation result")
                );
            }
            other => panic!("expected terminal deactivation, got {other:?}"),
        }
        return;
    }
    let manifest = CompleteHistoryManifest {
        expected_version_id: request.expected_version_id,
        expected_entry_count: request.expected_entry_count,
    };
    let output = import_complete_history(input, &manifest)
        .await
        .expect("independent complete history must verify locally");
    let snapshot = LifecycleSnapshot::from_verified(&output).expect("verified snapshot");
    println!(
        "{}",
        serde_json::to_string(&snapshot).expect("serialize verified snapshot")
    );
}
