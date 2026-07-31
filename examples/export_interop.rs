use robin_did_resolver_spike::{DidResolver, ResolutionInput, WebvhResolver};
use serde_json::json;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "log".into());
    let input: ResolutionInput =
        serde_json::from_str(include_str!("../tests/fixtures/basic-create/input.json"))
            .expect("pinned fixture must parse");
    let output = WebvhResolver
        .resolve(input)
        .await
        .expect("pinned fixture must resolve");
    match mode.as_str() {
        "log" => print!("{}", output.evidence.raw_log),
        "result" => println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "didResolutionMetadata": { "contentType": "application/did+ld+json" },
                "didDocument": output.did_document(),
                "didDocumentMetadata": {
                    "versionId": output.metadata.version_id,
                    "created": output.metadata.created,
                    "updated": output.metadata.updated,
                    "deactivated": false
                }
            }))
            .expect("interop result must serialize")
        ),
        other => panic!("unsupported export mode: {other}"),
    }
}
