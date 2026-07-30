use robin_did_resolver_spike::{DidResolver, ResolutionInput, SourceKind, WebvhResolver};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let input: ResolutionInput =
        serde_json::from_str(include_str!("../tests/fixtures/basic-create/input.json"))
            .expect("fixture input must parse");
    assert_eq!(input.source_kind, SourceKind::LocalFixture);
    let output = WebvhResolver
        .resolve(input)
        .await
        .expect("authoritative fixture must resolve");
    println!(
        "{} {} {}",
        output.did_document["id"], output.metadata.version_id, output.evidence.log_sha256
    );
}
