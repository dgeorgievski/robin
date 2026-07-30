use crate::{DidResolver, ResolutionInput, WebvhResolver};
use wasm_bindgen::prelude::*;

/// Resolve caller-supplied `did:webvh` evidence entirely inside the WASM module.
///
/// The browser host remains responsible for network transport, DNS, TLS, CORS,
/// redirects, timeouts, and cancellation. The verified raw evidence is returned
/// so it can be cached and compared by the application.
#[wasm_bindgen]
pub async fn resolve_webvh(input_json: String) -> Result<String, JsValue> {
    let input: ResolutionInput = serde_json::from_str(&input_json)
        .map_err(|error| JsValue::from_str(&format!("malformed input: {error}")))?;
    let output = WebvhResolver
        .resolve(input)
        .await
        .map_err(|error| JsValue::from_str(&error.to_string()))?;
    serde_json::to_string(&output)
        .map_err(|error| JsValue::from_str(&format!("serialization failed: {error}")))
}
