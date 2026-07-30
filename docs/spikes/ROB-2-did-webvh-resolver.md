# ROB-2 — Rust/WASM `did:webvh` adversarial resolver spike

Status: experimental Construction evidence; no production Design approval.

## Scope and architecture

`DidResolver` accepts raw method evidence plus provenance and cached freshness
context. `WebvhResolver` is the only method adapter. It delegates the
`did:webvh` cryptographic and history rules to a pinned established
implementation and returns a method-neutral DID Document, metadata, raw
evidence, evidence digests, freshness information, and typed failures.

This crate has no secret-sharing or document-management code. A future method
adapter can implement `DidResolver` without changing those consumers.

The core path performs no network I/O. A browser or native transport must fetch
raw evidence within a separately reviewed policy and treat it as untrusted
until this verifier succeeds. A remote universal resolver is neither required
nor trusted.

## Normative and implementation pins

Accessed 2026-07-30:

- `did:webvh` DID Method Specification v1.0, DIF-hosted source commit
  `e426f93e9682bf53952f15b1803f426be5c57fa0`
  (`spec-v1.0/`, specification status v1.0).
- `didwebvh-rs` 0.6.0, source commit
  `d3cc50049320445ac49eda2b85b8afb5429434be`, consumed as the exact
  crates.io version `=0.6.0` and transitively pinned by `Cargo.lock`.
- DIF `didwebvh-test-suite`, commit
  `f792ce4568c8c3efb3b6a055a1c2ba963dc00c35`. Vendored fixtures retain
  source paths in test input provenance.
- Rust toolchain observed: `rustc 1.96.0 (ac68faa20 2026-05-25)` and
  `cargo 1.96.0 (30a34c682 2026-05-25)`. The crate declares MSRV 1.95,
  matching `didwebvh-rs` 0.6.0.

The method-mandated v1.0 algorithms are SHA-256, multihash/base58btc, JCS
(RFC 8785), and `eddsa-jcs-2022`. Robin does not choose or reimplement them in
this spike; the pinned dependency verifies them solely to measure
compatibility. This is not a production cryptographic approval.

## Enforced local policy limits

- DID log: 200 KiB.
- Witness file: 200 KiB.
- History: 1,024 entries.
- Single JSONL entry: 64 KiB.
- Supported method/version: exactly `did:webvh` / `did:webvh:1.0`.
- Rollback: reject a version lower than the caller's cached tip.
- Conflict: reject different identifiers at the same version number, or
  different evidence bytes for the same cached version identifier.

The transport layer must separately bound response size while streaming,
timeouts, retries, redirects, concurrency, and DNS resolution. Browser WASM
cannot directly control DNS, TLS, CORS, service workers/extensions, or its
hosting origin.

## Stage 1 evidence

Commands run from the repository root on 2026-07-30:

```text
cargo fmt --all
make test
make lint
make run
```

Observed:

- 11 tests passed; 0 failed; 0 ignored.
- Formatting passed.
- Clippy passed with all features and `-D warnings`.
- The example resolved the independently generated TypeScript inception
  fixture to version
  `1-QmRqMp6AtLbWzMyLa6ZdCjiQXo1HaLpUStJFwqAMY7pVfo`.
- Positive TypeScript inception and two-entry update histories verified.
- Altered SCID/inception, malformed JSON, unsupported method/version, removed
  or changed proof, skipped/duplicated/reordered/modified/unsigned entry,
  non-monotonic/future time, oversize input, excess history, rollback, and
  same-version conflict cases failed closed.

Stage 1 assessment:

- AC-1: PASS for the in-memory method-neutral boundary, evidence provenance,
  freshness/conflict inputs, and typed boundary failures.
- AC-2: PASS for the pinned independent TypeScript inception fixture and
  listed negative mutations.
- AC-3: PASS for a complete two-entry authorized update and listed chain,
  predecessor, time, proof, and mutation failures. Coverage-guided fuzzing is
  not yet run; the deterministic mutation set is the Stage 1 evidence.

## Stage 2 evidence

Additional command:

```text
cargo test --locked --test stage2
```

Observed: 8 passed, 0 failed, 0 ignored.

- AC-4: PASS for exact relationship selection behavior. A verified independent
  fixture selects only its `authentication` key; unit evidence adds a distinct
  `keyAgreement` relationship and proves that dangling, malformed, empty, and
  unsupported relationships fail. This does not approve the illustrative
  key-agreement value as production cryptography.
- AC-5: PASS against independent TypeScript pre-rotation inception and
  three-version consumption vectors. Wrong and omitted reveals fail.
- AC-6: PASS for a valid independent witness vector and failures for absent,
  changed-key, changed-signature, replayed-version, and did:key
  body/fragment-mismatch evidence. A duplicate proof does not change the
  distinct-witness outcome. The upstream suite's witness-update interpretation
  remains a documented interoperability risk.
- AC-7: PASS: an independently generated authorized deactivation history
  returns the typed `Deactivated` result and no DID Document.
- AC-8: PASS at the method boundary for cached lower-version rollback,
  same-version identifier conflict, and same-tip evidence-digest conflict.
  Cross-source watcher quorum and persistent browser caching remain
  application-level logic outside the method verifier.

## Stage 3 evidence

Commands and observed results:

```text
cargo test --locked --test stage3
# 9 passed; 0 failed; 0 ignored

make test
# 28 passed; 0 failed; 0 ignored

make lint
# PASS

make wasm-check
# PASS for wasm32-unknown-unknown with features=wasm, default features disabled
```

The optimized package was built with Rustup stable 1.97.1 and
`wasm-bindgen-cli` 0.2.126:

```text
PATH=$HOME/.cargo/bin:$PATH rustup run stable cargo build --locked --release \
  --target wasm32-unknown-unknown --features wasm --no-default-features
wasm-bindgen --target web --out-dir target/browser-release \
  target/wasm32-unknown-unknown/release/robin_did_resolver_spike.wasm
```

The raw optimized module was 2,058,942 bytes and the binding-processed module
was 1,572,445 bytes before HTTP compression. Size optimization was not
attempted; this is feasible but material for a Web client.

A temporary localhost page loaded the optimized module in Chromium and invoked
the exported async `resolve_webvh` function over the pinned fixture. Visible
result:

```text
PASS did:webvh:QmUy89VrfryQ254CeHZzQfmcKqByPoKNGqYykP3SeXuegQ:example.com
1-QmRqMp6AtLbWzMyLa6ZdCjiQXo1HaLpUStJFwqAMY7pVfo
```

Chromium recorded zero console errors and zero warnings on the final run. The
integrated browser surface was unavailable, so the installed Playwright
Chromium runner was used as the real-browser fallback.

Stage 3 assessment:

- AC-9: PASS for bounded log/witness/entry/history sizes, deep nesting,
  malformed escape, repeated keys, unknown method parameters, 64 deterministic
  signature mutations, IP/local-host/path/separator/fragment attacks, and
  no-panic fail-closed outcomes. Coverage-guided fuzzing was not run; mutation
  testing is the selected issue-AC evidence type.
- AC-10: PASS for a method-specific fixed HTTPS transformation; IP and
  localhost refusal; no redirects; bounded response/concurrency policy; and
  deterministic fail-closed DNS, TLS, CORS, timeout, 404, 5xx, redirect,
  oversize, and unavailable transport outcomes. A host fetcher must additionally
  reject private/reserved addresses after every DNS resolution to prevent DNS
  rebinding; the WASM verifier cannot perform that browser-host check.
- AC-11: PASS for compilation and actual Chromium execution of local SCID,
  hash-chain, JCS/Data Integrity, and DID Document resolution. Browser WASM
  cannot directly control DNS, TLS certificate processing, CORS, browser
  extensions, service workers, the JavaScript host, cancellation of a host
  fetch, or hosting-origin compromise. Those remain explicit host trust
  boundaries.
- AC-12: PASS against pinned TypeScript-generated cross-implementation suite
  vectors for inception, update, pre-rotation, witnesses, and deactivation.
  Witness-update semantics remain a known upstream disagreement, so this is
  positive compatibility evidence rather than full ecosystem equivalence.

No live network endpoint is required by the core verifier. This reduces
resolver privacy leakage and permits deterministic offline verification of
previously acquired evidence, but freshness still requires a new authorized
source retrieval and cached-tip comparison.

## AC-13 evidence and handoff map

All paths are repository-relative. Exact fixture provenance is embedded in
`ResolutionInput.source_uri` or listed above.

| AC | Status | Files and fixtures | Exact command and observed result | Checks not run, limitations, residual risk |
|---|---|---|---|---|
| AC-1 | PASS | `src/resolver.rs`, `src/lib.rs`, `tests/stage1.rs` | `make test`: boundary tests included in 28/28 pass | Only `did:webvh` adapter exists; persistence and consumers are out of spike scope. |
| AC-2 | PASS | `tests/fixtures/basic-create/input.json`, `tests/stage1.rs` | `cargo test --locked --test stage1`: 11/11 pass | Independent TypeScript fixture plus deterministic mutations; no second resolver executed live. |
| AC-3 | PASS | `tests/fixtures/basic-update/did.jsonl`, `tests/stage1.rs` | same Stage 1 command: positive two-entry chain and listed mutations pass | Mutation tests, not coverage-guided fuzzing; engine remains upstream code. |
| AC-4 | PASS | `src/resolver.rs::authorized_keys`, `tests/stage2.rs` | `cargo test --locked --test stage2`: 8/8 pass | Key-agreement value is structural test evidence, not a production algorithm/key approval. |
| AC-5 | PASS | `tests/fixtures/pre-rotation*`, `tests/stage2.rs` | Stage 2 command: inception/three-version positive plus wrong/omitted reveal pass | Secure generation/storage/destruction of unrevealed keys is controller-side and not tested. |
| AC-6 | PASS | `tests/fixtures/witness-threshold`, `tests/stage2.rs` | Stage 2 command: positive, missing, tampered, replay, body/fragment, duplicate cases pass | Witness-update interpretation differs upstream; reputation/availability not tested. |
| AC-7 | PASS | `tests/fixtures/deactivate/did.jsonl`, `tests/stage2.rs` | Stage 2 command: typed deactivation and no document pass | Historical query behavior after deactivation is delegated upstream and not exercised. |
| AC-8 | PASS | `Freshness`, `enforce_freshness`, Stage 1 tests | Stage 1 command: lower tip, same-version ID, and same-tip digest conflicts pass | Durable cache/watchers and multi-source fork convergence are application-level. |
| AC-9 | PASS | envelope limits/duplicate parser in `src/resolver.rs`, `tests/stage1.rs`, `tests/stage3.rs` | `cargo test --locked --test stage3`: 9/9 pass; overall 28/28 | No coverage-guided fuzzer or performance benchmark; resource bounds are provisional. |
| AC-10 | PASS | `TransportPolicy`, `EvidenceFetcher`, `evidence_urls`, `tests/stage3.rs` | Stage 3 command: all injected transport errors and hostile URLs pass | Live DNS/TLS/CORS not used; host must enforce post-DNS address policy/rebinding defense. |
| AC-11 | PASS | `src/wasm.rs`, `tests/browser/index.html`, `Makefile` | `make wasm-check`: pass; optimized Chromium run: expected PASS, console 0 errors/warnings | One desktop Chromium run; 1.57 MB processed module; browser host controls transport/origin. |
| AC-12 | PASS | all vendored TypeScript fixtures, lifecycle interop test | Stage 3 command: inception/update/pre-rotation/witness vectors pass; deactivation separately pass | Positive compatibility evidence only; no claim of full equivalence amid known suite disagreement. |
| AC-13 | PASS | this document, README, Cargo/Make files and all tests | final `make test`, `make lint`, `make run`, `make wasm-check` required before checkpoint | Independent QAS and Security Review intentionally not performed by Developer. |

## Final Construction assessment

Recommendation: **PROCEED to independent QAS and Security Review with
revisions required before any production Design approval**.

The spike provides enough evidence that a method-neutral, client-side
`did:webvh:1.0` verification adapter is technically feasible in Rust/WASM and
can fail closed across the exercised lifecycle and adversarial cases. It does
not establish production readiness. In particular:

- resolve the upstream witness-update semantic disagreement;
- obtain an independent security review of the pinned dependency graph and
  Robin's transport/trust boundaries;
- decide and test persistent rollback/fork storage and watcher policy;
- add post-DNS private/reserved-address checks in the native host and document
  the browser-host equivalent;
- budget and optimize the WASM module and test supported browser/device matrix;
- decide whether the lack of an immutable v1.0 spec tag and upstream
  work-in-progress status are acceptable supply-chain/governance risks.

The System Architect owns the issue #1 coordination-rollup update. QAS owns
acceptance/regression verification; Security owns the independent trust,
dependency, crypto-usage, and abuse-path review.

## Specification and ecosystem ambiguities

- The v1.0 website identifies a stable version, but its repository has no
  immutable v1.0 Git tag and continues clarification-only changes on `main`.
  This spike therefore pins a commit, not merely the page label.
- `schemas/v1.0/log_entry.json` uses `minItems: 1` for `updateKeys` and
  `nextKeyHashes`, while normative prose permits empty arrays for deactivation
  and disabling pre-rotation. The verifier follows normative processing rather
  than treating that schema as sufficient validation.
- The current conformance ecosystem records recent cross-implementation
  disagreements involving witness updates and hostile DID-to-URL transforms.
  Witness and transport claims require their own Stage 2/3 evidence.
- The upstream Rust implementation labels itself work in progress. Its passing
  fixtures are evidence, not proof of production readiness or independent
  security review.
