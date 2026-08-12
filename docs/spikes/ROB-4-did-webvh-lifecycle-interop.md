# ROB-4 `did:webvh` lifecycle/interoperability spike — Developer evidence

## Scope and approval boundary

This is Developer/Construction evidence for issue #4 at immutable predecessor
`4bb76ec7dd87fc863b4bf27e52a971d0952e22f3`. It reuses the issue #2 resolver
and does not claim independent QAS, Security approval, production readiness,
recovery custody, production X25519/DH approval, witness/source policy, or
final Robin identity Design approval.

The preserved boundary is:

```text
untrusted bytes
    ->
local did:webvh verification
    ->
verified method-neutral state
```

DID update authorization, `authentication`, and `keyAgreement` remain separate.
The lifecycle writer exists only in tests and the external evidence harness;
runtime-generated private material remains in memory and only public signed
history crosses process boundaries.

## Immutable provenance

| Evidence source | Exact pin | Use |
|---|---|---|
| `did:webvh` v1.0 specification | `e426f93e9682bf53952f15b1803f426be5c57fa0` | Method/profile evidence |
| `didwebvh-rs` 0.6.0 source | `d3cc50049320445ac49eda2b85b8afb5429434be` | Robin-side writer/verifier dependency already locked by #2 |
| DIF `didwebvh-test-suite` | `f792ce4568c8c3efb3b6a055a1c2ba963dc00c35` | Independent vectors and runtime crypto helper |
| `didwebvh-ts` | `9b899225b304b27adef009083cd9ff3bc98b1f09` | Independent generator/verifier |
| External harness | Node 24.4.1; pnpm 11.10.0; Bun 1.3.14 | Exact executed runtime |

These are evidence pins, not dependency or production approval. They match the
issue #2 canonical report and repository harness; no replacement pin was used.

## Changed files and evidence roles

| File | Role |
|---|---|
| `src/lifecycle.rs` | Post-verification creation profile, complete-import manifest gate, complete lifecycle snapshots, exact DIFF vocabulary |
| `src/resolver.rs` | Retains a private copy of verified tip parameters so caller-visible evidence mutation cannot change lifecycle snapshots |
| `src/lib.rs` | Exposes the additive lifecycle boundary |
| `tests/support/rob4_lifecycle.rs` | Runtime-only ephemeral Robin lifecycle generator; exports only public evidence when explicitly requested |
| `tests/stage4.rs` | Nine lifecycle/profile/import/relationship/pre-rotation/device/deactivation/continuity/adversarial/comparison tests |
| `examples/import_lifecycle.rs` | Reads public independent JSONL from stdin and returns only locally verified state or a typed deactivation tip |
| `scripts/lifecycle_interop.sh` | Fetches/builds exact pins and runs the reciprocal matrix |
| `scripts/rob4_interop.ts` | Generates independent runtime histories, consumes Robin histories, compares snapshots, classifies every DIFF, and includes the focused QAS-1 comparator-scope self-test |
| `docs/spikes/ROB-4-did-webvh-lifecycle-interop-results.json` | Public, sanitized 24-direction comparison artifact |
| `Makefile`, `README.md` | Non-interactive `make lifecycle-interop` entry point and usage |

No private fixture is tracked. The #2 report and fixtures are not rewritten.

## Developer acceptance-criterion ledger

| AC | State | New evidence | Reused predecessor evidence / limitation |
|---|---|---|---|
| AC-1 portable creation | **PASS** | `robin_creation_is_portable_prerotated_private_and_metadata_minimal`; runtime identity is v1.0, `portable:true`, pre-rotated, locally resolved, independently consumed; valid non-portable and application-metadata-bearing creations are profile-rejected | #2 method verification and pinned writer; minimum metadata policy is not a final privacy budget |
| AC-2 complete import | **PASS** | `CompleteHistoryManifest` commits expected terminal version/count before output; independent three-entry pre-rotation history imports; truncated, missing, reordered, modified, and incomplete packages fail with no output | #2 complete-chain/SCID/proof verification; the manifest closes the valid-prefix ambiguity found during Construction |
| AC-3 authorized update | **PASS** | Ten authorized active transitions in each direction; adversarial wrong key, predecessor/order, version, time, and state mutations fail closed | #2 proof/chain checks unchanged |
| AC-4 authentication lifecycle | **PASS** | Add/rotate/remove assertions preserve other roles and select only current Ed25519 `authentication`; removed and relationship-substitution cases fail; caller mutation cannot alter retained verified parameters | #2 dangling, controller, assertion/update/agreement substitution and detached-state protections retained |
| AC-5 key-agreement lifecycle | **PASS** | Add/rotate/remove assertions select only current supported X25519 `keyAgreement`; unrelated authentication stays fixed | Selection/profile evidence only; no production DH approval |
| AC-6 pre-rotation | **PASS** | Every active transition consumes the prior commitment and replenishes one next commitment; missing/mismatched reveal, reuse, and compromised-current bypass fail | #2 verifier behavior retained; explicit teardown exists only to permit terminal deactivation in the harness |
| AC-7 device representation | **PASS** | Opaque `device-a7c9e2f4` / `agreement-a7c9e2f4` relationship material is added/removed in both directions; removal preserves the unrelated auth key; metadata scan passes | DID-document representation only, not Robin enrollment/removal protocol |
| AC-8 deactivation | **PASS** | Both implementations consume each other's deactivation; Robin returns typed terminal tip and no authorized state; append and stale restoration fail | Complete post-deactivation document comparison is separately `UNSUPPORTED CAPABILITY` under AC-11 because Robin intentionally exposes no document |
| AC-9 method continuity | **PASS** | Precommitted update replacement plus relationship transition verifies in both directions; uncommitted/current-key-only bypass fails | Method-level cryptographic continuity only; no human recovery authorization/custody |
| AC-10 adversarial lifecycle | **PASS** | Deterministic seed `0x524f422d344c4946`; 16 named invalid transitions plus separate incomplete-import, stale-history, and post-deactivation cases; every case returns a typed error/no state, no panic, bounded sanitized diagnostics | Broad #2 mutation/resource campaigns not repeated |
| AC-11 reciprocal interop/DIFF | **BLOCKED — QAS-1 REMEDIATED; FOCUSED QAS PENDING** | 24 directional consumptions; 22 active snapshots consumed with zero defects and one fully classified slash DIFF each; comparator normalization is now restricted to the implicit `#files` origin-root endpoint and executable negatives reject broader scope; both deactivations consumed | Robin's fail-closed API intentionally exposes no post-deactivation DID Document, so byte/semantic document comparison remains `UNSUPPORTED CAPABILITY`; it is not called reciprocal PASS |
| AC-12 exact evidence/handoff | **DEVELOPER REMEDIATION COMPLETE — FOCUSED QAS PENDING** | This corrected ledger, public JSON artifact, exact pins/commands/counts, dependency delta, private-material scan, limitations, QAS-1 history, and security-scope assessment | AC-1–AC-10 retain independent QAS PASS; QAS checkpoint `5258547861` failed AC-11/AC-12 only; focused QAS and Security remain pending and separate |

## Reciprocal matrix

The public machine-readable artifact is
`ROB-4-did-webvh-lifecycle-interop-results.json`, schema
`robin-rob4-interop-v1`, SHA-256
`ca54f8324ab565749a20ecb513410b82cefd4875e54185d7dd53fede7e85e7da`.

| Operation | Robin -> independent | Independent -> Robin | Byte match | Semantic match | DIFF |
|---|---|---|---|---|---|
| Inception | PASS consumed | PASS consumed | No / No | Yes after bounded normalization | `SPEC-PERMITTED DIFFERENCE` |
| Authentication add | PASS consumed | PASS consumed | No / No | Yes after bounded normalization | `SPEC-PERMITTED DIFFERENCE` |
| Authentication rotate | PASS consumed | PASS consumed | No / No | Yes after bounded normalization | `SPEC-PERMITTED DIFFERENCE` |
| Authentication remove | PASS consumed | PASS consumed | No / No | Yes after bounded normalization | `SPEC-PERMITTED DIFFERENCE` |
| Key-agreement add | PASS consumed | PASS consumed | No / No | Yes after bounded normalization | `SPEC-PERMITTED DIFFERENCE` |
| Key-agreement rotate | PASS consumed | PASS consumed | No / No | Yes after bounded normalization | `SPEC-PERMITTED DIFFERENCE` |
| Key-agreement remove | PASS consumed | PASS consumed | No / No | Yes after bounded normalization | `SPEC-PERMITTED DIFFERENCE` |
| Device add | PASS consumed | PASS consumed | No / No | Yes after bounded normalization | `SPEC-PERMITTED DIFFERENCE` |
| Device remove | PASS consumed | PASS consumed | No / No | Yes after bounded normalization | `SPEC-PERMITTED DIFFERENCE` |
| Precommitted continuity replacement | PASS consumed | PASS consumed | No / No | Yes after bounded normalization | `SPEC-PERMITTED DIFFERENCE` |
| Pre-rotation teardown before terminal action | PASS consumed | PASS consumed | No / No | Yes after bounded normalization | `SPEC-PERMITTED DIFFERENCE` |
| Deactivation | PASS recognized | PASS recognized | BLOCKED / BLOCKED | Terminal metadata agrees; document comparison blocked | `UNSUPPORTED CAPABILITY` |

There are 24 direction rows: 22 `SPEC-PERMITTED DIFFERENCE`, 2
`UNSUPPORTED CAPABILITY`, zero `IMPLEMENTATION DEFECT`, zero
`SPECIFICATION AMBIGUITY`, and zero unexplained DIFFs.

### DIFF-1 — implicit files-service trailing slash

- **Exact path:** `/didDocument/service/*/serviceEndpoint` (the implicit
  `#files` endpoint only).
- **Robin value:** `https://example.com`.
- **Independent value:** `https://example.com/`.
- **Classification:** `SPEC-PERMITTED DIFFERENCE`.
- **Applicable evidence:** the pinned v1.0 method derives implicit HTTP
  services from the DID location; the slash is an equivalent root-path URL
  representation. The independently accepted #2 report recorded the same
  bounded difference.
- **Security relevance:** no identifier, controller, verification method,
  relationship, version, proof, commitment, or deactivation value changes.
- **Disposition:** retain byte mismatch. The implementation explicitly locates
  only the service entry whose ID is the verified DID Document ID plus `#files`,
  and normalizes only its exact origin-root endpoint from `https://host/` to
  `https://host`. It does not recursively normalize property names, other
  services, nested objects, path URLs, or any security/lifecycle field.

This exact DIFF occurs in both directions for all eleven active snapshots (22
rows). The artifact records both exact values for every row.

### DIFF-2 — no post-deactivation document from Robin

- **Exact path:** `/didDocument` after deactivation.
- **Robin value:** `not exposed after typed deactivation`.
- **Independent value:** `document exposed with deactivated=true`.
- **Classification:** `UNSUPPORTED CAPABILITY`.
- **Security relevance:** Robin's behavior is deliberately fail closed and
  ensures no authentication or key-agreement state is exposed.
- **Disposition:** both deactivation directions pass consumption/terminal-state
  recognition, but byte/semantic document comparison and AC-11 remain BLOCKED.

## Adversarial matrix

The deterministic Stage 4 campaign uses seed `0x524f422d344c4946` and names:

1. wrong update key;
2. removed/revoked key;
3. wrong verification relationship;
4. missing pre-rotation reveal;
5. mismatched pre-rotation reveal;
6. invalid commitment reuse;
7. skipped update;
8. reordered update;
9. conflicting history;
10. incorrect device-key retention;
11. incorrect device-key removal;
12. modified import;
13. compromised-current successor selection;
14. invalid version;
15. invalid time;
16. unauthorized state mutation.

Separate assertions cover incomplete import, stale history, and update after
deactivation. Every invalid result is a typed error and therefore exposes no
`ResolutionOutput`; diagnostics are checked for known private-material field
names and a 1,024-byte maximum. No invocation selects zero tests.

## Exact execution evidence

### Starting-tree baseline at `4bb76ec7...`

| Command | Exit/result |
|---|---|
| `cargo fmt --all -- --check` | 0, PASS |
| `cargo test --locked --all-targets` | 0, 83 passed: 11 unit, 16 Stage 1, 15 Stage 2, 41 Stage 3; two example targets selected 0 tests and are not counted as evidence |
| `cargo clippy --locked --all-targets --all-features -- -D warnings` | 0, PASS |
| `RUSTDOCFLAGS='-D warnings' cargo doc --locked --no-deps --all-features` | 0, PASS |
| `cargo metadata --locked --offline --format-version 1 --no-deps` | 0, PASS |
| `make test` | 0, same 83 tests |
| `make lint` | 0, PASS |
| `make run` | 0, expected DID/version/evidence digest |
| `make wasm-check` | 0, PASS |
| `make interop` | 2 on first attempt because a prior temporary cache retained empty `.git` directories; not a PASS |
| `TMPDIR=/private/tmp/rob-4-interop-baseline.tDdO5j make interop` | 0 in a fresh directory; pinned `basic-create` reported the expected `DIFF`, not PASS |

Baseline tool versions were Node 24.4.1, pnpm 11.10.0, Bun 1.3.14,
`rustc 1.96.0`, and Cargo 1.96.0.

### Construction evidence

| Command | Exit/result |
|---|---|
| `cargo test --locked --test stage4` | 0, 9 passed, 0 failed, 0 ignored |
| `cargo test --locked --all-targets` | 0, 93 passed: 12 unit, 16 Stage 1, 15 Stage 2, 41 Stage 3, 9 Stage 4 |
| `cargo clippy --locked --all-targets --all-features -- -D warnings` | 0, PASS |
| `TMPDIR=/private/tmp/rob-4-reciprocal.HfbREP ROB4_INTEROP_ARTIFACT=/private/tmp/rob-4-reciprocal.HfbREP/rob4-interop-results.json make lifecycle-interop` | 0; selected Stage 4 test: 1 passed, 8 filtered; 24 reciprocal comparisons; 24 classified DIFFs; 0 implementation defects |
| `shasum -a 256 docs/spikes/ROB-4-did-webvh-lifecycle-interop-results.json` | 0; `ca54f8324ab565749a20ecb513410b82cefd4875e54185d7dd53fede7e85e7da` |
| `git diff 4bb76ec7... -- Cargo.toml Cargo.lock` | 0; empty: no manifest or lockfile dependency change |
| `cargo tree --locked` | 0; existing locked graph only |
| targeted current-tree private-material scan | 0; one expected source-test literal match in `src/resolver.rs`, manually confirmed not private material; no secret-bearing JSON, PEM private key, or fixed seed match |

The external harness initially failed with exit 2 because top-level `await` was
not supported by the `tsx` CommonJS output mode. That harness defect was fixed
with an async entry point; it is not represented as lifecycle evidence.

### Focused QAS-1 remediation evidence

Independent QAS checkpoint `5258547861` found that the original comparator
recursively removed one trailing slash from every string property named
`serviceEndpoint`, which exceeded the exact normalization scope described
above. QAS independently retained PASS for AC-1–AC-10, failed AC-11/AC-12 on
that evidence-integrity defect, and confirmed that the two post-deactivation
`UNSUPPORTED CAPABILITY` rows are legitimate and must remain BLOCKED.

The focused Developer correction replaces recursive normalization with explicit
traversal of `snapshot.didDocument.service`. It selects only the entry whose
`id` equals `${snapshot.didDocument.id}#files` and removes `/` only when the
endpoint is exactly an origin root with no path, query, or fragment.

| Command | Exit/result |
|---|---|
| `ROB4_COMPARATOR_SCOPE_TEST=1 bun run scripts/rob4_interop.ts` | 0; 4 assertions passed: permitted implicit `#files` root slash normalized; a non-root `#files` path slash, another DID service path slash, and a nested same-named field each remained `IMPLEMENTATION DEFECT` |
| first fresh exact-Node remediation `make lifecycle-interop` | 2; sandbox DNS could not resolve GitHub; not counted as evidence |
| `env PATH=/Users/dimitar/.nvm/versions/node/v24.4.1/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin TMPDIR=/private/tmp/rob-4-remediation-interop.yu7AdI ROB4_INTEROP_ARTIFACT=/private/tmp/rob-4-remediation-interop.yu7AdI/rob4-interop-results.json CARGO_TARGET_DIR=/private/tmp/rob-4-remediation-target.PgIyiJ make lifecycle-interop` | 0 with network authorization; selected Stage 4 test: 1 passed, 8 filtered; 24 comparisons; 22 `SPEC-PERMITTED DIFFERENCE`; 2 `UNSUPPORTED CAPABILITY`; 0 defects; 0 ambiguities; 0 unexplained rows; exact original pins and Node 24.4.1/pnpm 11.10.0/Bun 1.3.14 |
| `shasum -a 256 <regenerated> <tracked>` and `cmp <regenerated> <tracked>` | Both hashes `ca54f8324ab565749a20ecb513410b82cefd4875e54185d7dd53fede7e85e7da`; `cmp` exit 0, so the tracked JSON remains unchanged |

This remediation changes only `scripts/rob4_interop.ts` and this ledger. It
does not alter lifecycle semantics, the resolver, tests/fixtures, manifests,
lockfiles, external pins, the deactivation boundary, or the identified
Security-review scope. Final regression, dependency, secret-scan, commit, and
publication evidence is recorded in the focused Developer checkpoint.

Final format/test/lint/doc/metadata/Make/WASM/diff/history-scan/push evidence is
recorded in the immutable Developer handoff checkpoint.

## Dependency delta

`Cargo.toml` and `Cargo.lock` are unchanged from the immutable predecessor.
There is **no dependency change**. The harness uses the same exact external
pins and existing locked Rust graph. Pinning remains experimental provenance,
not independent Security or production approval.

## Private-material handling and scan

- Rust and TypeScript signing/update/device/continuity keys are generated at
  runtime; no deterministic private seed or secret fixture is tracked.
- The independent process receives Robin public JSONL only. Robin receives
  independent public JSONL over stdin only.
- The committed comparison artifact contains endpoint values, classifications,
  and public outcomes, not public histories or private material.
- The harness rejects artifacts containing known private-key/seed/recovery
  field names. The targeted repository scan separately searches for
  secret-bearing JSON values, PEM private keys, and fixed hexadecimal seeds.
- No private, recovery, credential, or temporary generated fixture was found.

## Checks not run and limitations

- Independent QAS and Security Review were not performed by the Developer.
- No browser, WebCrypto custody, browser persistence/export/recovery, mobile,
  or multi-browser matrix was run.
- No witness governance, watcher/source quorum, live DNS/TLS/CORS/CDN/outage,
  control-proof, invitation, human recovery, or production encryption work was
  run or inferred.
- Broad predecessor URL/resource/provenance/browser campaigns were not repeated
  because lifecycle code does not change those implementations; affected
  resolver/key-selection/pre-rotation/deactivation regressions did run.
- X25519 remains selection/profile evidence only.
- Independent `versionNumber` is derived from the numeric `versionId` prefix
  because its public result omits a separate field; the exact version ID and
  derived number match in every active snapshot.
- The writer APIs and dependency graph are experimental and unapproved for
  production.

## Security-scope assessment

**NEW SECURITY-SENSITIVE BOUNDARY INTRODUCED — INDEPENDENT SECURITY REVIEW REQUIRED**

Reason: ROB-4 adds test-only runtime private-material generation and signing
orchestration in both Rust and TypeScript, plus an external-process boundary
for public lifecycle evidence. Private material is not persisted or passed
between processes, but this is still a new cryptographic generation/signing
path that requires independent Security scope confirmation. This document does
not perform that review.

## Developer recommendation

**PROCEED** to independent QAS and independent Security Review at the immutable
published ROB-4 commit, with AC-11 explicitly BLOCKED only on complete
post-deactivation document comparison. Do not claim production readiness or
final Robin identity Design approval.
