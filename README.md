# Robin

Experimental platform with focus on developing a secure and trustless services for managing and exchanging secrets between individuals and group of users.

## Development workflow

Robin includes a focused Codex integration of the SAFe Agentic Workflow harness. See [Using the SAFE Harness in Robin](docs/SAFE-HARNESS.md) for setup, role handoffs, and example prompts.

SAFE work is tracked in GitHub Issues. The `.github/` directory contains the SAFE
work-item issue form used to capture stable scope, acceptance criteria, security
considerations, and Definition of Done before agents begin implementation.

## Experimental DID resolver spike

Issue #2 adds evidence-gathering Rust/WASM code behind a method-independent
resolver interface. It is not production code and does not approve
`did:webvh`, its cryptographic suite, or Robin's overall identity design.

The non-interactive command set is:

- `make setup` verifies Rust/Cargo and fetches the exact lockfile dependencies.
- `make test` runs all deterministic native tests.
- `make lint` checks formatting and treats Clippy warnings as errors.
- `make run` resolves the pinned TypeScript inception fixture locally.
- `make wasm-check` compiles the local verifier for `wasm32-unknown-unknown`
  with the Rustup stable toolchain after that target has been installed.
- `make interop` fetches exact pinned test-suite and TypeScript revisions into
  a temporary directory, builds the independent resolver, and runs the
  reciprocal interoperability check. It requires Node 24, Bun, Corepack, and
  network access on the first run.

No development server is applicable to this library-only spike. Network failure
tests use deterministic injected evidence; the core resolver never needs a
remote universal resolver.

See [the spike evidence record](docs/spikes/ROB-2-did-webvh-resolver.md) for
scope, revision pins, commands, limitations, and acceptance-criterion results.
