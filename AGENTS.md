# Repository Guidelines

## Project Structure & Module Organization

Robin is currently an early-stage repository with no application or test directories. SAFE workflow configuration lives in `.codex/`, repo skills in `.agents/skills/`, and usage guides in `docs/`. Keep root-level files limited to project-wide documentation and configuration. When implementation begins, place production code in `src/`, tests in `tests/`, and non-code resources in `assets/`. Mirror source paths in the test tree (for example, `src/secrets/store.*` should have a corresponding `tests/secrets/store_test.*`). Document any new top-level directory in `README.md`.

## Build, Test, and Development Commands

There is currently no build tool, dependency manifest, or automated test command. Do not assume a language-specific workflow. When adding one, expose a small, documented command set, preferably through a `Makefile`:

- `make setup` installs or verifies development dependencies.
- `make test` runs the complete automated test suite.
- `make lint` checks formatting and static-analysis rules.
- `make run` starts the project locally.

Keep these commands non-interactive and suitable for CI, and update both this guide and `README.md` when they become available.

## Coding Style & Naming Conventions

Follow the standard formatter and linter for the language introduced, and commit their configuration with the first source code. Prefer descriptive module names, small focused functions, and explicit error handling. Use lowercase directory names; avoid ambiguous abbreviations. Never log secret values, credentials, or cryptographic material.

## Testing Guidelines

Add tests with every behavior change and regression fix. Keep unit tests deterministic and isolated from network services. Place slower integration tests in a clearly named subtree such as `tests/integration/`. Test names should describe behavior and expected outcome. Security-sensitive paths should cover invalid input, authorization failures, and safe error reporting.

## Commit & Pull Request Guidelines

History currently contains only `Initial commit`, so no established convention exists. Use short, imperative, sentence-case subjects (for example, `Add encrypted secret storage`) and keep each commit focused. Pull requests should explain the motivation, summarize changes, list verification performed, and link relevant issues. Include screenshots only for user-visible changes. Call out security assumptions, migrations, configuration changes, and follow-up work explicitly.

## GitHub Issue Checkpoints

Use GitHub Issues as the durable system of record for SAFE work. The issue body
contains stable scope, acceptance criteria, and Definition of Done. For work tied
to an issue, read its body and all comments before acting, then reconcile the
latest `<!-- robin-safe-checkpoint:v1 -->` checkpoint with the current branch,
commit, worktree, and evidence.

Append a checkpoint comment after every SAFE gate, whenever work becomes blocked,
before an expected interruption, and before ending a session with unfinished
work. Never rewrite an older checkpoint to represent new state. Include the UTC
timestamp, phase, role, status, last completed gate, branch and commit, AC
progress, exact evidence, blockers and risks, one next action, and expected exit
state. Never put secrets or sensitive output in an issue.

Do not claim a role handoff is complete until its checkpoint is persisted. If
GitHub is unavailable or issue-comment writes are not authorized, return a
ready-to-post checkpoint and mark persistence BLOCKED. Long-running or
multi-agent SAFE work must have a GitHub issue before implementation begins.

## Security & Configuration

Do not commit secrets or local environment files. Provide sanitized examples such as `.env.example`, use least-privilege defaults, and treat changes to authentication, authorization, encryption, or secret lifecycle handling as security-sensitive reviews.

## SAFE Harness Documentation Synchronization

Treat `docs/SAFE-HARNESS.md` as living, evidence-based documentation. Whenever
repository-changing work reveals actual Codex or SAFE harness behavior that
contradicts or materially qualifies that guide, update the affected instructions
in the same change without waiting for a separate documentation request. Record
surface- or version-specific limitations when relevant, and do not use a UI
listing alone as proof that a capability is unavailable. If the current task is
read-only or repository edits are not authorized, report the discrepancy and the
required documentation update explicitly.
