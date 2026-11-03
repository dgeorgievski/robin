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

## Authorization for bounded SAFE workflows

Preparation and execution are separate. Creating an issue, drafting a prompt,
assigning `Owner` or `NextRole`, or updating coordination metadata authorizes
those artifacts only unless execution is explicitly included.

The human may authorize one SAFE role or an entire bounded workflow. Identify
the authorization source, issue or Unit of Work, accepted scope, included roles
or named workflow, allowed correction/reverification loops, and stopping point
from the human request and active conversation. Clarify material ambiguity before
dependent work; a coordinator or checkpoint cannot create or expand authority.

Once a bounded workflow is authorized, carry those bounds in checkpoints and
handoffs. Do not ask again merely because `NextRole` changes. Routine tool waits
and session interruptions do not revoke authorization; an explicit human pause
or stop requires human direction to resume.

Within the authorized scope, the coordinator may progress through System
Architect, Developer or the appropriate evidence owner, independent QAS,
in-scope remediation, focused QAS, required independent Security Review,
correction/reverification, and final System Architect reconciliation. This is
orchestration, not permission to collapse roles: Developer cannot substitute for
QAS, Security Reviewer, System Architect, or Product Owner. QAS and required
Security Review remain independent. System Architect cannot self-approve final
Design. Corrections must preserve accepted immutable evidence and checkpoints.

At every completed role, persist its checkpoint, verify the write, reconcile
branch/commit/evidence, then continue to the next authorized role. Do not claim a
completed handoff when checkpoint persistence failed.

When covered by the bounded authorization, routine actions need no repeated
task authorization: repository reads; Git status/diff/log/show/fetch; creating
the issue-specific branch; scoped commits and pushes to the authorized branch;
approved build/test/lint commands; GitHub issue/PR/check/run reads; checkpoints
and routine coordination updates. PR creation or non-deployment workflow
dispatch must be explicitly included. Tool and sandbox enforcement still apply;
use the required escalation path rather than treating task authorization as
execution permission. Do not add broad shell or GitHub command allow rules.

Stop and ask for human direction at:

- material scope changes or materially ambiguous Product requirements;
- architectural/security choices outside existing authorization;
- required credentials/secrets or new privileged access;
- destructive operations outside scope or proposed history rewrite/force-push
  over accepted evidence;
- production deployment, or release/publication without explicit authorization;
- final ADR acceptance, final identity Design, or final Robin Design approval;
- merge to `master` or issue closure without explicit authorization;
- an unresolved blocker that prevents safe progress, or a human pause/stop.

Never bypass a sandbox denial, repository protection, or GitHub permission
failure. Automatic approval review handles eligible escalation requests; it
does not grant new task authority or override sandbox/managed restrictions.

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
