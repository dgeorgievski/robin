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
branch/commit/evidence, synchronize and verify Project Status, then continue to
the next authorized role. A failed checkpoint or board readback blocks handoff.

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

## Coordinator Project Status ownership

Apply the shared [safe-workflow contract](.agents/skills/safe-workflow/SKILL.md#coordinator-project-status-ownership)
at every handoff: persist checkpoint -> verify persistence -> determine next
activity/owner -> update live Robin Project #3 Status -> re-read/verify -> start
or assign the next role. Coordinator owns mutations, including for read-only
specialists. Resolve live project/item/field/option IDs by repository and issue
number/URL; add missing tracked issues, never match titles alone. Record
`Current Project Status:`, `Intended Project Status:`, `Next Owner:` and
`Next Action:` plus a subsequent verified transition confirmation.

Use Backlog for non-executable work, Ready for executable waiting work,
In progress for active Design/implementation/remediation, In review for independent
validation/reconciliation, Demo for fully gated human outcome review and Done
only after required acceptance. Active authorized Design can start directly from
Backlog; accepted Design can return to Ready; review findings requiring repair
return to In progress. Keep successive reviews in In review. BLOCKED retains its
phase and records the blocker; missing options or failed persistence/update/readback
block handoff. Reconcile concurrent changes rather than blindly overwriting them.
Routine transitions within bounded authority need no repeated human permission.
Every Demo exit still requires an explicit persisted human decision; closure is
separate. Do not claim handoff complete until checkpoint and board are verified.

## Human-controlled Demo gate

`Demo` is an optional human outcome review gate after all required automated/agent
validation and before `Done` or closure as completed. Each issue/workflow must
record `Demo gate: required` or `Demo gate: not required` in its issue/checkpoint;
no custom Project field is needed. An explicit accepted scope or human setting
takes precedence. Without one, require Demo for user-visible/product behavior,
architecture/Design evidence needing Product Owner judgment, security/privacy
outcomes whose accepted workflow includes human outcome review, milestone work,
and any authorization saying `stop at Demo`. Routine internal maintenance may
omit Demo when the issue or human authorization explicitly permits direct
completion after required reviews.

The Coordinator owns routine authorized, evidence-supported transitions:
`Backlog -> Ready`, `Ready -> In progress`, `In progress -> In review`, and
`In review -> Demo`. Persist and verify the supporting checkpoint, mutate the
board, then read back the live item value before continuing. Resolve live project,
field and option IDs rather than copying IDs from prior sessions. A missing
required stage is a blocker; do not silently map it to another status.

Enter Demo only after all required role checkpoints are persisted and verified,
required QAS and Security Review are complete, required System Architect
reconciliation is complete, unresolved blockers are recorded, and issue-specific
Demo entry conditions are satisfied. A blocker that prevents a required gate or
entry condition prevents Demo entry. Record `Next owner: Human / Product Owner`,
verify the board is in Demo, and STOP. The issue remains OPEN unless the human
separately authorizes closure. Demo entry is not final Design or release approval.

Every `Demo -> *` decision requires explicit human authorization, persisted
before the board mutation. The Coordinator may execute the API call after that
decision; the human need not click the board. Apply these transitions:

- Human accepts outcome: `Demo -> Done`; close with reason `completed` only if
  closure is included in that authorization or separately authorized.
- Human requests implementation corrections: `Demo -> In progress`; preserve
  accepted scope/evidence and repeat affected independent verification.
- Human requests requirements/Design revision: normally `Demo -> Ready`, or
  `Backlog` when substantial Product/architecture elaboration is needed.
- Human has not accepted: remain in `Demo`.

Tests, QAS PASS, Security PASS, System Architect reconciliation, PR creation or
merge do not authorize `Demo -> Done`. No role, including Coordinator, System
Architect, QAS, Security or RTE, may infer human acceptance. Bounded workflows
that stop at Demo include authorized roles and in-scope correction/reverification,
then automated Demo entry and a stop for human review. This gate adopts no ALISS
temporary demo policy, reduced tests, Chrome-only testing, disabled CI, or
clinical/demo-specific behavior; all Robin verification requirements remain.

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
