# Using the SAFE Harness in Robin

Robin includes a focused Codex integration of [SAW — SAFe Agentic Workflow (SAFE)](https://github.com/bybren-llc/safe-agentic-workflow), pinned to upstream `v2.11.1`. SAFE supplies an evidence-gated workflow inspired by SAFe: clarify the work, review the design, implement, independently validate, then prepare a human-reviewed release.

This integration deliberately includes only the provider-neutral core needed by Robin. It does not import upstream's optional Claude, Gemini, Cursor, Linear, Confluence, Stripe, RLS, deployment, or Dark Factory configuration.

## What is installed

```text
.codex/config.toml                 Codex sandbox and multi-agent defaults
.codex/agents/                     BSA, architect, developer, QAS, and RTE roles
.agents/skills/safe-workflow/      Single-ticket delivery gates
.agents/skills/safe-ai-dlc/        Multi-issue/Bolt planning
.agents/skills/security-audit/     Secret-focused independent review
.github/ISSUE_TEMPLATE/            SAFE work-item issue form
docs/SAFE-LICENSE.md               Upstream version, attribution, and MIT license
```

Codex loads root `AGENTS.md`, discovers repository skills under `.agents/skills/`, and discovers project agents under `.codex/agents/`. The project config does not pin a model or store credentials.

## Prerequisites

1. Install a current Codex CLI:

   ```bash
   npm install -g @openai/codex
   ```

2. Authenticate with `codex login` (recommended) or your normal organization-approved method. Do not commit API keys or place them in `.codex/config.toml`.
3. Connect GitHub with permission to read issues and comments and to append issue
   comments. Checkpoint persistence is blocked when issue comments are read-only.
4. From the repository root, start Codex:

   ```bash
   cd /path/to/robin
   codex
   ```

5. Confirm repository skill discovery by explicitly invoking each skill from a
   prompt: `$safe-workflow`, `$safe-ai-dlc`, and `$security-audit`. Codex should
   acknowledge and follow the selected skill. Do not use the `/skills` list as
   the sole discovery check: on some Codex surfaces it shows only
   plugin-provided skills even when repository skills under `.agents/skills/`
   are loaded and available. If explicit invocation fails, confirm Codex was
   started from this repository, verify the skill paths above, and then restart
   the session. Use `/agent` to inspect agent threads during delegated work.

## Automatic approval review

Robin's repository configuration retains the sandbox and interactive escalation
policy while selecting automatic review for eligible requests:

```toml
approval_policy = "on-request"
approvals_reviewer = "auto_review"
sandbox_mode = "workspace-write"
```

`auto_review` reduces direct human confirmation by routing eligible escalation
requests to a reviewer. It does not disable sandboxing, grant repository/network
authority, expand the accepted task, or bypass managed policy. It is not the
`never` approval policy. Denied operations must not be bypassed.

See the [official auto-review documentation](https://learn.chatgpt.com/docs/sandboxing/auto-review).
Effective settings depend on the Codex client/session and managed requirements;
reload or restart the applicable client when adopting changed configuration.
Parsing this file does not prove that an active session loaded it or that an
escalation will be approved. Do not add broad shell/GitHub command rules; any
future narrow rule needs observed approval noise and separate review.

## Bounded workflow authorization

“Prepare a workflow” authorizes artifacts such as an issue, prompt, or owner
assignment. “Execute a bounded workflow” authorizes the specified roles and
correction loops within accepted scope, up to a stated stopping point. A human
can authorize one role or a complete bounded workflow. A coordinator cannot
create additional authority by assigning a role or writing a checkpoint.

Carry the human authorization source, issue, accepted scope, included roles,
allowed corrections/reverification, and stopping point through every handoff.
Routine waits and session interruptions do not revoke it. A human pause/stop
requires human direction to resume. Apply the
[shared execution contract](../.agents/skills/safe-workflow/SKILL.md#bounded-workflow-execution)
and [repository authorization rules](../AGENTS.md#authorization-for-bounded-safe-workflows).

Within those bounds, the coordinator continues automatically through System
Architect, the appropriate Construction/evidence owner, independent QAS,
bounded remediation and focused QAS, required independent Security Review,
independent reverification, and final System Architect reconciliation. Persist
and verify each role checkpoint, reconcile its Git target, then update and verify
Project Status before starting the next role. Checkpoint or board verification
failure prevents a completed handoff. Changing role does not require
repeated human approval, and a focused PASS does not clear outstanding gates.

Developer never substitutes for QAS, Security Reviewer, System Architect, or
Product Owner. Final ADR acceptance, final identity Design, and final Robin
Design remain human decisions; System Architect cannot self-approve them.
Preserve immutable accepted evidence during correction loops. Stop for material
scope/Product decisions, out-of-authorization architecture/security choices,
new credentials/privilege, destructive actions outside scope, unresolved
blockers, and the human's stated stopping conditions.

### Example: execute an accepted scope

```text
Execute $safe-workflow for issue #N as a bounded workflow within its accepted
scope.

Proceed from System Architect through the appropriate Construction/evidence
role, independent QAS, required independent Security Review, in-scope
remediation and focused reverification, and final System Architect
reconciliation.

Persist/verify checkpoint -> update Project Status -> verify readback -> next role.

Stop at:
- Demo after all required gates and verified board entry;
- a material scope or Product-policy decision;
- an unresolved blocker;
- final ADR or final Product/Design approval;
- merge, release, publication, deployment, destructive history change, or issue
  closure unless explicitly authorized.

Do not ask for repeated role-transition approval while work remains inside this
bounded authorization.
```

### Coordinator Project Status ownership

Use the [shared handoff contract](../.agents/skills/safe-workflow/SKILL.md#coordinator-project-status-ownership)
for every specialist completion/start, including read-only reviews. Coordinator
persists/verifies the result, determines the next activity, resolves live Project
#3 and issue/item/Status/option metadata, updates Status, re-reads and verifies,
then starts/assigns the next authorized role. Checkpoints record current/intended
Status and next owner/action; append the verified transition confirmation.
Failures block handoff while preserving evidence. Reconcile concurrent edits;
never blindly overwrite them or broaden permissions after denial.

Backlog means not executable; Ready means executable but waiting. Active Design,
implementation and remediation use In progress. Independent QAS, Security and
final Architect reconciliation stay In review until technical gates complete;
implementation findings return to In progress. Ready can follow completed Design,
and authorized active Design can begin directly from Backlog. BLOCKED retains
the phase of the blocker. Demo/Done retain the human gates below.

This session's GitHub connector exposes no Project operations; authenticated
`gh api graphql` provides live metadata/readback where already authorized.
Tool availability is surface-specific; do not infer API capability from UI
listings. These instructions define Coordinator enforcement, not a deployed
GitHub transition validator.

### Human-controlled Demo workflow

Robin [Project #3](https://github.com/users/dgeorgievski/projects/3) uses:

```text
Backlog -> Ready -> In progress -> In review -> Demo -> Done
```

Demo is an optional human review gate after all required automated/agent validation
and before Done or closure as completed. The issue/checkpoint establishes
`Demo gate: required` or `Demo gate: not required`, the authorization/default and
issue-specific entry conditions. No new custom Project field is needed. An
explicit accepted scope or human setting takes precedence. Without one, Demo is
required for user-visible/product behavior, architecture/Design evidence needing
Product Owner judgment, security/privacy-sensitive outcomes where the accepted
workflow includes human outcome review, milestone work, and explicit `stop at Demo`
workflows. Routine internal maintenance may omit Demo when the issue or human
explicitly permits direct completion after required reviews.

Coordinator owns routine authorized, evidence-supported `Backlog -> Ready`,
`Ready -> In progress`, `In progress -> In review` and `In review -> Demo`
transitions. Persist and verify the supporting checkpoint, resolve live project,
field and option IDs, mutate the item, and read back its board value before
continuing. Do not reuse historical IDs or silently substitute another status
when a required stage is missing.

For technical completion, enter Demo only after all required role checkpoints are
persisted and verified, required QAS and Security Review have completed, required
System Architect reconciliation has completed, unresolved blockers are recorded,
and issue-specific Demo entry conditions are satisfied. A blocker preventing a
required gate or entry condition prevents entry. Then verify `In review -> Demo`,
record `Next owner: Human / Product Owner`, and STOP. The issue remains OPEN
unless the human separately authorizes closure. Entry implies neither final
Design approval nor release readiness.

Every exit from Demo requires an explicit human decision, persisted before the
board mutation. The Coordinator may execute that decision via API; human-only
refers to decision authority, not who clicks or calls GitHub.

| Human outcome decision | Board transition and subsequent authority |
|---|---|
| Accept | `Demo -> Done`; close as `completed` only when closure is included in that authorization or separately authorized. |
| Implementation corrections | `Demo -> In progress`; preserve accepted scope/evidence, use appropriate Developer/evidence owner and repeat affected independent verification. |
| Requirements/Design revision | Normally `Demo -> Ready`, or `Backlog` if substantial Product/architecture elaboration is needed. |
| Not accepted yet | Remain in `Demo`; no inferred completion. |

Green tests, QAS PASS, Security PASS, System Architect reconciliation, PR creation
or PR merge do not authorize Demo -> Done. No role, including Coordinator, System
Architect, QAS, Security or RTE, may infer human Demo acceptance. Only the
human-controlled gate concept is borrowed from ALISS; no temporary demo policy,
reduced tests, Chrome-only testing, disabled CI or clinical/demo-specific behavior
is adopted.

For example:

```text
Execute $safe-workflow for issue #N through Developer, QAS,
Security Review and System Architect reconciliation.
Stop at Demo.
```

This authorizes automatic orchestration of the included roles, persisted/verified
checkpoints and in-scope remediation/reverification. Once all required gates and
entry conditions pass, Coordinator moves the item to Demo, verifies readback and
stops for Human / Product Owner review. It authorizes no automatic exit, closure,
merge, deployment or release action.

On 2026-11-03 authenticated GraphQL reconciliation found five Status options;
adding Demo before Done and rereading verified the exact six-option order above,
preserved prior option IDs/metadata and unrelated fields, and left #5 OPEN in
Backlog. This is observed configuration, not proof of a deployed transition
validator. Enforcement here is the issue/checkpoint and coordinator contract;
GitHub edit permissions alone do not enforce human decision authority.

A subsequent 2026-11-03 handoff reconciliation verified all six options and
found #5 already In progress under its Developer-remediation checkpoint. #1's
latest Design-evidence checkpoint still said IN PROGRESS while its board item
was Backlog; Coordinator persisted reconciliation before correcting it to
In progress and verified live readback. Maintenance #10 appeared on the board
in Backlog between creation and lookup; the stale-state guard stopped before
mutation, then a fresh checkpoint/live-state reconciliation permitted correction.
Always re-resolve actual item state rather than assuming new issues are absent.

### GitHub and GitHub Actions

Bounded authorization may cover routine reads, issue comments/checkpoints,
coordination updates, scoped branch creation/commits/pushes, PR inspection, and
check/run inspection. PR creation and dispatch of an already-approved
non-deployment workflow must be explicitly included. Follow tool escalation
requirements even when the task itself is already authorized.

Those routine actions do not automatically authorize merge, deployment,
release/publication, issue closure, secrets or environment changes, permission
changes, or destructive history operations. Keep their explicit human gates.
Never bypass sandbox denial, repository protection, or GitHub permission failure.
No ALISS temporary demo policy, reduced testing, browser restriction, or disabled
CI policy is adopted; Robin's existing Design/security/verification gates remain.

### Issue #5 baseline and Demo reconciliation

The human merged harness PR #7 at master/6ba83193c53191988b7e2d035a354cb373573869.
Issue #5 subsequently received Design-entry checkpoint 6614831925 and has a
separate `ROB-5-witness-first-use-assurance` branch with unfinished uncommitted
work. The earlier instruction to wait for the harness merge is satisfied; do not
use its historical “no branch” state as current evidence. Read #5 and all current
checkpoints before resuming; reconcile actual Git/snapshot state and preserve
immutable #2/#4 predecessor evidence. Do not rebase or rewrite accepted evidence.

`Demo gate: required` applies to #5 because its bounded workflow explicitly stops
at Demo. Creating the option resolves only the missing-board-stage blocker.
The separate writer-ownership/stable-snapshot blocker remains until independently
resolved. Incomplete implementation, QAS, Security/Privacy and System Architect
reconciliation remain incomplete; no premature Demo movement. Once all required
gates and issue-specific entry conditions are met, Coordinator moves #5 from
In review to Demo and stops, leaving it OPEN for human outcome review. This
maintenance does not execute #5's evidence workflow or approve production/final
Design, and its PR authority does not relax #5's no-commit/push/PR restriction.

## GitHub issue checkpoints

GitHub Issues are Robin's durable system of record for SAFE work. Create a SAFE
work-item issue before starting long-running or multi-agent implementation. Keep
stable outcome, scope, acceptance criteria, security considerations,
dependencies, and Definition of Done in the issue body. Agents append checkpoint
comments; they do not rewrite earlier checkpoints to represent new state.

Every checkpoint starts with:

```markdown
<!-- robin-safe-checkpoint:v1 -->
```

A checkpoint records the UTC timestamp, SAFE phase, role, status, last completed
gate, branch and commit, acceptance-criterion progress, exact evidence, decisions,
blockers, residual risks, one next action, and expected exit state. Post one:

- after every SAFE gate;
- whenever work becomes blocked;
- before an expected interruption; and
- before ending a session with unfinished work.

Never include credentials, keys, secret values, sensitive fixtures, or unsafe
command output. Link to a safe commit, check, or pull request instead.

### Resuming interrupted work

Before making changes, the resuming agent:

1. reads the issue body and all comments;
2. finds the latest valid `robin-safe-checkpoint:v1` comment;
3. compares its branch and commit to the local repository;
4. inspects `git status`, relevant diffs, and whether recorded evidence still
   applies;
5. appends a reconciliation checkpoint if Git and the recorded state diverge;
6. continues from the recorded next action.

Git state and fresh command output override stale checkpoint prose. If GitHub is
unavailable or comment writes fail, the agent returns a complete ready-to-post
checkpoint and marks persistence BLOCKED. A role may not claim its handoff until
the checkpoint is verified and Coordinator Project Status synchronization/readback
is verified before the next role starts.

## First workflow: one ticket

Codex uses natural-language prompts rather than SAFE's Claude slash commands. A complete first prompt is:

```text
Use the safe-workflow skill for GitHub issue #12. Read the issue and its latest
checkpoint before acting. First have the BSA define testable
acceptance criteria for adding encrypted local secret storage. Ask me about any
product or security decision that cannot be inferred. Then have the system
architect review trust boundaries. After I approve the plan, delegate implementation
to the developer and independent validation to QAS. Do not prepare a release handoff
unless every criterion has evidence and each role checkpoint is recorded on #12.
```

For a small, already-defined change:

```text
Use safe-workflow for GitHub issue #12. Resume from its latest checkpoint,
implement the accepted scope, run all available checks, then have QAS
independently review the diff. Append every gate checkpoint to #12 and return the
evidence table and remaining risks; do not commit, push, or open a PR.
```

For security-only review:

```text
Use the security-audit skill and a read-only QAS agent to review GitHub issue #12
and this branch against main. Resume from the latest checkpoint. Focus on secret
exposure, authorization failures, cryptographic misuse, and missing negative
tests. Append the security review checkpoint to #12. Report findings only; do not
fix them.
```

## Larger initiatives

Use `safe-ai-dlc` only when work spans several dependent issues. Create or select
a coordination issue for the Unit of Work or Bolt, and maintain detailed
checkpoints on each work-item issue:

```text
Use safe-ai-dlc with coordination issue #20 to plan the secret-sharing MVP as a
Unit of Work. Read the latest checkpoint on #20 and every active child issue.
Propose Bolts, dependencies, human checkpoints, and Definitions of Done. Delegate
read-only elaboration to BSA and system-architect agents in parallel, then update
the issue checkpoints and wait for my approval before any implementation.
```

SAFE does not grant extra authority. Human approval remains required for ambiguous requirements, credentials, destructive operations, production changes, publishing, and final merge. Parallel agents are best for independent analysis and validation; avoid assigning simultaneous edits to overlapping files.

## Expected handoffs

| Gate      | Owner            | Required GitHub checkpoint |
| --------- | ---------------- | -------------------------- |
| Define    | BSA              | Scope, non-goals, acceptance criteria, risks, decisions |
| Design    | System Architect | Trust boundaries, constraints, open decisions, evidence gates |
| Implement | Developer        | Branch/commit, AC progress, exact checks, next action |
| Validate  | QAS              | PASS/FAIL/BLOCKED per criterion with evidence and next owner |
| Release   | RTE              | PR-ready evidence, residual risks, and human action |

Robin currently has no dependency manifest or automated test suite. Until those exist, `git diff --check` is only a baseline integrity check—not proof that behavior works. Add real build, lint, and test commands to `AGENTS.md` as the implementation takes shape.

## Acronyms

1. BSA (Business Systems Analyst): The bridge between business needs and technical solutions. They analyze requirements, define system scope, and map out acceptance criteria for the development team.

2. QAS (Quality Assurance Specialist): The gatekeeper of software quality. They design test cases, execute testing protocols, and verify that the built features meet all predefined criteria with clear data evidence.

3. RTE (Release Train Engineer): The chief Scrum Master for the entire Agile Release Train (ART). While typically a program-level role, they step in at the team level during the release gate to unblock deployments and facilitate organization-wide delivery.

## Updating the integration

Review new upstream releases before copying changes; this is a tailored integration, not a live submodule.

```bash
git clone https://github.com/bybren-llc/safe-agentic-workflow.git /tmp/safe-review
git -C /tmp/safe-review checkout <version>
git diff --no-index .agents/skills /tmp/safe-review/.agents/skills
git diff --no-index .codex /tmp/safe-review/.codex
```

Reapply Robin-specific role boundaries and the GitHub checkpoint contract, remove
unrelated provider and stack assumptions, update the pinned revision in this
document and `docs/SAFE-LICENSE.md`, and independently review the result before
committing. Do not replace Robin's GitHub Issues system of record with upstream
tracker-specific instructions during an update.

## Keeping this guide synchronized

This guide describes verified behavior, not assumptions about a Codex user
interface. A missing repository skill in `/skills`, by itself, is not evidence
that discovery failed; verify behavior through explicit invocation and record
surface- or version-specific limitations when they are known.

Whenever repository-changing work uncovers Codex or SAFE harness behavior that
contradicts or materially qualifies this guide, update the affected instructions
in this file as part of the same change. Do not leave a known discrepancy for a
separate documentation pass. If the current task is read-only or cannot modify
the repository, report the exact discrepancy and the required documentation
change instead of silently treating this guide as current. This synchronization
requirement is also recorded in root `AGENTS.md`, which Codex loads for every
repository task.

## References

- [SAFE repository and quick start](https://github.com/bybren-llc/safe-agentic-workflow)
- [SAFE workspace adoption guide](https://github.com/bybren-llc/safe-agentic-workflow/blob/main/docs/guides/WORKSPACE-ADOPTION-GUIDE.md)
- [Codex custom agents](https://developers.openai.com/codex/subagents/)
- [Codex skills](https://developers.openai.com/codex/skills/)
- [Codex project instructions](https://developers.openai.com/codex/guides/agents-md/)
