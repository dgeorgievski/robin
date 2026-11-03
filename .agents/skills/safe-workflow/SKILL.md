---
name: safe-workflow
description: Use for Robin GitHub issue work that must follow SAFE role boundaries, immutable Git history, durable issue checkpoints, focused acceptance-criterion evidence, independent validation, or release handoff. Apply this skill when starting, resuming, implementing, validating, or preparing issue-scoped work. Do not use for simple questions or repository tasks that do not require SAFE gates.
---

# SAFE Workflow for Robin

This skill is the shared control plane for Robin SAFE work. Role agents should keep only role-specific behavior in their own definitions and rely on this skill for the common workflow below.

## 1. Resume from durable state

For issue-scoped work:

1. Read the issue body and all comments.
2. Locate the latest valid `<!-- robin-safe-checkpoint:v1 -->` checkpoint.
3. Reconcile its branch, commit, acceptance-criterion state, and next action with current Git state and fresh command output.
4. Treat Git state and fresh evidence as authoritative when checkpoint prose is stale.
5. Append a reconciliation checkpoint before continuing when state diverges materially.

Do not rewrite an older checkpoint to represent new state.

## 2. Preserve role boundaries

- **BSA:** defines outcome, scope, non-goals, testable acceptance criteria, dependencies, and product/security decisions.
- **System Architect:** reviews architecture, trust boundaries, constraints, and evidence gates.
- **Developer:** implements the smallest focused change and records exact evidence.
- **QAS:** independently validates the immutable diff and does not repair it.
- **Security Reviewer:** independently reviews required security boundaries and remediation.
- **RTE:** prepares the human-reviewed release handoff only after all required gates pass.

Do not collapse Developer and QAS for security-sensitive work. Human approval remains required for ambiguous requirements, credentials, destructive operations, production changes, publishing, and final merge.

## Bounded workflow execution

The latest valid human authorization may cover one role or multiple SAFE gates.
At start/resume, reconcile it with the active conversation and record in each
checkpoint and handoff:

- authorization source;
- issue or Unit of Work;
- accepted scope;
- included roles or named workflow;
- allowed correction/reverification loops;
- stopping condition.

Apply the repository's [bounded authorization contract](../../../AGENTS.md#authorization-for-bounded-safe-workflows).
Preparation of issues/prompts/owners alone does not authorize execution.
Checkpoints preserve authority; they never expand it. Routine waits or session
interruptions do not revoke it; an explicit human pause requires human resumption.

Under an active bounded authorization, automatically transition through covered
roles after persisting and verifying each role checkpoint and reconciling its
branch, commit, and evidence, then synchronizing and verifying Project Status
under the contract below before starting/assigning the next role. Do not request
repeated confirmation solely for a role change or its routine board transition.
Do not proceed when checkpoint persistence or board verification is unconfirmed.

| Result/event | Next action within the recorded authorization |
|---|---|
| PASS | Continue to the next included role; a focused PASS does not clear other outstanding criteria or gates. |
| FAIL with an in-scope, bounded correction | Return to Developer or the appropriate implementation owner; correct only the finding, then rerun required independent verification. |
| BLOCKED | Resolve inside existing authorization if possible; otherwise persist the blocker and stop for human direction. Do not turn missing evidence into PASS. |
| Scope change / Product decision | Stop for the human when scope materially changes or a material decision is outside existing authorization. |
| Required Demo entry | After all required gates and issue-specific entry conditions are satisfied, Coordinator persists/verifies the checkpoint, moves `In review -> Demo`, reads back the board value, assigns Human / Product Owner, and stops. |
| Any exit from Demo | Require an explicit human decision persisted before the board mutation; no role may infer acceptance from verification or merge. |
| Final Design / merge / release / deploy | Stop for the human unless separately and explicitly authorized; final ADR and Product/Design decisions remain human-owned. |

Preserve independent QAS and required independent Security Review throughout
correction loops. Developer cannot substitute for either reviewer, System
Architect, or Product Owner; System Architect cannot self-approve final Design.
Produce new focused commits/evidence for corrections without rewriting accepted
immutable evidence. Stop at the recorded boundary even if more roles are needed;
name the outstanding gate rather than treating it as waived.

Routine in-scope Git/GitHub actions follow the same authorization bounds and
enforced tool controls. Never bypass a denial, protection, or permission failure.

## Human-controlled Demo and board ownership

Apply the repository's [Demo contract](../../../AGENTS.md#human-controlled-demo-gate).
Demo is optional per accepted issue/workflow: record exactly `Demo gate: required`
or `Demo gate: not required` in the issue/checkpoint, together with entry
conditions and the authorization source. Do not add a custom Project field for
this setting. Respect an explicit accepted scope/human setting. Otherwise require
Demo for user-visible/product behavior, architecture/Design evidence needing
Product Owner judgment, security/privacy outcomes whose accepted workflow
includes human outcome review, milestone work, and explicit `stop at Demo`
authorization. Routine internal maintenance may omit Demo when explicitly allowed
to complete after required reviews.

For `stop at Demo`, orchestrate all included roles, persist/verify every checkpoint,
and complete in-scope remediation plus affected independent reverification.
Enter Demo only after required QAS, Security Review, System Architect reconciliation
and all other required roles/entry conditions are complete. Record unresolved
blockers; those preventing a required gate/entry condition prevent entry. Persist
the entry checkpoint, move from In review to Demo, verify readback, set
`Next owner: Human / Product Owner`, and STOP. Keep the issue OPEN; no final Design
or release approval is implied.

Never automatically exit Demo. Every `Demo -> *` requires an explicit human
decision persisted before the Coordinator executes the board mutation:

| Human decision | Authorized transition / follow-up |
|---|---|
| Accept outcome | `Demo -> Done`; close with reason `completed` only when closure is included or separately authorized. |
| Request implementation corrections | `Demo -> In progress`; preserve accepted scope/prior evidence, assign appropriate Developer/evidence owner, repeat affected independent reviews. |
| Request requirements/Design revision | Normally `Demo -> Ready`, or `Backlog` for substantial Product/architecture elaboration. |
| No acceptance yet | Stay in `Demo`. |

Decision authority is human-only; API execution may be Coordinator-owned after
authorization. Tests, QAS/Security PASS, System Architect reconciliation, PR
creation or merge never authorize `Demo -> Done`. No Coordinator, System
Architect, QAS, Security or RTE may infer human acceptance. No ALISS temporary
demo policy, reduced tests, Chrome-only testing, disabled CI or clinical/demo
behavior is adopted.

## Coordinator Project Status ownership

A SAFE handoff is complete only in this order:

1. Obtain the outgoing specialist's result, evidence, next owner and next action.
2. Persist the role checkpoint and re-read it to verify persistence; reconcile Git/evidence.
3. Determine the actual next authorized activity and owner.
4. Resolve live Robin [Project #3](https://github.com/users/dgeorgievski/projects/3)
   by owner/number and verify its identity. Resolve the issue by repository
   `dgeorgievski/robin` plus number/URL, never title alone, and its project item ID.
   Add the issue if absent when accepted tracking requires it. Paginate reads
   until the required issue, item and metadata are found or absence is established.
5. Resolve the live `Status` field and target option by exact name, then update
   the item. Never hardcode or reuse historical project, field, item or option IDs.
6. Query the item again and verify the expected Status and issue identity. If
   already correct, verify and record that readback without a redundant write.
7. Append a Coordinator confirmation with `Project transition verified: <before>
   -> <after>` and `Next owner: <role>`; only then start/assign the next agent.

The Coordinator owns external mutations and checkpoint persistence for read-only
specialists, including QAS, Security Reviewer and System Architect. Specialists
return result/evidence/next owner/action; do not make them mutate the board.
Apply this contract at role completion, role start, remediation and resume. When
Ready represents a waiting role, verify Ready before assignment, then persist
and verify the start checkpoint and In progress before active work begins.
Covered role transitions and their routine board updates require no renewed
human authorization inside an existing bounded workflow.

Select Status by next activity, not outgoing role:

| Next activity / event | Status |
|---|---|
| Not executable: unresolved requirements/decisions, predecessor or Design authorization missing, no authorized next role | Backlog |
| Entry gates satisfied; executable specialist waiting, including accepted Design handed to Developer before start | Ready |
| Active System Architect Design, implementation, evidence construction or remediation | In progress |
| Accepted immutable Git or content-addressed review target; independent QAS, Security, final Architect reconciliation or required PR review active | In review |
| All required technical gates and persisted evidence complete; required human outcome review next | Demo; verify, assign Human / Product Owner, STOP; leave OPEN |
| All required gates including required human acceptance satisfied | Done only under applicable authorization; closure remains separate |

Authorized active Design may move `Backlog -> In progress`. Accepted Design
waiting for Developer may move `In progress -> Ready`; Developer start moves
`Ready -> In progress`. Developer handoff to QAS moves `In progress -> In review`.
Keep `In review` through QAS PASS -> Security -> final Architect reconciliation;
role changes alone do not bounce Status. Findings requiring code/evidence repair
move `In review -> In progress`, followed by new independent verification.
BLOCKED is a checkpoint verdict, not a new Status: retain the phase where the
blocker occurred and record its exact disposition. Never leave active work in
Backlog or infer technical completion from tests, a merged PR or a closed child.

The lifecycle is `Backlog -> Ready -> In progress -> In review -> Demo -> Done`.
Verify all six live option names; a missing required option (especially Demo)
is a configuration blocker, never permission to substitute In review or Done.
Apply the human-controlled Demo contract above to every `Demo -> *`, including
corrections/redesign. This matrix cannot authorize a Demo exit or issue closure.

Every role-completion checkpoint includes `Current Project Status:`,
`Intended Project Status:`, `Next Owner:` and `Next Action:`. Current means observed
live state; intended means the evidence-supported next activity, not a claimed
successful mutation. Preserve the supporting checkpoint before any board write.
If checkpoint persistence is unavailable, return the ready-to-post checkpoint
and stop the handoff. If the checkpoint persists but the board operation fails,
preserve specialist evidence and report:

```text
CHECKPOINT: persisted
PROJECT STATUS UPDATE: BLOCKED
CURRENT STATUS: <actual, or unavailable with reason>
INTENDED STATUS: <expected>
NEXT OWNER: <role>
BLOCKER: <exact permission/tool/API error, with sensitive values redacted>
```

Persist the blocker when possible. Do not claim handoff complete or start the next
role until resolved. Do not request new credentials or broaden privileges to
work around a denial. If readback differs or concurrent changes appear, re-read
latest checkpoints and live state; reconcile or report the conflict rather than
blindly overwriting a human/Coordinator change. Retain immutable evidence and
human decisions. Board repair alone does not authorize specialist execution.

## 3. Reconcile immutable Git scope

Before implementation or validation, establish:

- repository and issue;
- branch;
- baseline commit;
- target commit or expected new commit;
- ancestry;
- exact commit count in the focused delta;
- changed files;
- clean worktree.

Never amend, squash away, rebase away, force-push over, or otherwise rewrite prior SAFE evidence unless a human explicitly authorizes history rewriting.

QAS should validate in a detached worktree or equivalent isolated checkout. Developer should preserve unrelated work and stage only files in scope.

## 4. Keep prompts criterion-specific

Task prompts should contain only information that changes per task:

- issue and criterion;
- branch, baseline, and target SHA;
- prior checkpoint identifiers;
- exact failed or required behavior;
- unique tests or evidence;
- acceptance criteria already passed or still unresolved.

Do not repeat the common Git, checkpoint, verdict, privacy, or role-boundary rules from this skill unless the task overrides them.

## 5. Evidence rules

For every claimed result:

- record the exact command;
- record exit status and relevant counts;
- distinguish observed results from expected results;
- identify checks not run and why;
- record generated files and network use when relevant;
- never invent a passing check;
- never convert unavailable evidence into PASS;
- keep deterministic simulation distinct from live environment testing;
- keep mutation/property campaigns distinct from coverage-guided fuzzing.

Prefer focused tests first, then the affected suite, then full repository gates.

Use repository-defined commands when available. Typical Rust gates are:

```bash
cargo fmt --all -- --check
cargo test --locked --all-targets
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo metadata --locked --offline --format-version 1 --no-deps
make test
make lint
make run
make wasm-check
```

Run only commands relevant to the delta, and list every omitted gate with the exact reason.

## 6. Safety and privacy

Never place credentials, keys, secret values, raw protected fixtures, authorization headers, cookies, private material, or unsafe command output in commits, prompts, logs, or checkpoints.

Use bounded, sanitized error categories instead of copying arbitrary untrusted error text. Link to safe repository evidence rather than pasting sensitive output.

## 7. Verdict semantics

Use evidence-based criterion verdicts:

- **PASS:** every required behavior and evidence gate was independently established.
- **FAIL:** one or more required behaviors or evidence claims failed.
- **BLOCKED:** required repository state, tooling, execution, or checkpoint persistence was unavailable.

A focused PASS is not a full issue PASS. Preserve previously passed criteria and explicitly retain unresolved criteria. Do not claim Security Review, Approved for RTE, production readiness, or final Design approval before those gates occur.

## 8. Checkpoint contract

Every checkpoint must begin exactly with:

```markdown
<!-- robin-safe-checkpoint:v1 -->
```

Then include:

- UTC timestamp;
- SAFE phase;
- role and status;
- branch and relevant commit SHA(s), or `not created` with a reason;
- scope and acceptance-criterion state;
- `Demo gate: required` or `Demo gate: not required`, its authorization/default,
  issue-specific entry conditions, board state/readback and any human exit decision;
- exact validation evidence;
- findings, failures, and checks not run;
- blockers and residual risks;
- `Current Project Status:`, `Intended Project Status:`, `Next Owner:` and
  `Next Action:`; include verified readback in a subsequent Coordinator confirmation;
- expected exit state.

Append a checkpoint:

- after each completed SAFE gate;
- when work becomes blocked;
- before an expected interruption;
- before ending unfinished work;
- at Developer handoff;
- at QAS verdict.

If checkpoint persistence fails, return a complete ready-to-post block and mark
persistence BLOCKED. Do not claim the handoff is complete until the checkpoint is
recorded and Project Status synchronization/readback is verified under the shared
contract.

## 9. Role handoff requirements

### Developer handoff

Include:

- starting and final commit;
- implementation summary;
- focused and full checks;
- acceptance-criterion state;
- checks not run;
- residual risks;
- exact QAS scope and baseline/target.

### QAS handoff

Include:

- immutable reconciliation;
- PASS/FAIL/BLOCKED per criterion in scope;
- independent commands and observed results;
- findings by severity;
- checks not run;
- residual risks;
- exact next owner/action.

### RTE handoff

Proceed only when all required criteria and independent gates pass. Summarize PR-ready evidence and the remaining human action; do not merge without explicit authorization.
