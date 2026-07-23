---
name: safe-workflow
description: Use for starting, implementing, validating, resuming, or preparing Robin GitHub issue work with SAFE role boundaries, durable checkpoint comments, and evidence gates. Do not use for simple questions that make no repository change.
---

# SAFE Workflow for Robin

Use this sequence for a single issue or cohesive change:

1. **Resume** — read the GitHub issue and its comments, locate the latest valid checkpoint, and reconcile it with the current branch, commit, worktree, and available evidence.
2. **Define** — BSA states outcome, scope, non-goals, testable acceptance criteria, and security concerns.
3. **Design** — System Architect reviews architecture and trust boundaries when the change is material.
4. **Implement** — Developer makes a focused change and records checks run.
5. **Validate** — QAS independently maps every acceptance criterion to evidence.
6. **Release** — RTE assembles evidence and declares the work ready for human review.

Do not collapse implementation and independent validation into one role for security-sensitive work. A human owns ambiguous product decisions, credentials, destructive operations, production changes, and final merge approval.

## GitHub issue checkpoint contract

GitHub Issues are Robin's durable system of record for SAFE work. The issue body
holds stable scope, acceptance criteria, and Definition of Done. Append a new
checkpoint comment at every completed gate, whenever work becomes blocked, before
an expected interruption, and before ending a session with unfinished work. Do
not edit an older checkpoint to represent new state.

Every checkpoint comment must start with this exact marker:

```markdown
<!-- robin-safe-checkpoint:v1 -->
```

Then record:

- UTC timestamp and SAFE phase
- role and status
- last completed gate
- branch and commit SHA, or `not created` with a reason
- completed work and acceptance-criterion progress
- exact validation evidence, including failures and checks not run
- decisions, blockers, and residual risks
- one concrete next action and the expected exit state

Never put credentials, keys, secret values, sensitive fixtures, or other secret
material in an issue or checkpoint. Link to safe repository evidence instead of
copying sensitive output.

Before resuming work, read all checkpoint comments and select the latest one that
matches the issue and workflow version. Compare its branch and commit with the
local repository, inspect `git status` and relevant diffs, and confirm that its
evidence applies to the current commit. If state diverged, reconcile it and append
a new checkpoint explaining the discrepancy before continuing. Git state and
fresh command output override stale checkpoint prose.

Use the available GitHub issue-comment capability to persist the checkpoint. If
GitHub is unavailable or a role cannot write comments, return a complete
ready-to-post checkpoint block to the parent agent and mark persistence BLOCKED.
Do not claim the role's handoff is complete until the checkpoint is recorded on
the issue.

## Working conventions

- Suggested branch: `ROB-123-short-description` when a ticket exists; otherwise use the repository's current convention.
- Suggested commit: `type(scope): description [ROB-123]`.
- Include the GitHub issue number in every delegated role prompt.
- Never invent a passing test. Record the command, result, and any checks that could not run.
- Do not claim completion while required acceptance criteria are blocked.

Example evidence:

```markdown
Ticket: ROB-123
Outcome: <user-visible result>
Validation:
- `dart test` — PASS (42 tests)
- `dart analyze` — PASS
Risks/blocked checks: None
QAS verdict: Approved for RTE
```

Example checkpoint:

```markdown
<!-- robin-safe-checkpoint:v1 -->

## SAFE checkpoint — Construction

- Recorded: 2026-07-22T18:00:00Z
- Role: Developer
- Status: In progress
- Last completed gate: Design approved
- Branch: ROB-123-encrypted-storage
- Commit: 31d9c82

Completed:
- Added the storage interface and encryption implementation.

Evidence:
- `make test` — PASS (18 tests)

Blockers and risks:
- Secure deletion remains incomplete.

Next action:
- Implement secure deletion, rerun the full test suite, and hand off to QAS.

Expected exit: Ready for QAS
```
