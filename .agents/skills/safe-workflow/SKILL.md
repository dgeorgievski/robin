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
- **RTE:** prepares the human-reviewed release handoff only after all required gates pass.

Do not collapse Developer and QAS for security-sensitive work. Human approval remains required for ambiguous requirements, credentials, destructive operations, production changes, publishing, and final merge.

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
- exact validation evidence;
- findings, failures, and checks not run;
- blockers and residual risks;
- one concrete next owner/action;
- expected exit state.

Append a checkpoint:

- after each completed SAFE gate;
- when work becomes blocked;
- before an expected interruption;
- before ending unfinished work;
- at Developer handoff;
- at QAS verdict.

If checkpoint persistence fails, return a complete ready-to-post block and mark persistence BLOCKED. Do not claim the handoff is complete until the checkpoint is recorded.

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
