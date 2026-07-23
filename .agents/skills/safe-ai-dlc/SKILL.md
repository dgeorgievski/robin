---
name: safe-ai-dlc
description: Use for multi-issue Robin initiatives that need SAFE planning, dependency ordering, parallel agent work, GitHub issue checkpoints, and explicit human decisions. Do not use for one small ticket; use safe-workflow instead.
---

# SAFE x AI-DLC Program Workflow

Treat a multi-issue initiative as a Unit of Work delivered through one or more short Bolts. Use one GitHub coordination issue for the Unit of Work or Bolt and one GitHub issue for each independently deliverable work item.

1. **Resume:** read the coordination issue and each active work-item issue, reconcile their latest `<!-- robin-safe-checkpoint:v1 -->` comments with Git and current evidence, and identify the next unblocked action.
2. **Inception:** define the outcome, Definition of Done, risks, issue breakdown, dependencies, and a human decision checkpoint.
3. **Mob elaboration:** use BSA and System Architect roles to remove ambiguity before code changes begin.
4. **Construction:** delegate only independent, bounded tasks. Avoid parallel edits to the same files. Require Developer-to-QAS handoffs.
5. **Operations:** assemble evidence, resolve failures, document residual risk, and stop for human acceptance and merge.

Exit a Bolt on evidence, not elapsed time. If scope or security policy remains unclear, run a discovery spike rather than forcing implementation.

Apply the checkpoint contract from `safe-workflow` to every work-item issue.
Update the coordination issue with an append-only checkpoint whenever issue
dependencies, ownership, gate state, or the next executable work item changes.
The coordination checkpoint must list each issue's latest phase and status,
dependency links, active owner, blockers, and the next unblocked issue. A rollup
does not replace the detailed checkpoint on the work-item issue.

Do not start an issue whose latest checkpoint says it is blocked. Do not infer
completion from a closed issue, merged branch, or green check alone; require the
expected role checkpoint and evidence. If multiple agents could update the same
issue concurrently, assign one checkpoint owner before work begins.
