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
For execution across roles or children, apply its
[bounded workflow execution contract](../safe-workflow/SKILL.md#bounded-workflow-execution).
The program coordinator carries the human's authorization into covered child
handoffs; it cannot authorize new scope itself. Respect each child's accepted
scope, dependency order, checkpoint ownership, independent reviews, and human
Product/Design gates. Preparing a program or child issue does not authorize its
execution, and authorization for one child does not extend to another.

## Coordinator Project Status ownership

Apply [safe-workflow's shared Status contract](../safe-workflow/SKILL.md#coordinator-project-status-ownership)
to each child and the coordination issue at every handoff and role start:
checkpoint -> board update -> verification -> next role. Coordinator owns the
external writes; read-only specialists return result/evidence/next owner/action.
Carry current/intended Project Status and next owner/action in checkpoints and
verify live IDs/readbacks. Determine each item's Status from its own next activity;
a parent rollup or child's completion does not advance another issue. Preserve
child dependencies, bounded authority and human-only Demo exits. Failed board
synchronization blocks that handoff; record the blocker in the rollup as well.

Update the coordination issue with an append-only checkpoint whenever issue
dependencies, ownership, gate state, or the next executable work item changes.
The coordination checkpoint must list each issue's latest phase and status,
dependency links, active owner, blockers, and the next unblocked issue. A rollup
does not replace the detailed checkpoint on the work-item issue.

Do not start an issue whose latest checkpoint says it is blocked. Do not infer
completion from a closed issue, merged branch, or green check alone; require the
expected role checkpoint and evidence. If multiple agents could update the same
issue concurrently, assign one checkpoint owner before work begins.

For each child and the coordination issue, carry `Demo gate: required` or
`Demo gate: not required` and its accepted entry conditions in checkpoints. Apply
[safe-workflow's human-controlled Demo contract](../safe-workflow/SKILL.md#human-controlled-demo-and-board-ownership):
Coordinator may enter Demo after required gates and verified board updates, then
stops with Human / Product Owner next. Every exit from Demo requires an explicit
persisted human decision, even when a parent rollup, green checks or merged PR
suggests completion. Acceptance of one child does not accept another; closure
requires its own included or separate authorization. No program role can infer
human acceptance or reduce Robin validation requirements.
