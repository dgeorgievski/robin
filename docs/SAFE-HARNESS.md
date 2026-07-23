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
the checkpoint comment is recorded.

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
