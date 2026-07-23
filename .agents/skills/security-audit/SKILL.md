---
name: security-audit
description: Use when reviewing Robin changes involving secrets, cryptography, authentication, authorization, storage, transport, logging, dependencies, or trust boundaries.
---

# Robin Security Audit

Perform an independent, read-only review unless the user explicitly asks for fixes.

- Identify assets, actors, entry points, trust boundaries, and failure modes.
- Search the diff and history for committed credentials or secret material without printing values.
- Verify secrets are not logged, embedded in errors, fixtures, screenshots, or telemetry.
- Check authentication and authorization on every protected path, including failure cases.
- Review cryptographic choices for established primitives, correct nonce/key handling, rotation, and deletion behavior.
- Confirm untrusted input is validated and sensitive data has explicit retention and lifecycle rules.
- Run applicable tests and dependency/security scanners when they exist.

Report findings by severity with file references, impact, evidence, and a safe remediation. State PASS only when all required checks ran; otherwise state BLOCKED and name the missing evidence.

When the review is attached to a GitHub issue, read its latest
`<!-- robin-safe-checkpoint:v1 -->` comment before reviewing and append a Security
Review checkpoint with the verdict, safe evidence references, residual risks,
and next action. Never paste secret material into the issue. If the reviewer
cannot write the comment, return a ready-to-post checkpoint and mark persistence
BLOCKED; do not claim the security handoff is complete.
