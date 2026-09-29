# AI security review checklist

Traceguard intentionally keeps authorization and containment decisions outside the model. Use this checklist when changing prompts, tools, evidence handling, or approval workflows.

## Tool safety

- Keep the planner bounded to explicitly registered tools.
- Enforce authorization inside each tool or service boundary, not in prompt text.
- Treat log lines, alert descriptions, and model output as untrusted data.
- Reject cross-organization asset, alert, and containment access server-side.

## Prompt-injection resistance

- Do not allow instruction-like telemetry to alter tool permissions or policy.
- Separate system policy from evidence content and preserve typed tool arguments.
- Redact secrets before optional model calls and keep model context scoped to the active organization and incident.
- Test malicious evidence strings that request credential disclosure, policy override, or unauthorized tools.

## Human approval

- Keep containment proposals non-executing until a separate authorized administrator approves them.
- Preserve the different-approver requirement and replay protection.
- Log proposal creation, approval identity, decision, and resulting simulated action.

## Verification

Changes affecting AI behavior should include deterministic tests for tenant isolation, authorization failure, malicious evidence, replayed approvals, tool-call bounds, malformed model output, and model unavailability. A generative model must remain optional for the core security decision path.
