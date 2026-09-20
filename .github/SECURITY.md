# Security policy

## Scope

Everything in this repository: `core`, `store`, `server`, the clients and the reference deployment in `deploy/`. The threat model, with what the system promises and what it does not, is in [`docs/threat-model.md`](../docs/threat-model.md). A finding that falls under "Outside the model" or "Accepted limitations" is welcome as a discussion, but it is not a vulnerability.

## How to report

**Do not open a public issue.** Use GitHub's private form: *Security → Report a vulnerability* in this repository. Include the version or commit, steps to reproduce and the impact you see.

Commitment: initial response within 72 hours; assessment and plan within 14 days; coordinated disclosure once there is a fix. If the finding affects the project's public server, it is fixed and redeployed before publication.

## Acknowledgement

Whoever reports a confirmed vulnerability appears, if they wish, in the release note of the version that fixes it and in `docs/audit-log.md`.

## External review

The cryptographic core is pending external review before the beta (`docs/audit-log.md`, spec 061). Until then, treat the project as experimental.
