# Security Policy

## Reporting vulnerabilities

Please **do not** open a public issue for security vulnerabilities.

1. Contact the repository maintainers privately via GitHub
   (`aakanksha-2005`) — use a private security advisory or the maintainer's
   contact listed on their GitHub profile.
2. Include: affected commit/version, reproduction steps, impact, and any
   suggested fix.
3. Expect acknowledgement before public disclosure. Fixes will be released
   with a regression test.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x (main branch, prototype) | best-effort, development only |

## Scope and expectations

RASP v0.1 is an **experimental prototype**:

- Development-only header identity — do not expose beyond localhost.
- In-memory audit/approval state.
- Detection controls are defense-in-depth, not complete.

See `docs/THREAT_MODEL.md` (assets, adversaries, residual risks) and
`docs/LIMITATIONS.md` (what is untested). Reports that demonstrate a
bypass of the *enforced* controls (execution boundary, approval binding,
fail-closed policy evaluation) are the highest priority.
