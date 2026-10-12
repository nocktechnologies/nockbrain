# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | Yes |

## Report a vulnerability

Report vulnerabilities privately. Don't open a public issue.

Use GitHub private vulnerability reporting on this repository: open the Security tab and choose "Report a vulnerability". You can also email info@nocktechnologies.io.

## Scope

These areas are in scope:

| Area | Examples |
|---|---|
| Signature verification | Signed facts, the signed revocation chain, signed correction and forgetting proposals, the recovery journal, and both the Ed25519 and HMAC-SHA256 paths |
| Store integrity | Proposal digests and staleness checks, the store lock, interrupted operations and `recover` |
| Path handling and refusals | Source path checks and denied paths, transcript root containment, symlink and hard-link refusals, ownership and permission checks on store files |
| Secret redaction | Secrets that survive import into a proposal |
| The hooks | Recall verification, what reaches Claude as context, capture outside the allowed transcript roots, anything that makes a hook write accepted facts |
| Memory Explorer | The local server's Host and Origin checks, the per-launch capability token, route and request handling, and the refusal to read the private signing key |

Pattern-based secret redaction is documented as imperfect. A reliable way to get a common secret format past it is still worth reporting.

## What to include

Tell us the NockBrain version from the `VERSION` file, your operating system and Python version, and whether `cryptography` is installed. Describe the steps to reproduce the problem using fictitious data, what an attacker gains, and any proof of concept. Never send real memories, transcripts or keys.

## What happens next

We acknowledge every report, investigate it, and fix confirmed vulnerabilities in the supported versions. With your permission, we credit you in [CHANGELOG.md](CHANGELOG.md) when the fix ships. There is no bug bounty.
