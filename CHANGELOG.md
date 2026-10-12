# Changelog

Notable changes to NockBrain are recorded in this file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-10-12

First public release.

### Added

- Review-first capture. `propose` imports Markdown notes or Claude Code JSONL transcripts you select into a review queue, and an optional `Stop` hook queues candidates from the session transcript each time Claude finishes a reply, keeping one pending proposal per session. Nothing is stored until you `apply` the exact proposal digest you reviewed, and the hook never applies anything.
- Pattern-based secret redaction on every imported candidate, with redaction, skip and privacy-fence counts in each proposal.
- A signed local store. Facts are signed with Ed25519 when the `cryptography` package is installed and with HMAC-SHA256 from the standard library otherwise. Proposals are bound to the store, its signing key and its current generation, so a stale proposal can't be applied.
- An opt-in recall hook on `UserPromptSubmit`. When the classifier finds a question about earlier work, it verifies every signature in the store, ranks current facts with BM25, and returns up to 800 tokens to Claude as untrusted reference context.
- `correct`, `forget` and `recover`. A correction supersedes the old record without rewriting it, forgetting removes one record and leaves a signed revocation that blocks reimporting the same content and kind, and a signed journal lets `recover` finish an interrupted change.
- Memory Explorer, a read-only local viewer on `127.0.0.1` with a per-launch capability token, a BM25 recall preview, and a fictitious demo store.
- An agent playbook that lets Claude run these commands from plain requests: `claude --append-system-prompt-file docs/agent-playbook.md`.
- A standard-library smoke test and CI on Linux and macOS for Python 3.9 through 3.13.

[Unreleased]: https://github.com/nocktechnologies/nockbrain/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/nocktechnologies/nockbrain/releases/tag/v0.1.0
