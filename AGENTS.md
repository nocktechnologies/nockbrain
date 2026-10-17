# NockBrain agent guide

## What this repository is

NockBrain is a local-first, review-first memory store for one person working
across sessions. It imports only selected notes or Claude Code transcripts,
redacts common secret patterns, and waits for an explicit review and apply
before storing any fact. Recall returns matching reviewed facts as untrusted
reference context. The main entry point is `bin/consumer-brain.py`.

The store, hooks, and Memory Explorer stay on the user's machine. NockBrain
makes no model calls, telemetry, or network requests. Its MCP server is local
stdio and offers read-only `recall` and `status` tools.

## Build, test, and release

- There is no build step, package manager, or required dependency. Run the
  Python entry points directly from the repository root.
- Supported Python is 3.9 or newer on macOS and Linux. Keep syntax and standard
  library calls compatible with Python 3.9.
- Run the full suite with `python3 -B -m unittest discover -s tests -v`.
- CI runs that suite on Python 3.9 through 3.13 on Linux and macOS, plus the
  stock macOS interpreter. A separate job installs `cryptography` and checks
  the Ed25519 path.
- The CI workflow also checks that paths documented in this file exist and are
  tracked. Run `python3 scripts/check-agents-paths.py` from the repository root.
- There is no deploy step. A `v*` tag runs the release workflow, which takes
  notes from the matching section in `CHANGELOG.md`.
- For contribution and release-source rules, read `CONTRIBUTING.md`.

## Rules and gotchas

- This is a public repository; keep agent guidance and handoff notes
  product-only, with no private coordination or review instructions.
- Keep the standard library as the only required dependency. `cryptography` is
  optional: new stores use Ed25519 when it is installed and HMAC-SHA256 when it
  is absent. An HMAC store's public-key file contains secret material too.
- Never replace or convert an existing store key automatically. Back up the
  whole store, including both key files, and keep it outside a Git repository.
- A proposal is not a memory. Read the full proposal and apply its exact digest
  only after review. Hooks never apply proposals.
- Redaction is pattern-based and can miss secrets; the review step is required.
  Do not add real memories, transcripts, stores, or keys to source, issues, or
  pull requests. Use `examples/notes.md` for fictitious data.
- Corrections preserve the old signed fact as history. Forgetting removes the
  selected record and leaves a signed revocation; paraphrases, source notes,
  backups, and already captured Explorer snapshots are separate copies.
- If a store operation is interrupted, run `recover` before making more
  changes. Do not edit store files by hand to bypass a verification error.
- `setup-hooks` writes its settings into the store and embeds absolute paths to
  this checkout and the Python interpreter. Run setup again after moving either.
- Hook roots must be selected transcript directories. Avoid broad roots; the
  hook accepts only transcripts inside configured roots and never scans them.
- Hooks have short time limits and fail without blocking Claude Code. An empty
  recall result can mean no match, a non-recall prompt, or failed verification.
- Memory Explorer is read-only and binds only to loopback. Its URL contains a
  per-launch capability token; keep the link private and stop it with Ctrl-C.
- The normal consumer recall path uses lexical BM25 matching. Semantic search
  and graph expansion are not enabled by the hooks or MCP server.
- The MCP server is read-only. Other agents can recall through it, but capture
  still comes from Claude Code or an explicitly selected notes file.
- Do not commit live stores or key material. The store's ignore-all
  `.gitignore` is a safeguard, not a substitute for keeping the store elsewhere.
- `NOCKBRAIN_SIGNING_KEY` and `NOCKBRAIN_SIGNING_PUB` override key file paths
  for internal commands. Leave them unset for ordinary store use; a wrong key
  can make verification fail closed. CI's
  `NOCKBRAIN_TEST_EXPECT_ALGORITHM` is test-only.

## Repository map

| Path | Purpose |
|---|---|
| `bin/consumer-brain.py` | Main user CLI and subcommand routing |
| `bin/consumer-hook.py` | Claude Code capture and recall hook adapter |
| `bin/nockbrain-mcp.py` | Read-only MCP server for recall and status |
| `bin/_consumer_import.py` | Selected-file and Claude transcript parsing |
| `bin/_consumer_store.py` | Review queue, signed store, and recovery |
| `bin/_sign.py` | Ed25519/HMAC key handling and signatures |
| `bin/_revoke.py` | Signed revocation and supersession history |
| `bin/budget-recall.py` | Lexical ranking and recall budget |
| `bin/recall-classifier.py` | Recall-intent classifier |
| `bin/explore-memory.py` | Starts the local Memory Explorer |
| `web/explorer/` | Read-only Explorer page and browser code |
| `tests/test_smoke.py` | End-to-end command and MCP smoke coverage |
| `examples/notes.md` | Fictitious import example |
| `.github/workflows/ci.yml` | Test matrix and agent-path check |
| `.github/workflows/release.yml` | GitHub release from a version tag |
| `scripts/check-agents-paths.py` | Verifies paths cited in this file |
| `docs/HANDOFF.md` | Current pod notes; read at start and update at end |
| `docs/archive/` | Dated handoff snapshots |

## Documentation

`CHANGELOG.md` records releases, `docs/ROADMAP.md` records product direction,
and `docs/ARCHITECTURE.md` maps the main flows. For user-facing detail, see
`docs/getting-started.md`, `docs/commands.md`, `docs/how-it-works.md`,
`docs/privacy-and-security.md`, and `docs/mcp.md`. Keep gotchas agents cannot
infer here, then update the relevant guide when behavior changes.

At the start of each run, read `docs/HANDOFF.md`. Before finishing, add what
changed, what caused friction, and what remains open. Move dated snapshots to
`docs/archive/`.
