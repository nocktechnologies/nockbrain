# Command reference

This page documents every command in NockBrain 0.1.0, its flags, and the limits the store enforces. For a guided first run, read [getting-started.md](getting-started.md). To let Claude run these commands for you from plain requests, load the [agent playbook](agent-playbook.md). The sample notes in [examples/notes.md](../examples/notes.md) are fictitious and safe to import.

NockBrain creates one fresh, private store and imports only the files you select. It doesn't discover data in your home directory, change your global Claude Code settings, call a model, or connect to any remote service. The commands run on macOS and Linux.

## How commands work

Every command has the same shape. Run it from the repository root:

```sh
python3 bin/consumer-brain.py COMMAND --store ABSOLUTE_PATH [FLAGS]
```

`--store` is required on every command and has to be an absolute path. The examples on this page use:

```sh
STORE="$HOME/nockbrain-store"
```

Every command except `open` prints JSON on standard output. `status` and `review` pretty-print it; the others print one line. `open` hands over to Memory Explorer, which prints its own URL and messages. When a command fails it prints `{"error": "..."}` with a short fixed message and exits with status 2. Invalid arguments produce a generic message that never echoes what you typed, so terminal control characters in an argument can't reach your terminal. Paths that contain control characters are refused. Running the script with no command prints its help.

| Command | Flags besides `--store` | What it does |
|---|---|---|
| `init` | none | Create a fresh, private store |
| `status` | none | Show store health, counts and next commands |
| `propose` | `--format {markdown,claude-jsonl}`, `--source ABSOLUTE_FILE` (repeatable) | Import selected files into the review queue |
| `pending` | none | List saved proposals and whether they're stale |
| `review` | `--proposal SHA256` | Read one complete proposal without applying it |
| `apply` | `--proposal SHA256` | Accept the exact proposal you reviewed |
| `discard` | `--proposal SHA256` | Delete one saved proposal |
| `correct` | `--fact FACT_ID`, `--replacement-proposal SHA256` | Propose replacing one fact with a single imported candidate |
| `forget` | `--fact FACT_ID` | Propose erasing one fact and clearing saved proposals |
| `recover` | none | Finish an interrupted memory operation you already accepted |
| `setup-hooks` | `--transcript-root ABSOLUTE_DIRECTORY` (repeatable) | Generate opt-in Claude Code session settings |
| `open` | none | Open the local, read-only Memory Explorer |

Every `--proposal` and `--replacement-proposal` value is the full 64-character SHA-256 digest. Abbreviated digests are refused.

## Create a store

```sh
python3 bin/consumer-brain.py init --store "$STORE"
```

The destination must not exist, and its parent directory must. Choose a location outside any source checkout or repository. `init` creates the directory with owner-only permissions and writes an empty `facts.json`, a `proposals/` directory, the signing key pair (`signing-key` and `signing-key.pub`), the store manifest `customer.json`, and a `.gitignore` that ignores everything.

New stores sign with Ed25519 when the `cryptography` package is importable, and with HMAC-SHA256 from the standard library otherwise. `init` prints the new store UUID, the algorithm, and ready-made `status` and `open` commands. It never prints key material. If initialization is interrupted, the incomplete directory stays private and is never adopted; run `init` again with a new destination.

## Check the store

```sh
python3 bin/consumer-brain.py status --store "$STORE"
```

`status` verifies the store and reports its UUID, its generation (a hash of the accepted facts and revocations), the number of facts with how many are current and superseded, the number of revoked IDs, the number of saved proposals, and whether recovery is required. It also prints the exact `pending`, `open` and `recover` commands for this store.

## Propose an import

```sh
SOURCE="$PWD/examples/notes.md"
python3 bin/consumer-brain.py propose --store "$STORE" --format markdown --source "$SOURCE"
```

`propose` reads only the files you pass and saves an unsigned proposal in the review queue. Nothing is accepted yet. It prints the candidate count, the full proposal digest, the import statistics, and an exact `review` command as a JSON string. The simplest way to continue is to type the review command yourself with the printed digest. If you copy the command out of the JSON instead, decode the JSON string first, because removing the outer quotes alone doesn't decode escapes in unusual paths.

To import several files, repeat `--source` once per file. All files in one proposal share one format. Each source has to be an absolute path to an ordinary file with a single hard link. The file itself can't be a symlink, though a symlinked parent directory is fine. The same file can't be selected twice. Sources must be UTF-8 text, and NockBrain never rewrites them.

Some source paths are always refused: anything inside a `.ssh` or `.gnupg` directory, any file whose name starts with `signing-key`, any path containing `token` or `secret`, `.env` files, paths with a file or directory name starting with `credentials` or `id_rsa`, and `.pem` files.

### Markdown sources

With `--format markdown`, only lines that start with `- ` are read. Each bullet becomes a candidate when it carries a recognized tag or matches the built-in patterns; other bullets are ignored. Tag your own notes with `[DECISION]`, `[DIRECTIVE]` or `[CORRECTION]` at the start of the bullet. The tag stays in the stored content. The classifier doesn't treat an untagged "I decided..." as a decision. It does recognize a few role words, so "the user decided..." works without a tag. Names carry no special authority: "my teammate decided..." is read like any other sentence. `[ARCHITECTURE]`, `[BUG]`, `[CONFIG]` and `[CONTENT]` tags are also recognized.

### Claude Code transcript sources

With `--format claude-jsonl`, NockBrain reads Claude Code JSONL transcripts you select and keeps each message's role. Tool calls and tool results never become candidates. A message that mixes text with a tool result is skipped, because its authorship is ambiguous. Subagent sidechain messages are excluded. System reminders that Claude Code appends to a typed prompt are stripped and counted. Only your own turns can produce decision, directive or correction candidates; assistant text never can. The built-in privacy fences also drop tool calls and tool results that reference denied paths, tools or endpoints, and the statistics count each one.

### What every import does

Each candidate's text passes through pattern-based secret scrubbing, and matches are replaced with `[REDACTED_SECRET]`. Pattern matching is imperfect, which is why a complete review matters. A candidate longer than 1,500 characters is skipped and counted as `overlong_skipped`, never truncated. Extraction is heuristic and can miss useful facts.

Identical content and kind found more than once in one proposal becomes one candidate with combined evidence. Each source gets a receipt holding its path, with any secret-shaped text scrubbed, and the SHA-256 hash of its raw bytes. Proposal statistics hold only counts: files, candidates, redactions, skips and privacy-fence hits. A malformed, unsafe, oversized or changed source fails the whole proposal.

## Review a proposal

```sh
python3 bin/consumer-brain.py review --store "$STORE" --proposal FULL_DIGEST
```

`review` only reads. It prints the complete proposal: each candidate's full content, kind, confidence, subject and evidence, the source receipts, and the statistics. It also reports whether the proposal is stale, whether recovery is required, and the exact `apply` command. The JSON output escapes the escape character and every other C0 and C1 control code, so stored text can't send escape sequences to your terminal.

Read all of it. Check that each candidate is accurate, current, attributed to the right person, and free of sensitive details. If anything is wrong, fix your source file and run `propose` again. `facts.json` doesn't change until you apply.

## Apply a proposal

```sh
python3 bin/consumer-brain.py apply --store "$STORE" --proposal FULL_DIGEST
```

`apply` accepts the proposal as a whole; there is no per-candidate apply. It signs each new candidate and adds it to `facts.json`. A candidate whose ID is already stored or revoked is skipped, and the existing record keeps its evidence and signature. The command prints the added, skipped and total counts. A stale proposal is refused.

Applying doesn't remove the proposal file. Once the store changes, `pending` lists it as stale, and you can discard it.

## Review queue

```sh
python3 bin/consumer-brain.py pending --store "$STORE"
python3 bin/consumer-brain.py discard --store "$STORE" --proposal FULL_DIGEST
```

`pending` lists each saved proposal's digest, its action (`import`, `correct` or `forget`), its candidate count, and whether it's stale. It never prints memory content; use `review` to read a proposal before applying it. `discard` deletes one proposal and leaves accepted facts alone.

The queue holds at most 100 proposal files and 64 MiB in total. When it fills, `propose`, the capture hook, `correct` and `forget` refuse to add more until you discard old or stale proposals.

## Open Memory Explorer

```sh
python3 bin/consumer-brain.py open --store "$STORE"
```

`open` starts Memory Explorer for this store and opens its loopback URL in your browser. Keep that terminal running while you use the page; Ctrl-C stops the server. Explorer is read-only. Its BM25 recall preview shows one selection under the displayed settings, and it doesn't record what an agent actually received. To print the URL without opening a browser, run `python3 bin/explore-memory.py --store "$STORE"`. See [memory-explorer.md](memory-explorer.md) for the details.

## Claude Code hooks

The two hooks are optional. Choose the specific existing directory that holds the transcripts you want to allow. Claude Code tells the hook which transcript belongs to the session, and that file has to be inside a directory you allowed. Setup doesn't scan the directory or import old conversations. Avoid broad roots that contain unrelated projects.

```sh
python3 bin/consumer-brain.py setup-hooks --store "$STORE" \
  --transcript-root /absolute/path/to/selected/project-transcripts
claude --settings "$STORE/claude-settings.json"
```

Repeat `--transcript-root` to allow another directory, up to 16. Each root has to be an existing directory, not a symlink, given as an absolute path at least three levels deep, such as `/a/b/c`. A root can't contain the store, and two roots can't resolve to the same directory. Setup refuses to run while recovery is required.

Setup writes one owner-only file, `claude-settings.json`, inside the store, and prints the settings path, a quoted launch command, and the `pending` command. The generated hooks call this checkout's `bin/consumer-hook.py` with the current Python interpreter by absolute path, so regenerate the settings after moving either one.

Your normal Claude Code settings still apply. Claude Code merges hook entries across settings levels, so this workflow doesn't remove existing hooks, and other memory hooks you already use can inject their own context next to NockBrain's. Managed and plugin hooks can apply too. Run `/hooks` inside Claude Code to see what's active, and test in a setup without other memory hooks if you want NockBrain on its own. The settings file adds two hooks and nothing else; it doesn't sandbox the rest of the session. To opt out, stop launching Claude Code with this settings file.

### What the recall hook does

The `UserPromptSubmit` hook runs on every prompt in a session launched with the settings file, with a 5-second limit. It accepts prompts up to 2,000 characters. First it asks the recall classifier whether the prompt refers to earlier work, such as "what did we decide" or "last time". Short acknowledgments and prompts that start with words like review, send or merge are skipped. If the classifier says no, the hook adds nothing.

If recall is requested, the hook verifies the store before using it: the manifest, the verification key, the signature on every fact, and the signed revocation chain. It adds nothing if any check fails, if recovery is pending, or if the store changes while it reads. It copies only `facts.json`, `signing-key.pub` and `revocations.jsonl` into a private scratch directory and never reads `signing-key`. Then it ranks current facts with BM25 and returns up to 800 tokens of them as `additionalContext`, labeled as untrusted reference data for Claude to reconcile with the current request. Semantic search and graph expansion are off.

### What the capture hook does

The `Stop` hook runs each time Claude finishes responding, with a 10-second limit. It reads the transcript path Claude Code supplies. The path must end in `.jsonl`, point to an ordinary single-link file, and sit inside an allowed root both as written and after resolving symlinks. The hook imports the transcript with the `claude-jsonl` rules above and drops candidates that are already stored or revoked. If anything new remains, it saves a pending proposal and shows a fixed notification with the proposal digest and candidate count. It never runs `apply`. Use `pending` and `review` to inspect what it saved. Each capture reads the whole transcript and keeps one pending proposal per transcript: a new capture replaces the earlier pending one from the same session, which it already includes, and the notification says so. If you run `review` or `apply` on a replaced digest, NockBrain tells you it was replaced; run `pending` and review the newest one.

If the transcript is still being written or exceeds the import limits, capture fails safely instead of saving part of it. Some Claude Code versions append the final assistant response after Stop runs; that text is only considered at a later Stop or a manual import.

### Failure behavior

Both hooks do their work in a child process with an empty home directory, user site-packages turned off, and a fresh owner-only scratch directory under `/tmp`. They never block a conversation. On any failure they return nothing and print one fixed warning line to standard error. No recall context can mean the classifier didn't request recall, nothing matched, or verification failed; check the warning and run `status`. The hooks don't keep a raw transcript log. The input and output contracts follow the [Claude Code hooks reference](https://code.claude.com/docs/en/hooks), and the launch command uses the documented `--settings` flag from the [CLI reference](https://code.claude.com/docs/en/cli-reference).

## Correct a memory

Copy the complete fact ID from Memory Explorer. Fact IDs are `customer-` followed by 64 hex characters. First write a notes file that contains exactly one replacement fact and run `propose` on it. Creating that replacement proposal doesn't accept it. Pass its digest to `correct`, then review and apply the correction:

```sh
python3 bin/consumer-brain.py correct --store "$STORE" --fact FACT_ID \
  --replacement-proposal REPLACEMENT_DIGEST
python3 bin/consumer-brain.py review --store "$STORE" --proposal CORRECTION_DIGEST
python3 bin/consumer-brain.py apply --store "$STORE" --proposal CORRECTION_DIGEST
```

`correct` requires a current target fact and a replacement proposal with exactly one candidate that isn't stale. The replacement has to be a new fact that isn't already stored or revoked. Don't apply the replacement proposal on its own; the correction carries it. `review` of a correction also shows the target record.

Applying the correction signs the new record, marks the old one superseded, and appends a signed revocation event. The old record's signed content and evidence aren't rewritten, and Explorer can still show it in history. A correction keeps the old record; use `forget` to remove one.

## Forget a memory

To erase one record, create, review and apply a forgetting proposal:

```sh
python3 bin/consumer-brain.py forget --store "$STORE" --fact FACT_ID
python3 bin/consumer-brain.py review --store "$STORE" --proposal FORGET_DIGEST
python3 bin/consumer-brain.py apply --store "$STORE" --proposal FORGET_DIGEST
```

Applying it removes that record from `facts.json` and clears every saved proposal, because proposals can hold copies of the forgotten text. A signed revocation keeps the record's ID and no content. Because an ID is derived from the store, the kind and the content, importing the same content with the same kind later is skipped instead of restored.

This is exact-record forgetting. Paraphrases, other records, your original source files, backups and shell output are outside its scope. Refresh or close any open Explorer page afterward, because snapshots it already captured are separate copies.

## Recover from an interruption

If a memory operation is interrupted, `status` reports that recovery is required, and the store refuses new changes until it's resolved. Applying a correction or a forgetting proposal writes a signed journal before it publishes anything, so an interrupted one can be finished:

```sh
python3 bin/consumer-brain.py recover --store "$STORE"
```

`recover` validates the journal and the store, then finishes the operation you already accepted. It never accepts a pending proposal. If the interruption left only an unpublished temporary file, `recover` deletes it without changing any memory. It cleans up only the temporary files NockBrain itself creates; unknown files and copies you made are outside its scope. When nothing needs recovering it reports that and changes nothing. NockBrain makes no claim about surviving power loss. Don't edit store files by hand to get past a recovery error.

## Limits

| Limit | Value |
|---|---|
| Source files per proposal | 16 |
| Size of one source file | 8 MiB |
| Combined size of all sources in one proposal | 32 MiB |
| Candidates per proposal | 1,000 |
| Length of one candidate | 1,500 characters (longer ones are skipped and counted) |
| Evidence entries on one candidate | 1,000 |
| Saved proposals | 100 files and 64 MiB in total |
| One proposal, `facts.json`, or `revocations.jsonl` | 32 MiB each |
| Transcript roots per `setup-hooks` | 16 |
| Prompt length the recall hook accepts | 2,000 characters |
| Hook event input | 16 KiB |
| Recall budget | 800 tokens |

Apart from overlong candidates, which are skipped and counted, exceeding a limit fails the operation with an error instead of producing a partial result.

## Proposals, keys and backups

A proposal is bound to the store UUID, the signing key ID, and the store generation, which covers the accepted facts and the signed revocations. Correction and forgetting proposals are also signed. After any memory change, older proposals are stale and can't be applied. Run `propose` again and review the new digest.

Back up the whole store directory, including both `signing-key` and `signing-key.pub`, and keep owner-only permissions on the copy. NockBrain refuses store files and directories that are owned by another user or carry any group or other permissions. Opening an existing Ed25519 store still requires `cryptography`; the CLI never converts keys or silently replaces them with HMAC keys. With the HMAC fallback, `signing-key.pub` holds the same shared secret as `signing-key`, so treat it as a secret too. Losing or mixing up either key file can make the store unusable, and the CLI won't replace them for you.

Commands that change the store, and the capture hook, hold an exclusive lock on it, so two writers never interleave. The recall hook and Memory Explorer only read snapshots. The other scripts in `bin/` are modules these commands load; don't run them against your store directly. The store's ignore-all `.gitignore` is a second safeguard, and the store should still live outside any repository.

## Memory Explorer flags

`bin/explore-memory.py` is the read-only viewer that `open` starts. You can also run it directly:

```sh
python3 bin/explore-memory.py --demo
python3 bin/explore-memory.py --store "$STORE"
python3 bin/explore-memory.py --store "$STORE" --verify-key /absolute/path/to/verification-file --open
```

| Flag | What it does |
|---|---|
| `--demo` | Open a fictitious demo store in a temporary directory that is removed on exit |
| `--store STORE` | Select one existing store directory |
| `--verify-key FILE` | Use this verification file instead of the store's `signing-key.pub`; only with `--store` |
| `--open` | Open the page in your default browser as well as printing its URL |

`--demo` and `--store` are mutually exclusive. With neither, the script prints usage and exits. It prints a `http://127.0.0.1:PORT/#token=...` link; the token is a per-launch capability, so don't share the link. Ctrl-C stops it. [memory-explorer.md](memory-explorer.md) covers what the page shows, its limits, and its security properties.
