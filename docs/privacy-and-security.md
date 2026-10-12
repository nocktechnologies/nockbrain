# Privacy and security

I don't want my notes leaving my machine, so NockBrain doesn't send them anywhere, and it makes you approve every word before it keeps any of it. This page says exactly what it reads, what it refuses, what it writes, what leaves your machine, and what it doesn't protect you from.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="diagrams/privacy-boundary-dark.svg">
  <img alt="Privacy boundary: on your machine, NockBrain reads only files you name and, if you opt in, the transcript Claude Code names inside an allowed folder; it always refuses SSH and GPG folders, env files, private keys, credentials files and paths containing secret or token. Commands, Memory Explorer and the session hook run locally and keep everything in your owner-only store folder and short-lived private temporary copies. Outside your machine, NockBrain sends nothing; Claude Code's normal conversation with Claude includes facts the hook adds." src="diagrams/privacy-boundary.svg">
</picture>

## What leaves your machine

Nothing from NockBrain. There are no network calls, no model calls, no telemetry and no downloads anywhere in `bin/`. The only network listener it starts is Memory Explorer, on 127.0.0.1. The MCP server talks to your agent over standard input and output and opens no port.

Claude Code still talks to Claude the way it always does. When the recall hook adds facts to a prompt, those facts travel with that conversation. Keep that in mind before you apply anything you wouldn't put in a prompt yourself.

## What it reads

`propose` reads the exact files you pass with `--source` and nothing else. It doesn't scan folders or go looking for your notes. The Stop hook reads one file: the transcript Claude Code names each time Claude finishes a reply, and only when that file sits inside a folder you allowed with `--transcript-root`. It doesn't import older conversations or scan the folder.

Some paths are always refused, even when you name them: anything inside `.ssh` or `.gnupg`, `.env` files, `*.pem` and `id_rsa` keys, `credentials` files, any path with "secret" or "token" in it, and NockBrain's own `signing-key` files. The rules are in `bin/_consumer_import.py:101` and `bin/ingest-jsonl.py:46`.

## What it writes

Everything goes in the store folder you chose. `init` creates it with access for your user only, and files inside it are written owner-only. The folder holds:

| File | What it is |
|---|---|
| `facts.json` | Your signed facts |
| `revocations.jsonl` | The signed, chained log of corrections and forgets |
| `proposals/` | Pending proposals waiting for review |
| `customer.json` | The store's ID, algorithm and key ID |
| `signing-key`, `signing-key.pub` | The store's key pair |
| `claude-settings.json` | The hook settings from `setup-hooks` |
| `.gitignore` | Ignores everything, in case the folder lands in a repository |
| `.customer.lock` | The lock that keeps two commands from writing at once |

The recall hook and Memory Explorer work on private temporary copies of the store's public files and delete them when they finish. Nothing is written to your Claude Code settings, your home folder or anywhere else.

## Redaction and review

Text that matches common secret and token shapes is redacted before it reaches the review queue (`bin/_scrub.py:98`). Pattern matching misses things. Review is the real control: read every candidate before you apply it, and treat a redaction count above zero as a reason to look closer.

## How the store protects itself

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="diagrams/store-integrity-dark.svg">
  <img alt="Store integrity: init makes one key per store, Ed25519 when the cryptography package is installed and HMAC-SHA256 otherwise. Apply checks the proposal is not stale, derives each fact ID from the store ID, kind and text, and signs each new fact once. Correct and forget write a signed journal first, append a numbered revocation that carries the hash of the line before it, then rewrite facts.json; an interruption requires recovery. Every open and every recall checks every signature, the revocation chain and the history, and any failure makes commands refuse and recall add nothing." src="diagrams/store-integrity.svg">
</picture>

Each store gets its own key when you run `init`. With the `cryptography` package installed that's an Ed25519 key pair, and only `signing-key` is secret. Without it NockBrain falls back to HMAC-SHA256 using the standard library, and the same secret sits in both files, so both stay private. An existing Ed25519 store still needs `cryptography` to open; NockBrain never converts keys or quietly swaps in a new one.

A fact's signed content never changes after you apply it. Corrections and forgets are recorded as signed revocations, numbered, with each line carrying the hash of the line before it. Every command that opens the store, and every recall, checks every signature, the whole chain, and that nothing revoked has come back. A failed check stops commands and makes recall add nothing.

Changes write a signed journal before they touch your facts. If a change is interrupted, the store refuses everything except `recover`, which checks the journal's signature and finishes the same change. Recovery is built for a process that's killed partway through a change. This release makes no claim about a power cut during a write.

## Memory Explorer

Explorer binds to 127.0.0.1 on a random port and prints a link with a token in the URL fragment that's new each time Explorer starts. The page removes the token from the address bar and keeps it only in that tab's memory. Every data request needs it, and the server checks the exact Host and Origin headers. The page loads no outside assets, sets a strict content security policy, and never reads the private `signing-key`. It can't edit anything. The details are in `bin/explore-memory.py` and [Memory Explorer](memory-explorer.md).

## What NockBrain doesn't protect you from

Other programs running as your user can read your store, the same way they can read the rest of your files. NockBrain isn't a sandbox for Claude Code either: your other hooks, plugins and settings still apply, and anything they add to a session is outside NockBrain's control.

If a secret gets past redaction and you apply it, it's in the store until you forget it. Forgetting removes that exact record, and applying the same text again skips it. Paraphrases in other records, your original notes, your backups and any copy you made are outside its reach.

Back up the whole store folder with owner-only permissions and both key files. Losing a key can leave the store unreadable.

Found a security problem? Report it privately as described in [SECURITY.md](../SECURITY.md).
