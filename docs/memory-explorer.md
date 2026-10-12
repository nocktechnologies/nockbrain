# Memory Explorer

Memory Explorer is a local, read-only view of one NockBrain store. It shows facts, their lifecycle and verification state, stored evidence references, and a BM25 recall preview. It can't change anything in the store. To create a store and import reviewed notes, follow [getting-started.md](getting-started.md) or the [command reference](commands.md), then select that store here.

## Start with fictitious memories

From the repository root:

```sh
python3 bin/explore-memory.py --demo
```

The demo builds a temporary, owner-only store with a disposable verification identity. Its records describe a fictional business called Willow Workshop. It needs no existing store, Claude Code, model, credentials, or network service. Copy the printed `http://127.0.0.1:.../#token=...` link into a browser, or pass `--open`. Keep the terminal running while you browse, and press Ctrl-C to shut down and remove the demo's temporary files.

The link's fragment holds a random capability created for this launch. The page removes the fragment from the address bar and keeps the token only in the tab's memory. After a reload or in a new tab, reopen the full link printed in the terminal. Don't publish the link.

## Inspect a chosen store

```sh
python3 bin/explore-memory.py --store "$HOME/nockbrain-store"
```

`python3 bin/consumer-brain.py open --store "$HOME/nockbrain-store"` does the same and opens the browser for you. The path selects exactly one store directory when the process starts. There is no implicit home-store mode: without `--demo` or `--store`, the command prints usage and exits.

Explorer reads the store's JSON files: `facts.json`, and `insights.json` and `revocations.jsonl` when they exist, plus the verification file. It doesn't follow evidence paths or read transcripts. The service binds only to `127.0.0.1` on an available port.

Explorer looks for `signing-key.pub` in the selected store, or you can name a verification file explicitly:

```sh
python3 bin/explore-memory.py --store "$HOME/nockbrain-store" --verify-key /absolute/path/to/verification-file
```

It never reads the store's private `signing-key`. A verification path that names that file, or another link to it, is refused, and a verification file that contains a private key is never copied into the snapshot. HMAC verification files hold the same symmetric secret as the signing key, so treat a copied or supplied HMAC verification file as secret. If the verification file is missing or invalid, or the `cryptography` package needed for an Ed25519 store isn't installed, the page says so and doesn't label records verified. The page shows each record's stored confidence number as a score. It isn't a calibrated probability.

## Reading the workspace

The source strip names the selected store, its health state, whether verification is available, and the time the snapshot was captured. `Refresh snapshot` takes a new bounded copy. The visible data doesn't update on its own, and a failed refresh keeps the previous capture time. Missing, empty and unreadable stores each have their own state. Every snapshot and preview notice appears in the page.

Use search and the kind, lifecycle and collection filters to browse pages of 50 records. `Current` is the default lifecycle filter. Choose `All states` or `Superseded` to look at older decisions. Select a row to see its full stored content, dates, evidence references, verification, and any supersession links. Evidence paths and anchors are shown as text, and the viewer never opens the files they name. Stored content is treated as untrusted text.

The `BM25 preview` tab runs the same classifier and ranking as the recall hook against the displayed snapshot. The demo also includes a few sample insights, which the recall hook never returns. Semantic and graph tiers are off, the token budget defaults to 800 and accepts 1 to 1,500, and a date-diversity cap allows four items per date, deferring the overflow. Strict verification is off in the preview, and the settings line on the page says so. In the demo, try "What did we decide about Friday delivery?" The result shows whether the classifier would request recall separately from the selected matches, plus the rendered text and its approximate token cost. The preview is one selection under its displayed settings. It isn't a record of what an agent received. If a source input is unreadable, the preview is unavailable. No preview query is sent to a model or a remote service.

## Security properties

The HTTP service accepts only fixed routes and serves only the bundled offline assets. Data requests need the per-launch capability, and every request has to carry the exact local Host header and, when present, the exact local Origin. Cross-site requests are refused. Responses forbid caching and framing and carry a strict content security policy. The page doesn't keep the capability in cookies or browser storage, load external assets, or send source paths in its requests.

## Limits and scope

| Limit | Value |
|---|---|
| Records per list page | 50 by default, 100 at most |
| Preview prompt | 2,000 characters |
| Preview budget | 1 to 1,500 tokens |
| Request body | 16 KiB |
| Snapshot input file | 32 MiB |
| Snapshot inputs in total | 64 MiB |
| Preview run time | 5 seconds |

Exceeding a limit produces a visible error instead of a partial result labeled complete. If selected files change while a snapshot is being captured, Explorer retries once and then reports that it couldn't get a stable snapshot. It doesn't share a transaction with other programs writing to the store at the same moment.

The viewer makes no memory edits, approvals, supersessions or purges, and it doesn't install hooks, change schedulers, download models or change settings. To change memory, use the commands in [commands.md](commands.md).
