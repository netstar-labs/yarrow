# resources — public YARA rule index

An aggregated, **yarrow-parsed** index of the major public YARA rule collections.
Building the index runs yarrow's parser over the entire public corpus, so it also
serves as a real-world parser-health check.

## What is tracked here vs. fetched

Public YARA rules carry **mixed and sometimes restrictive licenses** (e.g.
signature-base is Nextron's non-commercial Detection Rules License; Elastic rules
are Elastic License 2.0). This repo therefore **does not vendor the rule bodies**.
It tracks only:

| File | Contents |
|---|---|
| [`sources.json`](sources.json) | The manifest: each public source's repo, subtree, license, and description. |
| [`fetch.sh`](fetch.sh) | Clones every source into `resources/corpus/<name>/` (gitignored). |
| `index.jsonl` | One JSON object **per rule** — derived metadata only (name, tags, imports, string count, private/global). Generated. |
| `index.summary.json` | Aggregate stats: per-source counts, parse-success rate, import usage, top tags. Generated. |

The rule **bodies / detection logic are not stored** — they live in the
gitignored `resources/corpus/` after a fetch, reproducible from `sources.json`.
The index is derived, factual metadata (a catalogue), not the rules themselves.

## Build / refresh the index

```
bash resources/fetch.sh      # clone/update all sources into resources/corpus/
go run ./cmd/yindex          # parse every rule with yarrow → index.jsonl + summary
```

Both are idempotent. `cmd/yindex` uses `yarrow.ParseAST` on each file, so the run
reports how much of the public corpus parses cleanly.

## Query the index

`index.jsonl` is newline-delimited JSON — one rule per line — so it greps and
`jq`s directly:

```bash
# every rule that imports the pe module
jq 'select(.imports[]? == "pe") | .rule' resources/index.jsonl

# rules tagged APT, by source
jq -r 'select(.tags[]? == "APT") | [.source, .rule] | @tsv' resources/index.jsonl

# rule count per source
jq -r .source resources/index.jsonl | sort | uniq -c | sort -rn
```

## Index schema (`index.jsonl`)

```json
{"source":"signature-base","file":"yara/apt_x.yar","rule":"APT_X",
 "tags":["apt"],"imports":["pe"],"strings":12,"private":false,"global":false}
```

## Vendoring a permissive subset

If you want actual rule files committed (e.g. for offline tests), vendor only the
permissively-licensed sources (MIT/BSD/Apache per `sources.json`) into a tracked
subdirectory and keep the non-commercial ones fetch-only. Check each source's
license first — this is a licensing decision, not a mechanical one.
