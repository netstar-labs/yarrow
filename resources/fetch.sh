#!/usr/bin/env bash
# Aggregate the public YARA rule sources listed in resources/sources.json into
# resources/corpus/<name>/ (gitignored — rule bodies are fetched, never vendored).
# Idempotent: re-run to update. Then build the index with `go run ./cmd/yindex`.
#
#   bash resources/fetch.sh
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
mkdir -p resources/corpus

# Emit "name<TAB>repo" per source.
python3 - "$root/resources/sources.json" <<'PY' |
import json, sys
with open(sys.argv[1]) as f:
    for s in json.load(f)["sources"]:
        print(f"{s['name']}\t{s['repo']}")
PY
while IFS=$'\t' read -r name repo; do
    dir="resources/corpus/$name"
    if [ -d "$dir/.git" ]; then
        echo "== $name: updating =="
        git -C "$dir" pull --quiet --ff-only || echo "  (pull skipped)"
    else
        echo "== $name: cloning $repo =="
        git clone --depth 1 --quiet "$repo" "$dir" || echo "  (clone failed — skipping $name)"
    fi
done

n=$(find resources/corpus -type f \( -name '*.yar' -o -name '*.yara' \) 2>/dev/null | wc -l | tr -d ' ')
echo "corpus: ${n} .yar/.yara files under resources/corpus/"
