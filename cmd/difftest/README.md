# difftest — differential testing against YARA-X

Runs yarrow and the real YARA-X parser over the same corpus and diffs their CST /
CST-event-stream / AST dumps byte-for-byte, catching any construct the fixed
golden set does not exercise.

```
bash cmd/difftest/setup.sh     # clone+build YARA-X @ the pinned commit; clone the corpus
go run ./cmd/difftest -corpus _corpus -ref _ref/yara-x/target/release/examples/dump
```

- `reference/dump.rs` — the reference harness (a cargo example against
  `yara-x-parser`); `setup.sh` drops it into the pinned YARA-X checkout and builds it.
- `main.go` — the runner: yarrow is called in-process, the reference via exec; exit
  status is 1 on any divergence.

Scratch (`_ref/`, `_corpus/`) is gitignored — reproducible from `setup.sh`.
