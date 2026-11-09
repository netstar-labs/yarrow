# The matcher

yarrow parses rules; the **matcher** runs them against data. It is built on top of
the AST as a set of sibling packages, stdlib-only: the pure engine and compiler
carry no dependencies; the format modules that eventually need them move to their
own module.

```
yarrow (AST)
    │
    ▼
pkg/compile ─────► AST patterns/modifiers + condition → a compiled RuleSet
    │                 (extracts literal atoms for the prefilter)
    ▼
pkg/scan ────────► byte-oriented NFA engine (Thompson NFA + Pike VM)   ← phase 1 ✓
    │                 + Aho-Corasick atom prefilter (narrows start positions)
    ▼
condition VM ────► evaluates each rule's boolean condition over the match results
    │                 (#a, @a, $a at/in, N of them, for..of, filesize, entrypoint)
    ▼
modules ─────────► pe / elf / hash / math field providers (sibling module once
                   they pull dependencies)
```

## Design decisions

- **Byte NFA, not `regexp`.** YARA matches raw bytes, unanchored, and reports every
  match offset — semantics the stdlib rune-oriented, leftmost-once `regexp` does not
  provide. The engine (`pkg/scan`) is a Thompson NFA over bytes with a Pike-VM
  executor. This one engine backs all three pattern kinds (literal, hex, regexp).
- **Atoms + prefilter.** A raw NFA sweep is O(len·states) per start. Real scanning
  extracts the required literal **atoms** from each pattern, runs a single
  Aho-Corasick pass to find candidate offsets, and only then verifies with the NFA.
  Phase 1 ships the NFA; the prefilter is phase 3.
- **Engine decoupled from the AST.** `pkg/scan` consumes its own `Element`
  vocabulary (`Class`, `Jump`, `Alt`), so it is tested in isolation. `pkg/compile`
  is the only package that imports both the AST and the engine.

## Phase plan

| Phase | Scope | Status |
|---|---|---|
| 1 | `pkg/scan`: byte NFA + Pike VM; literal & hex (bytes, `??`, nibble masks, jumps `[n]`/`[n-m]`/`[n-]`, alternation) | **done** |
| 2 | Regexp-syntax → NFA (classes, shorthands, quantifiers `* + ? {n,m}` greedy/lazy, alternation, groups, `i`/`s` flags). Anchors `^`/`$` done (VM position assertions); `\b`/`\B` word boundaries still deferred. | **done** |
| 3 | Performance: the Pike VM reuses buffers (per-scan allocation is O(1)) and plain literals use a bytes.Index fast path (~4 GB/s). A required-atom (Aho-Corasick) prefilter to prune start positions is a further optimization. | **partial** |
| 4 | String modifiers: `nocase`, `wide`, `ascii`, `fullword`, `xor(a-b)`, `base64`/`base64wide` (3-alignment, custom alphabet) — **done**. xor+nocase combos + exact base64 char-count parity are differential refinements. | **done** |
| 5 | `pkg/compile`: AST → `RuleSet` (decoded pattern bytes → scan matchers, modifiers wired) | **done** |
| 6 | Condition VM: booleans, arithmetic/relational, string ops, `#a` `@a` `!a`, `$a at/in`, count ranges, `N of (...)`/`all\|any\|none of them`, `filesize`, global suppression, private-rule hiding. `matches` done; `for` loops + `entrypoint` deferred. | **done** |
| 6.1 | CLI `cmd/yarrow-scan` — compile a rule file, scan a target, print matches | **done** |
| 7 | Modules: `hash` (md5/sha1/sha256/crc32/checksum32), `math` (entropy/mean/min/max/in_range), `pe` + `elf` (scalar fields, sections array, common constants) via stdlib crypto/debug — **done, MVP surface**. Full field/constant coverage + `for` loops are differential-validated follow-ups. | **done** |

## Verifying the matcher

The same differential methodology the parser uses applies to the scanner: build a
reference harness against YARA-X at the pinned reference commit (cmd/difftest/setup.sh) that scans a
corpus of samples with a corpus of rules and emits `(rule, offset, length)`
matches, then diff yarrow's matches against it. Match semantics (overlap, reported
offsets, private-rule suppression) are subtle and are pinned by this diff rather
than by reading the spec — exactly as the meta-string escape divergence was caught
for the parser.
