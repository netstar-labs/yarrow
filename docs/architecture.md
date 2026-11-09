# Architecture

yarrow reproduces the YARA-X parser architecture: a three-mode tokenizer feeds an
error-resilient PEG engine that emits a flat event stream, from which two trees are
built — a lossless CST and a semantic AST.

```
source bytes
    │
    ▼
Tokenizer ──────────► three-mode lexer (normal / hex-pattern / hex-jump),
    │                 hand-written, maximal munch, 0 allocs
    ▼
TokenStream ────────► buffered lookahead + backtracking bookmarks
    │
    ▼
Parser ─────────────► error-resilient PEG combinator engine; fuel-bounded.
    │                 Emits a flat tape of Begin / Token / End / Error events
    ▼
    ├──► CST ────────► lossless concrete syntax tree — every byte represented
    │                  (whitespace, comments, all) → round-trips to source
    │
    └──► AST ────────► semantic tree: Pratt precedence resolution, n-ary
                       flattening of associative operators, trivia dropped
```

## Subsystems

| File | Subsystem |
|---|---|
| `token.go` | `Span` and `Token` value types. |
| `tokenizer.go` | The three-mode tokenizer. YARA's grammar is not regular: hex patterns (`{ 6A ?? }`) and hex jumps (`[4-6]`) need their own lexer modes, switched by the parser. Maximal-munch, hand-written, zero-allocation. |
| `tokenstream.go` | Buffered lookahead over the tokenizer with backtracking bookmarks — the parser speculates and rewinds. |
| `event.go` | The CST event model (`Begin`/`Token`/`End`/`Error`) and error-node merging. |
| `parser.go` | The PEG combinator engine, diagnostics, and the fuel budget. |
| `grammar.go` | The YARA grammar expressed as combinator productions. |
| `cst.go` | CST construction from the event stream and reference-format tree rendering. |
| `ast.go` | AST node types (rules, patterns, expressions, meta). |
| `ast_builder.go` | CST-events → AST lowering: a Pratt parser resolves operator precedence and associativity; associative operators flatten to n-ary nodes. |
| `ast_render.go` | AST → reference ASCII-tree rendering. |
| `kinds_gen.go`, `tokens_gen.go` | Generated tables: 127 syntax kinds, 82 tokens, and their 85 cross-mappings. |
| `internal/gen/extract.py` | Build-time extractor that transcribes those tables from the Rust reference. Not part of the library. |

## Key design decisions

**Lossless first, semantic second.** The CST is the ground truth — its tokens tile
the source with no gaps or overlaps, so it round-trips exactly. The AST is a
*projection* of the CST that discards trivia and resolves precedence. Keeping both
means one parser serves both a formatter (needs every byte) and a compiler (wants
the clean tree).

**One flat event tape, two trees.** The parser does not build a tree directly; it
emits a linear stream of `Begin{kind,span}` / `Token{kind,span}` / `End` / `Error`
events. `BuildCST` and `BuildAST` each consume that same tape. A streaming
consumer (e.g. an incremental formatter) can read the events without materialising
either tree.

**Error resilience, not error abort.** A syntax error produces an `Error` event and
a diagnostic, and parsing continues — so a broken rule in a 500-rule file does not
blind the parser to the other 499. Diagnostics carry a message and a source span.

**Bounded on hostile input.** Rules come from many upstreams and are effectively
attacker-adjacent. The parser carries a *fuel* budget (`SetFuel`/`OutOfFuel`) that
caps total work, and the AST builder is depth-bounded, so no input — however
adversarial or deeply nested — can hang the parser or overflow the stack. This is
validated by ~1.9M fuzz executions with no crashers.

**Generated tables, transcribed not hand-copied.** The 127 syntax kinds, 82 tokens,
and their 85 cross-mappings are load-bearing and not always obvious — e.g.
`SyntaxKind DIV` maps to `TokenID BACKSLASH`, because YARA spells integer division
`\`. `internal/gen/extract.py` transcribes them mechanically from the Rust source
so a regeneration cannot drift by a typo.

## Fidelity notes

The port is byte-exact against the reference, including deliberate reproductions of
reference quirks:

- **Upstream typo preserved.** `TokenID STARTSWITH_KW`'s description is
  `` "`startswith" `` — missing its closing backtick — in the reference, reproduced
  verbatim so the goldens match. Worth filing upstream; when fixed there, update the
  generated table and the affected golden.
- **Tokenizer mode switches do not flush lookahead**, matching a genuine quirk of
  the reference. Changing this would break parity on hex patterns.
- **Non-UTF-8 handling** in the tokenizer's `unexpected` path was inferred from the
  reference's `logos` error semantics, which are underspecified in the source. It
  passes all goldens and ~1.1M fuzz executions but is the part most worth a second
  look if a divergence ever surfaces — which is exactly what the planned
  differential testing against the reference binary is meant to flush out.

## Validation strategy

1. **Golden comparison** (hermetic, default): 213 exact comparisons — CST tree,
   CST event stream, AST tree — against the YARA-X reference outputs, pinned to a
   reference commit (pinned in cmd/difftest/setup.sh).
2. **Structural invariants**: on the goldens and across the corpus — spans tile the
   source, `Begin`/`End` balance, no span runs backwards or past the end.
3. **Corpus** (opt-in via `YARA_CORPUS`): 2,532 files / 22,756 rules parse and
   lower with zero drops or panics.
4. **Fuzzing**: native Go fuzzers on both the CST and AST entry points.
5. **Differential testing** (next): run this parser and the real YARA-X over the
   same whole corpus and diff the CST/AST dumps programmatically, to catch any
   construct the fixed golden set does not exercise. See the user guide.

## Beyond the parser

- **Matching / scanning** — built, in `pkg/scan` (a byte-oriented Thompson NFA +
  Pike VM behind the literal/hex/regexp compilers and the string modifiers) and
  `pkg/compile` (AST → RuleSet, the condition VM, and the hash/math/pe/elf
  modules). See [matcher.md](matcher.md). A required-atom prefilter and exhaustive
  module coverage are the remaining parity work.
- **Compilation / semantic analysis** — type checking and symbol resolution beyond
  what the condition VM does are not yet present; they build on the AST.
- **String-escape decoding** — `yarrow.DecodeStringLiteral` returns a literal's raw
  decoded bytes (used by the matcher); the AST still keeps the raw literal for the
  tree dump.
