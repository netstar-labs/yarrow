# Executive summary

**What it is.** yarrow is a Go library that parses the YARA rule language into a
syntax tree. It is a port of the parser from YARA-X (VirusTotal's Rust rewrite of
YARA), reproducing that parser's behaviour exactly, and it depends only on the Go
standard library.

**Why it exists.** Threat-intelligence tooling in this stack is Go. Working with
YARA rules — formatting them, linting them, indexing them, analysing them,
eventually compiling and matching them — needs a parser that is *ours*: embeddable
without a cgo boundary to the C YARA engine or an FFI hop to Rust, auditable, and
safe on hostile input. Rules arrive from many upstreams and are, in effect,
attacker-adjacent data; the parser is a boundary that must not be a liability.

**What it delivers.**

- **Fidelity.** Byte-for-byte agreement with the YARA-X reference: 213/213 golden
  comparisons (concrete tree, event stream, and semantic tree) pass exactly.
- **Two tree layers.** A lossless concrete syntax tree (CST) suitable for
  formatters, linters, and language servers; and a semantic abstract syntax tree
  (AST) — precedence resolved, chains flattened — suitable for compilers and
  analyzers.
- **Robustness at scale.** Across a 2,532-file / 22,756-rule real-world corpus
  every rule parses and lowers with zero drops and zero panics, structural
  invariants intact. Over ~1.9M fuzz executions produced no crashers and no
  invariant violations.
- **Safety on untrusted input.** The parser is fuel-bounded and the AST builder is
  depth-bounded; neither can be driven to hang or to overflow the stack.
- **Zero dependencies.** Standard library only — nothing to audit downstream but
  the code itself.

**Scanning.** On top of the parser, yarrow compiles rules and scans data against
them (`pkg/compile` + `pkg/scan`): a byte-oriented Thompson NFA backs literal, hex,
and regexp patterns with the string modifiers (nocase/wide/xor/base64/fullword),
and a condition VM evaluates the full boolean/count/offset/`of` grammar plus the
`hash`/`math`/`pe`/`elf` modules. It is a faithful MVP; remaining parity work
(a required-atom prefilter, `for` loops, exhaustive module fields) is tracked in
[matcher.md](matcher.md).

**Status.** Parser complete and byte-exact against YARA-X across a 22,756-rule
corpus (differential-tested). Scanner MVP complete, fuzzed, and benchmarked. Both
are stdlib-only and safe on untrusted input.
