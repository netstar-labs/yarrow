# yarrow

A parser for the [YARA](https://virustotal.github.io/yara-x/) rule language,
written in Go, depending only on the standard library — a faithful port of the
parser from [YARA-X](https://github.com/VirusTotal/yara-x).

```
source bytes
    │
    ▼
Tokenizer ──────────► three-mode lexer (normal / hex-pattern / hex-jump)
    │
    ▼
Parser ─────────────► error-resilient PEG engine
    │                 → flat Begin/Token/End/Error event stream
    ▼
    ├──► CST ────────► lossless concrete syntax tree (every byte represented)
    │
    └──► AST ────────► semantic tree (precedence resolved, chains flattened)
```

The CST tiles the source exactly — whitespace, comments, and all — so it
round-trips and suits formatters, linters, and language servers. The AST is the
semantic view for compilers and analyzers. Both are validated byte-for-byte
against the YARA-X reference (213/213 goldens) and across a 22,756-rule corpus.

## Documentation

- **Start here** — [introduction](docs/introduction.md) · [executive summary](docs/executive-summary.md)
- **Deep dive** — [architecture](docs/architecture.md) · [the matcher](docs/matcher.md)
- **Operations** — [user guide](docs/userguide.md)
- **Examples** — [example/README.md](example/README.md)

## Quick start

```go
import "github.com/netstar-labs/yarrow"

cst, _ := yarrow.Parse(src)        // lossless concrete syntax tree
fmt.Print(cst.String())
for _, d := range cst.Errors {    // syntax diagnostics
	fmt.Println(d.Message, d.Span)
}

ast, _ := yarrow.ParseAST(src)     // semantic AST
for _, item := range ast.Items {
	if rule, ok := item.(*yarrow.Rule); ok {
		_ = rule                  // walk rule.Condition, rule.Patterns, rule.Meta
	}
}
```

Scan data against rules with the matcher ([docs/matcher.md](docs/matcher.md)):

```go
import "github.com/netstar-labs/yarrow/pkg/compile"

rs, _ := compile.Compile(rules)          // parse + compile a rule file
hits, _ := rs.Scan(data)                 // names of the rules that matched
```

Command-line: `go run ./app/yarrow -mode cst|cststream|ast rules.yar` dumps a tree;
`go run ./cmd/yarrow-scan rules.yar target` scans a file. Untrusted input is safe —
the parser is fuel-bounded, the AST builder depth-bounded, and pattern compilation
is instruction-capped.

## Layout

| Path | Purpose |
|---|---|
| `token.go` | `Span` and `Token` types. |
| `tokenizer.go` | Three-mode tokenizer (hand-written, maximal munch). |
| `tokenstream.go` | Buffered lookahead + backtracking over the tokenizer. |
| `event.go` | CST event stream; error-node merging. |
| `parser.go` | PEG combinator engine and diagnostics. |
| `grammar.go` | The YARA grammar as combinator productions. |
| `cst.go` | CST construction and reference-format rendering. |
| `ast.go` | AST node types. |
| `ast_builder.go` | CST-events → AST lowering (Pratt precedence). |
| `ast_render.go` | AST → reference ASCII-tree rendering. |
| `kinds_gen.go`, `tokens_gen.go` | Generated: syntax-kind / token tables. |
| `internal/gen/` | Build-time table extractor (not part of the library). |
| `pkg/scan/` | The matcher engine: byte-oriented Thompson NFA + Pike VM; literal/hex/regexp compilers + string modifiers. |
| `pkg/compile/` | AST → compiled RuleSet + the condition VM and the hash/math/pe/elf modules. |
| `app/yarrow/` | CLI: dump a rule's tree; the Go side of the differential harness. |
| `cmd/yarrow-scan/` | CLI: compile a rule file and scan a target, printing matches. |
| `cmd/difftest/` | Differential testing of the parser against YARA-X over a corpus. |
| `example/` | Runnable library-embed demos. |
| `testdata/parser/` | 71 `.in` inputs + 213 reference golden dumps (the test oracle). |

## Testing

```
go test ./...                              # goldens + invariants, hermetic + race-safe
YARA_CORPUS=/path/to/rules go test ./...   # also runs the corpus tests
go test -fuzz FuzzParse ./...              # fuzz the CST parser
```

`go vet` clean, `gofmt` clean, `-race` clean. See the
[user guide](docs/userguide.md) for benchmarks, differential testing, and table
regeneration.

## Provenance and license

yarrow is licensed under **Apache 2.0** — see [LICENSE](LICENSE). Its parser is a
port of the YARA-X parser (BSD-3-Clause, Copyright the YARA-X authors), and the
golden files under `testdata/parser/` are copied from YARA-X; that upstream
attribution is retained in [NOTICE](NOTICE). The pinned reference commit the
parser is validated against lives in `cmd/difftest/setup.sh`.
