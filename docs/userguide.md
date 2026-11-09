# User guide

## Library API

```go
import "github.com/netstar-labs/yarrow"
```

| Call | Returns | Use |
|---|---|---|
| `yarrow.Parse(src []byte)` | `(*CST, error)` | Lossless concrete syntax tree. |
| `yarrow.ParseAST(src []byte)` | `(*AST, error)` | Semantic abstract syntax tree. |
| `yarrow.NewParser(src []byte)` | `*Parser` | Raw event stream via `.Events()`; fuel control via `.SetFuel(n)` / `.OutOfFuel()`. |
| `yarrow.NewTokenizer(src []byte)` | `*Tokenizer` | Token-level access (`.Next()`), with the three lexer modes. |
| `yarrow.FormatEvents(events)` | `string` | Reference-format render of an event stream. |

```go
// Concrete syntax tree (lossless).
cst, _ := yarrow.Parse(src)
fmt.Print(cst.String())            // reference-format tree dump
for _, d := range cst.Errors {     // syntax diagnostics
	fmt.Println(d.Message, d.Span)
}

// Abstract syntax tree (semantic).
ast, _ := yarrow.ParseAST(src)
for _, item := range ast.Items {
	if rule, ok := item.(*yarrow.Rule); ok {
		_ = rule // walk rule.Condition, rule.Patterns, rule.Meta ...
	}
}

// Raw event stream, e.g. for a streaming formatter.
events := yarrow.NewParser(src).Events()
```

`Parse`/`ParseAST` never fail outright — the parser is error-resilient, so a
malformed rule yields a tree *and* diagnostics rather than an error return. The
`error` is reserved for hard limits (e.g. `ErrSourceTooLarge`).

### Safety on untrusted input

Input is safe to parse from any source. The parser is **fuel-bounded**
(`Parser.SetFuel`, `Parser.OutOfFuel`) and the AST builder is **depth-bounded**;
neither can be made to hang or overflow the stack on adversarial input. Validated
by ~1.9M fuzz executions with no crashers.

## Command-line tool

`app/yarrow` dumps a rule file's tree in any of the three reference formats. It is
also the Go side of the differential harness.

```
yarrow rules.yar                  # CST tree (default)
yarrow -mode cststream rules.yar  # flat Begin/Token/End event stream
yarrow -mode ast rules.yar        # semantic AST tree
cat rules.yar | yarrow -mode ast  # stdin when no file is given
yarrow -q rules.yar               # suppress the stderr diagnostic listing
```

Exit status: `0` = no syntax errors; `1` = parsed but the source had syntax errors
(tree and diagnostics still emitted); `2` = usage/IO error.

Build it: `go build -o yarrow ./app/yarrow`.

## Scanning rules against data

The matcher compiles a rule file and scans bytes against it. See
[matcher.md](matcher.md) for the architecture and the supported subset.

```go
import "github.com/netstar-labs/yarrow/pkg/compile"

rs, err := compile.Compile(ruleSource) // parse + compile; errors on a syntax
                                        // error or an unsupported construct
hits, err := rs.Scan(data)             // []string: names of the rules that matched
```

Command-line:

```
yarrow-scan rules.yar target-file   # prints each matching rule name, one per line
```

Exit status: `0` if any rule matched, `1` if none, `2` on a usage/IO/compile
error. Build it: `go build -o yarrow-scan ./cmd/yarrow-scan`.

Supported today: text/hex/regexp patterns with `nocase`/`wide`/`ascii`/`xor`/
`fullword`/`base64`; conditions over booleans, arithmetic/relational/string ops,
`$a`/`#a`/`@a`/`!a` (with `at`/`in` and count ranges), `N of (...)` /
`all|any|none of them`, `filesize`, and the `hash`/`math`/`pe`/`elf` modules.
Untrusted input is safe: pattern compilation is instruction-capped, so a
malicious `{ [0-99999999] }` or `a{0,99999999}` is refused, not unrolled.

## Output formats

Three reference formats, all byte-exact against YARA-X:

- **`.cst`** — the concrete tree: `KIND@start..end "text"`, indented by depth.
- **`.cststream`** — the flat event tape: `Begin { kind, span } / Token { … } / End`.
- **`.ast`** — the semantic tree as an ASCII tree (`├─`, `└─`).

## Testing

```
go test ./...                              # goldens + invariants, hermetic + race-safe
YARA_CORPUS=/path/to/rules go test ./...   # also runs the corpus tests
go test -bench . ./...                     # benchmarks
go test -fuzz FuzzParse ./...              # fuzz the CST parser
go test -fuzz FuzzAST ./...                # fuzz the AST builder
```

The corpus tests are gated behind `YARA_CORPUS` so the default `go test ./...`
stays hermetic and fast; CI opts in.

## Differential testing against the reference

The strongest check is to run yarrow and the real YARA-X over the *same whole
corpus* and diff their dumps, rather than relying on the fixed golden set. The Go
side is `app/yarrow` (its `-mode cst|cststream|ast` output is the dump). The
reference side is a small harness built against YARA-X at the pinned
reference commit (cmd/difftest/setup.sh) that emits the identical format. The runner walks a corpus,
feeds each file to both, and reports any byte difference. See `docs/plan/` (local)
and the `_ref/` / `_corpus/` scratch dirs (gitignored).

## Regenerating the token/kind tables

The two `*_gen.go` files are transcribed from the Rust reference by the extractor —
never edit them by hand:

```
python3 internal/gen/extract.py /path/to/yara-x .
```

If upstream changes a golden, re-copy `testdata/parser/` from the pinned reference commit and re-run the tests.

## Performance

On an Intel Xeon @ 2.10GHz: tokenizing ~200 MB/s (0 allocs/op); `ParseEvents`
~11 MB/s; `ParseCST` ~7 MB/s. Tokenizing is a few percent of total parse time, so
the parser — not the lexer — is where optimisation effort belongs. Measure first
(`go test -bench . -memprofile`); the remaining headroom is in the event slice and
the per-node backtracking bookmarks.
