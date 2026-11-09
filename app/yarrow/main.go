// Command yarrow parses a YARA rule file and dumps its syntax tree in one of the
// three reference formats. It is the primary entrypoint of the yarrow library and
// also the Go side of the differential harness (its output is diffed byte-for-byte
// against the YARA-X reference over a corpus — see docs/architecture.md).
//
//	yarrow rules.yar                 # CST tree (default)
//	yarrow -mode cststream rules.yar # flat Begin/Token/End event stream
//	yarrow -mode ast rules.yar       # semantic AST tree
//	cat rules.yar | yarrow -mode ast # stdin when no file is given
//
// Exit status: 0 = parsed with no syntax errors; 1 = parsed but the source had
// syntax errors (the tree and the diagnostics are still emitted); 2 = usage/IO
// error. A parse never fails outright — the parser is error-resilient — so mode
// output is always produced for a readable input.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/netstar-labs/yarrow"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("yarrow", flag.ContinueOnError)
	fs.SetOutput(stderr)
	mode := fs.String("mode", "cst", "output: cst (lossless tree) | cststream (event stream) | ast (semantic tree)")
	quiet := fs.Bool("q", false, "suppress the syntax-error listing on stderr")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: yarrow [-mode cst|cststream|ast] [-q] [file]   (reads stdin if no file)")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}

	src, err := readInput(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(stderr, "yarrow:", err)
		return 2
	}

	// Every mode needs the CST diagnostics for the exit status; the event stream
	// and AST are derived from the same parse so the three views never disagree.
	cst, _ := yarrow.Parse(src)
	switch *mode {
	case "cst":
		fmt.Fprint(stdout, cst.String())
	case "cststream":
		fmt.Fprint(stdout, yarrow.FormatEvents(yarrow.NewParser(src).Events()))
	case "ast":
		ast, _ := yarrow.ParseAST(src)
		fmt.Fprint(stdout, ast.String())
	default:
		fmt.Fprintf(stderr, "yarrow: unknown -mode %q (want cst|cststream|ast)\n", *mode)
		return 2
	}

	if len(cst.Errors) > 0 {
		if !*quiet {
			for _, d := range cst.Errors {
				fmt.Fprintf(stderr, "yarrow: %s at %d..%d\n", d.Message, d.Span.Start, d.Span.End)
			}
		}
		return 1
	}
	return 0
}

// readInput returns the file's bytes, or stdin when path is empty.
func readInput(path string) ([]byte, error) {
	if path == "" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}
