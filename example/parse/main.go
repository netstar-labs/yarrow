// Command parse is a minimal library-embed demo: it parses a hard-coded rule and
// shows the three views yarrow offers — the lossless CST, the flat event stream,
// and the semantic AST — plus how to read syntax diagnostics.
//
//	go run ./example/parse
package main

import (
	"fmt"

	"github.com/netstar-labs/yarrow"
)

const rule = `rule demo : tag1 {
	meta:
		author = "example"
	strings:
		$a = "malware"
		$b = { 6A 40 68 ?? ?? 00 }
	condition:
		$a and #b > 3
}`

func main() {
	src := []byte(rule)

	// 1. Concrete syntax tree — lossless, every byte represented. Ideal for
	//    formatters, linters, and language servers.
	cst, _ := yarrow.Parse(src)
	fmt.Println("== CST ==")
	fmt.Print(cst.String())
	for _, d := range cst.Errors {
		fmt.Printf("syntax error: %s at %d..%d\n", d.Message, d.Span.Start, d.Span.End)
	}

	// 2. Semantic AST — precedence resolved, chains flattened, trivia dropped.
	ast, _ := yarrow.ParseAST(src)
	fmt.Println("\n== AST ==")
	fmt.Print(ast.String())

	// 3. Raw event stream — the flat Begin/Token/End tape both trees are built
	//    from, e.g. for a streaming formatter.
	fmt.Println("\n== first 8 events ==")
	for i, ev := range yarrow.NewParser(src).Events() {
		if i == 8 {
			break
		}
		fmt.Printf("  %+v\n", ev)
	}
}
