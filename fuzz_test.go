package yarrow

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzParse checks that no input can break the parser.
//
// A rule parser in a threat-intelligence pipeline ingests files from
// wherever the rules came from, so "malformed input is the caller's problem"
// is not an acceptable stance. The properties asserted here are:
//
//   - No panic. Slice indexing in the tokenizer is the obvious risk.
//   - Termination. The fuzzer's own timeout catches runaway backtracking;
//     the fuel budget is what should prevent it.
//   - The invariants from checkInvariants still hold, in particular that the
//     token spans tile the input exactly. This is the property that would
//     silently break if the tokenizer ever failed to advance or skipped a
//     byte, and it is invisible to a crash-only fuzz target.
//   - Determinism. Parsing twice gives the same tree.
func FuzzParse(f *testing.F) {
	seeds, _ := filepath.Glob("testdata/parser/*.in")
	for _, p := range seeds {
		if b, err := os.ReadFile(p); err == nil {
			f.Add(b)
		}
	}
	// A few shapes the corpus does not cover: unterminated delimiters,
	// mode-switch boundaries, and non-UTF-8 bytes.
	f.Add([]byte(`rule a { strings: $x = { 00 [1-] (11|22) } condition: $x }`))
	f.Add([]byte(`rule a { condition: /* unclosed`))
	f.Add([]byte(`rule a { strings: $x = "unclosed`))
	f.Add([]byte(`rule a { condition: /unclosed`))
	f.Add([]byte("rule \xff\xfe { condition: true }"))
	f.Add([]byte(`rule a { condition: for all i in (0..1) : ( true ) }`))

	f.Fuzz(func(t *testing.T, src []byte) {
		if len(src) > MaxSpan {
			t.Skip()
		}
		events := NewParser(src).Events()
		if err := checkInvariants(src, events); err != nil {
			t.Fatalf("invariant violated: %v", err)
		}
		// The tree must be rebuildable and reproducible.
		again := NewParser(src).Events()
		if len(again) != len(events) {
			t.Fatalf("non-deterministic: %d events then %d", len(events), len(again))
		}
		for i := range events {
			if events[i] != again[i] {
				t.Fatalf("non-deterministic at event %d", i)
			}
		}
		cst := BuildCST(events, src)
		if cst.Root == nil {
			t.Fatal("nil root")
		}
		_ = cst.String()
	})
}

// FuzzAST checks that lowering never panics and is deterministic on arbitrary
// input. The CST parser is already fuzzed; this extends the guarantee through
// the AST builder and renderer, which is where the untrusted-input surface
// now ends.
func FuzzAST(f *testing.F) {
	seeds, _ := filepath.Glob("testdata/parser/*.in")
	for _, p := range seeds {
		if b, err := os.ReadFile(p); err == nil {
			f.Add(b)
		}
	}
	f.Fuzz(func(t *testing.T, src []byte) {
		if len(src) > MaxSpan {
			t.Skip()
		}
		ast, err := ParseAST(src)
		if err != nil {
			return
		}
		s1 := ast.String()
		ast2, _ := ParseAST(src)
		if s1 != ast2.String() {
			t.Fatal("AST rendering is non-deterministic")
		}
	})
}
