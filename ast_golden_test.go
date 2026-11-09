package yarrow

import "testing"

// TestGoldenAST compares the rendered AST against the reference output
// byte-for-byte, the same way the CST goldens are checked. It exercises the
// full lowering: precedence resolution, associative flattening, and every
// node's exact rendered form.
func TestGoldenAST(t *testing.T) {
	for _, name := range goldenCases(t) {
		t.Run(name, func(t *testing.T) {
			src := read(t, "testdata/parser/"+name+".in")
			want := read(t, "testdata/parser/"+name+".ast")
			ast, err := ParseAST([]byte(src))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if got := ast.String(); got != want {
				t.Errorf("AST mismatch\n%s", firstDiff(want, got))
			}
		})
	}
}
