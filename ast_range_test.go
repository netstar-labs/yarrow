package yarrow

import (
	"strings"
	"testing"
)

// These pin the four byte-exactness divergences the parser-core audit found
// (edge cases the golden set and the 3k-file corpus never exercised), each
// confirmed byte-for-byte against YARA-X via the differential harness.

func firstErr(t *testing.T, src string) (Diagnostic, int) {
	t.Helper()
	ast, err := ParseAST([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(ast.Errors) == 0 {
		return Diagnostic{}, len(ast.Items)
	}
	return ast.Errors[0], len(ast.Items)
}

func TestXorBoundsAreU8(t *testing.T) {
	for _, src := range []string{
		`rule r { strings: $a = "x" xor(256) condition: $a }`,
		`rule r { strings: $a = "x" xor(0-300) condition: $a }`,
		`rule r { strings: $a = "x" xor(1KB) condition: $a }`, // 1024 > 255
	} {
		d, items := firstErr(t, src)
		if d.Kind != DiagInvalidInteger || !strings.Contains(d.Message, "[0, 255]") {
			t.Errorf("%s: want InvalidInteger [0, 255], got kind=%d %q", src, d.Kind, d.Message)
		}
		if items != 0 {
			t.Errorf("%s: rule must be dropped, got %d items", src, items)
		}
	}
	// A valid xor range still parses with the right bounds.
	ast, _ := ParseAST([]byte(`rule r { strings: $a = "x" xor(10-200) condition: $a }`))
	if len(ast.Errors) != 0 || len(ast.Items) != 1 {
		t.Fatalf("valid xor(10-200) must parse cleanly: errs=%d items=%d", len(ast.Errors), len(ast.Items))
	}
}

func TestHexJumpBoundsAreU32(t *testing.T) {
	d, items := firstErr(t, `rule r { strings: $a = { 11 [4294967296] 22 } condition: $a }`)
	if d.Kind != DiagInvalidInteger || !strings.Contains(d.Message, "[0, 4294967295]") {
		t.Errorf("hex jump 2^32: want InvalidInteger [0, 4294967295], got kind=%d %q", d.Kind, d.Message)
	}
	if items != 0 {
		t.Errorf("out-of-range jump must drop the rule, got %d items", items)
	}
	// A normal jump still parses.
	if ast, _ := ParseAST([]byte(`rule r { strings: $a = { 11 [2-6] 22 } condition: $a }`)); len(ast.Errors) != 0 {
		t.Error("valid hex jump [2-6] must parse cleanly")
	}
}

func TestI64IntegerOverflowIsInvalidInteger(t *testing.T) {
	// A meta/expression integer that overflows i64 renders InvalidInteger (was
	// SyntaxError before the audit fix).
	d, _ := firstErr(t, `rule r { condition: 99999999999999999999999999 }`)
	if d.Kind != DiagInvalidInteger {
		t.Errorf("i64 overflow must be InvalidInteger, got kind=%d %q", d.Kind, d.Message)
	}
}

func nested(name string, n int) string {
	return "rule " + name + " { condition: " + strings.Repeat("(", n) + " true " + strings.Repeat(")", n) + " }"
}

func TestASTDepthCapMatchesReference(t *testing.T) {
	// Under the 3000 cap: parses. Over it: the rule is dropped (maxASTDepth).
	if ast, _ := ParseAST([]byte(nested("r", 1000))); len(ast.Items) != 1 {
		t.Error("nesting under the cap must parse")
	}
	if ast, _ := ParseAST([]byte(nested("r", 2000))); len(ast.Items) != 0 {
		t.Error("nesting over the 3000 depth cap must drop the rule")
	}
}

func TestDepthResetOnRecovery(t *testing.T) {
	// A rule that aborts while deeply nested must not leak its depth into the
	// next rule (which would wrongly drop it).
	src := nested("a", 2000) + "\nrule b { condition: true }\n"
	ast, _ := ParseAST([]byte(src))
	var haveB bool
	for _, it := range ast.Items {
		if r, ok := it.(*Rule); ok && r.Identifier.Name == "b" {
			haveB = true
		}
	}
	if !haveB {
		t.Error("rule b must survive after a deep-aborting rule a (depth must reset on recovery)")
	}
}
