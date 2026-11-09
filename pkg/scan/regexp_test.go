package scan

import (
	"sort"
	"testing"
)

func mustRe(t *testing.T, body string, nocase, dotAll bool) program {
	t.Helper()
	p, err := Regexp(body, nocase, dotAll)
	if err != nil {
		t.Fatalf("Regexp(%q): %v", body, err)
	}
	return p
}

// endsFromZero returns the sorted distinct end offsets of matches that start at 0.
func endsFromZero(p program, input string) []int {
	seen := map[int]bool{}
	for _, m := range p.FindAll([]byte(input)) {
		if m.Start == 0 {
			seen[m.End] = true
		}
	}
	out := make([]int, 0, len(seen))
	for e := range seen {
		out = append(out, e)
	}
	sort.Ints(out)
	return out
}

func TestRegexpLiteral(t *testing.T) {
	p := mustRe(t, "abc", false, false)
	if !p.Match([]byte("xxabcyy")) || p.Match([]byte("abx")) {
		t.Error("literal regexp match wrong")
	}
}

func TestRegexpDot(t *testing.T) {
	p := mustRe(t, "a.c", false, false)
	if !p.Match([]byte("axc")) || !p.Match([]byte("a c")) {
		t.Error(". should match any non-newline")
	}
	if p.Match([]byte("a\nc")) {
		t.Error(". must not match newline without dotAll")
	}
	if !mustRe(t, "a.c", false, true).Match([]byte("a\nc")) {
		t.Error("dotAll: . must match newline")
	}
}

func TestRegexpClass(t *testing.T) {
	p := mustRe(t, "[a-cx]", false, false)
	for _, s := range []string{"a", "b", "c", "x"} {
		if !p.Match([]byte(s)) {
			t.Errorf("class must match %q", s)
		}
	}
	if p.Match([]byte("d")) {
		t.Error("class must not match d")
	}
	neg := mustRe(t, "[^0-9]", false, false)
	if neg.Match([]byte("5")) || !neg.Match([]byte("a")) {
		t.Error("negated class wrong")
	}
}

func TestRegexpShorthands(t *testing.T) {
	if !mustRe(t, `\d\w\s`, false, false).Match([]byte("5a ")) {
		t.Error(`\d\w\s should match "5a "`)
	}
	if mustRe(t, `\d`, false, false).Match([]byte("a")) {
		t.Error(`\d must not match a letter`)
	}
	if !mustRe(t, `\D`, false, false).Match([]byte("a")) {
		t.Error(`\D must match a non-digit`)
	}
}

func TestRegexpQuantifiers(t *testing.T) {
	if got := endsFromZero(mustRe(t, "a*", false, false), "aaab"); !eqInts(got, []int{0, 1, 2, 3}) {
		t.Errorf("a* ends = %v, want [0 1 2 3]", got)
	}
	if got := endsFromZero(mustRe(t, "a+", false, false), "aaab"); !eqInts(got, []int{1, 2, 3}) {
		t.Errorf("a+ ends = %v, want [1 2 3]", got)
	}
	if got := endsFromZero(mustRe(t, "a?", false, false), "aaab"); !eqInts(got, []int{0, 1}) {
		t.Errorf("a? ends = %v, want [0 1]", got)
	}
	if got := endsFromZero(mustRe(t, "a{2,3}", false, false), "aaaa"); !eqInts(got, []int{2, 3}) {
		t.Errorf("a{2,3} ends = %v, want [2 3]", got)
	}
	if got := endsFromZero(mustRe(t, "a{2}", false, false), "aaaa"); !eqInts(got, []int{2}) {
		t.Errorf("a{2} ends = %v, want [2]", got)
	}
	if got := endsFromZero(mustRe(t, "a{2,}", false, false), "aaaa"); !eqInts(got, []int{2, 3, 4}) {
		t.Errorf("a{2,} ends = %v, want [2 3 4]", got)
	}
}

func TestRegexpAlternationAndGroups(t *testing.T) {
	p := mustRe(t, "abc|def", false, false)
	if !p.Match([]byte("def")) || !p.Match([]byte("abc")) || p.Match([]byte("abf")) {
		t.Error("alternation wrong")
	}
	g := mustRe(t, "(ab)+c", false, false)
	if !g.Match([]byte("ababc")) || g.Match([]byte("abac")) {
		t.Error("repeated group wrong")
	}
	nc := mustRe(t, "(?:x|y)z", false, false)
	if !nc.Match([]byte("yz")) {
		t.Error("non-capturing group wrong")
	}
}

func TestRegexpEscapesAndHex(t *testing.T) {
	if !mustRe(t, `a\.c`, false, false).Match([]byte("a.c")) || mustRe(t, `a\.c`, false, false).Match([]byte("axc")) {
		t.Error(`\. should be a literal dot`)
	}
	if !mustRe(t, `\x41\x42`, false, false).Match([]byte("AB")) {
		t.Error(`\x41\x42 should match AB`)
	}
}

func TestRegexpCaseInsensitive(t *testing.T) {
	p := mustRe(t, "abc", true, false)
	for _, s := range []string{"abc", "ABC", "AbC"} {
		if !p.Match([]byte(s)) {
			t.Errorf("nocase regexp must match %q", s)
		}
	}
	cls := mustRe(t, "[a-c]+", true, false)
	if !cls.Match([]byte("ABC")) {
		t.Error("nocase class must match uppercase")
	}
}

func TestRegexpAnchors(t *testing.T) {
	// ^abc matches only at the start of the data.
	start := mustRe(t, "^abc", false, false)
	if !start.Match([]byte("abcdef")) {
		t.Error("^abc must match at start")
	}
	if start.Match([]byte("xabc")) {
		t.Error("^abc must not match mid-data")
	}
	// abc$ matches only at the end.
	end := mustRe(t, "abc$", false, false)
	if !end.Match([]byte("xxabc")) {
		t.Error("abc$ must match at end")
	}
	if end.Match([]byte("abcx")) {
		t.Error("abc$ must not match before the end")
	}
	// ^abc$ is a whole-input match.
	whole := mustRe(t, "^abc$", false, false)
	if !whole.Match([]byte("abc")) || whole.Match([]byte("abcd")) || whole.Match([]byte("xabc")) {
		t.Error("^abc$ must match exactly the whole input")
	}
}

func TestRegexpUnsupported(t *testing.T) {
	// Word boundaries still need VM support.
	for _, body := range []string{`\babc`, `abc\B`} {
		if _, err := Regexp(body, false, false); err == nil {
			t.Errorf("expected an error for unsupported %q", body)
		}
	}
}

func eqInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestRegexpSizeCapRefusesBomb(t *testing.T) {
	// A huge bounded repeat must be refused, not unrolled into an OOM.
	if _, err := Regexp("a{0,50000000}", false, false); err == nil {
		t.Error("expected ErrProgramTooLarge for a{0,50000000}")
	}
	// A huge mandatory count too.
	if _, err := Regexp("a{99999999}", false, false); err == nil {
		t.Error("expected ErrProgramTooLarge for a{99999999}")
	}
	// A reasonable bound still compiles.
	if _, err := Regexp("a{0,1000}", false, false); err != nil {
		t.Errorf("a{0,1000} should compile: %v", err)
	}
}

func TestRegexpParseIntNoOverflow(t *testing.T) {
	// A repetition count that would overflow int must be refused (via the cap),
	// never wrap to a negative that reads as an unbounded loop.
	if _, err := Regexp("a{10000000000000000000}", false, false); err == nil {
		t.Error("an overflowing repetition count must be refused")
	}
}
