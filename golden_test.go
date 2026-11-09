package yarrow

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// goldenCases returns the base name of every case in testdata/parser.
func goldenCases(t *testing.T) []string {
	t.Helper()
	ins, err := filepath.Glob("testdata/parser/*.in")
	if err != nil || len(ins) == 0 {
		t.Fatalf("no golden inputs: %v", err)
	}
	names := make([]string, len(ins))
	for i, p := range ins {
		names[i] = strings.TrimSuffix(filepath.Base(p), ".in")
	}
	return names
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// TestGoldenCST compares the rendered tree against the reference output
// byte for byte.
func TestGoldenCST(t *testing.T) {
	for _, name := range goldenCases(t) {
		t.Run(name, func(t *testing.T) {
			src := read(t, "testdata/parser/"+name+".in")
			want := read(t, "testdata/parser/"+name+".cst")
			cst, err := Parse([]byte(src))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			got := cst.String()
			if got != want {
				t.Errorf("CST mismatch\n%s", firstDiff(want, got))
			}
		})
	}
}

// TestGoldenStream compares the raw event stream, which also covers the
// error events that the tree dump omits.
func TestGoldenStream(t *testing.T) {
	for _, name := range goldenCases(t) {
		t.Run(name, func(t *testing.T) {
			src := read(t, "testdata/parser/"+name+".in")
			want := read(t, "testdata/parser/"+name+".cststream")
			got := FormatEvents(NewParser([]byte(src)).Events())
			if got != want {
				t.Errorf("stream mismatch\n%s", firstDiff(want, got))
			}
		})
	}
}

// firstDiff reports the first differing line with a little context, which
// is far easier to read than a full dump of two large trees.
func firstDiff(want, got string) string {
	w := strings.Split(want, "\n")
	g := strings.Split(got, "\n")
	for i := 0; i < len(w) || i < len(g); i++ {
		var wl, gl string
		if i < len(w) {
			wl = w[i]
		}
		if i < len(g) {
			gl = g[i]
		}
		if wl != gl {
			var b strings.Builder
			lo := i - 3
			if lo < 0 {
				lo = 0
			}
			for j := lo; j < i; j++ {
				b.WriteString("  ctx: " + w[j] + "\n")
			}
			b.WriteString("  line " + itoa(i+1) + "\n")
			b.WriteString("  want: " + wl + "\n")
			b.WriteString("   got: " + gl + "\n")
			return b.String()
		}
	}
	return "(no line difference; check trailing bytes)"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
