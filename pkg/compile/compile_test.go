package compile

import (
	"reflect"
	"testing"
)

// scan compiles src and scans data, returning the matching rule names.
func scanRules(t *testing.T, src, data string) []string {
	t.Helper()
	rs, err := Compile([]byte(src))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	hits, err := rs.Scan([]byte(data))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	return hits
}

func wantHits(t *testing.T, got []string, want ...string) {
	t.Helper()
	if want == nil {
		want = []string{}
	}
	if len(got) == 0 {
		got = []string{}
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("hits = %v, want %v", got, want)
	}
}

func TestTextAndCondition(t *testing.T) {
	src := `rule r {
		strings:
			$a = "malware"
			$b = "evil"
		condition:
			$a and $b
	}`
	wantHits(t, scanRules(t, src, "this malware is evil"), "r")
	wantHits(t, scanRules(t, src, "this malware is fine")) // $b absent
}

func TestCount(t *testing.T) {
	src := `rule r { strings: $a = "ab" condition: #a == 3 }`
	wantHits(t, scanRules(t, src, "ab ab ab"), "r")
	wantHits(t, scanRules(t, src, "ab ab")) // count 2
}

func TestAnchorAt(t *testing.T) {
	src := `rule r { strings: $a = "MZ" condition: $a at 0 }`
	wantHits(t, scanRules(t, src, "MZ header"), "r")
	wantHits(t, scanRules(t, src, "xMZ")) // not at 0
}

func TestOffsetLength(t *testing.T) {
	src := `rule r { strings: $a = "cat" condition: @a[1] == 4 and !a[1] == 3 }`
	wantHits(t, scanRules(t, src, "a a cat"), "r") // "cat" starts at offset 4
}

func TestHexPattern(t *testing.T) {
	src := `rule r { strings: $a = { 6A ?? 68 } condition: $a }`
	wantHits(t, scanRules(t, src, "x\x6A\x40\x68y"), "r")
	wantHits(t, scanRules(t, src, "\x6A\x68")) // no middle byte
}

func TestRegexpPattern(t *testing.T) {
	src := `rule r { strings: $a = /a[0-9]+b/ condition: $a }`
	wantHits(t, scanRules(t, src, "xa123by"), "r")
	wantHits(t, scanRules(t, src, "ab")) // needs at least one digit
}

func TestModifiers(t *testing.T) {
	nocase := `rule r { strings: $a = "SecretKey" nocase condition: $a }`
	wantHits(t, scanRules(t, nocase, "found secretkey!"), "r")

	wide := `rule r { strings: $a = "PE" wide condition: $a }`
	wantHits(t, scanRules(t, wide, "P\x00E\x00"), "r")
}

func TestOfQuantifiers(t *testing.T) {
	src := `rule r {
		strings:
			$a = "aaa"
			$b = "bbb"
			$c = "ccc"
		condition:
			2 of them
	}`
	wantHits(t, scanRules(t, src, "aaa and bbb"), "r") // 2 present
	wantHits(t, scanRules(t, src, "aaa only"))         // only 1
	wantHits(t, scanRules(t, "rule r { strings: $a=\"x\" $b=\"y\" condition: any of them }", "just x"), "r")
	wantHits(t, scanRules(t, "rule r { strings: $a=\"x\" $b=\"y\" condition: all of them }", "just x")) // not all
}

func TestFilesize(t *testing.T) {
	src := `rule r { condition: filesize > 3 }`
	wantHits(t, scanRules(t, src, "hello"), "r")
	wantHits(t, scanRules(t, src, "hi")) // len 2
}

func TestMultipleRulesAndPrivate(t *testing.T) {
	src := `
	private rule helper { strings: $h = "seed" condition: $h }
	rule a { strings: $x = "foo" condition: $x }
	rule b { strings: $y = "bar" condition: $y }`
	// helper matches but is private (not reported); a matches, b does not.
	wantHits(t, scanRules(t, src, "seed and foo"), "a")
}

func TestGlobalSuppression(t *testing.T) {
	src := `
	global rule must { condition: filesize > 100 }
	rule r { strings: $a = "x" condition: $a }`
	// The global fails (filesize small) → nothing reported even though r would match.
	wantHits(t, scanRules(t, src, "x"))
}

func TestArithmeticCondition(t *testing.T) {
	src := `rule r { strings: $a = "z" condition: #a * 2 + 1 == 3 }`
	wantHits(t, scanRules(t, src, "z only"), "r") // #a=1 -> 1*2+1=3
}
