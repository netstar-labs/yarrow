package scan

import (
	"reflect"
	"testing"
)

func starts(ms []Match) []int {
	out := make([]int, len(ms))
	for i, m := range ms {
		out[i] = m.Start
	}
	return out
}

func TestLiteral(t *testing.T) {
	p := Literal([]byte("abc"), false)
	got := p.FindAll([]byte("xabcyabc"))
	want := []Match{{1, 4}, {5, 8}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("FindAll = %v, want %v", got, want)
	}
	if p.Match([]byte("nope")) {
		t.Error("must not match absent literal")
	}
}

func TestLiteralOverlapping(t *testing.T) {
	// "aa" occurs at 0 and 1 in "aaa" — YARA reports overlapping matches.
	p := Literal([]byte("aa"), false)
	if got := starts(p.FindAll([]byte("aaa"))); !reflect.DeepEqual(got, []int{0, 1}) {
		t.Errorf("overlapping starts = %v, want [0 1]", got)
	}
}

func TestLiteralNocase(t *testing.T) {
	p := Literal([]byte("AbC"), true)
	for _, s := range []string{"abc", "ABC", "AbC", "aBc"} {
		if !p.Match([]byte(s)) {
			t.Errorf("nocase must match %q", s)
		}
	}
	if p.Match([]byte("abd")) {
		t.Error("nocase must not match abd")
	}
}

func TestHexBytesAndWildcard(t *testing.T) {
	// { 6A ?? 68 } — 0x6A, any byte, 0x68.
	p := compileOK([]Element{Byte(0x6A), AnyByte(), Byte(0x68)})
	if !p.Match([]byte{0x6A, 0x40, 0x68}) {
		t.Error("must match 6A 40 68")
	}
	if !p.Match([]byte{0x6A, 0xFF, 0x68}) {
		t.Error("wildcard must match any middle byte")
	}
	if p.Match([]byte{0x6A, 0x68}) {
		t.Error("must not match without the middle byte")
	}
}

func TestHexNibbleMask(t *testing.T) {
	hi := compileOK([]Element{MaskedByte(0x40, 0xF0)}) // 4? => 0x40..0x4F
	if !hi.Match([]byte{0x4A}) || hi.Match([]byte{0x5A}) {
		t.Error("4? must match 0x4A and not 0x5A")
	}
	lo := compileOK([]Element{MaskedByte(0x04, 0x0F)}) // ?4 => low nibble 4
	if !lo.Match([]byte{0xF4}) || !lo.Match([]byte{0x04}) || lo.Match([]byte{0x45}) {
		t.Error("?4 must match 0xF4/0x04 and not 0x45")
	}
}

func TestHexJumpFixed(t *testing.T) {
	// { 6A [2] 68 } — exactly two bytes between.
	p := compileOK([]Element{Byte(0x6A), Jump{Min: 2, Max: 2}, Byte(0x68)})
	if !p.Match([]byte{0x6A, 0x00, 0x11, 0x68}) {
		t.Error("must match with exactly two gap bytes")
	}
	if p.Match([]byte{0x6A, 0x00, 0x68}) || p.Match([]byte{0x6A, 0, 1, 2, 0x68}) {
		t.Error("must not match with one or three gap bytes")
	}
}

func TestHexJumpRange(t *testing.T) {
	// { 6A [1-3] 68 } — one to three bytes between.
	p := compileOK([]Element{Byte(0x6A), Jump{Min: 1, Max: 3}, Byte(0x68)})
	for _, gap := range [][]byte{{0}, {0, 1}, {0, 1, 2}} {
		in := append(append([]byte{0x6A}, gap...), 0x68)
		if !p.Match(in) {
			t.Errorf("must match gap of %d", len(gap))
		}
	}
	if p.Match([]byte{0x6A, 0x68}) { // zero gap
		t.Error("must not match zero gap")
	}
	if p.Match([]byte{0x6A, 0, 1, 2, 3, 0x68}) { // four gap
		t.Error("must not match a four-byte gap")
	}
}

func TestHexJumpUnbounded(t *testing.T) {
	// { 6A [2-] 68 } — two or more bytes between.
	p := compileOK([]Element{Byte(0x6A), Jump{Min: 2, Max: -1}, Byte(0x68)})
	if !p.Match([]byte{0x6A, 0, 1, 0x68}) {
		t.Error("must match the minimum gap")
	}
	big := append([]byte{0x6A}, make([]byte, 50)...)
	big = append(big, 0x68)
	if !p.Match(big) {
		t.Error("unbounded jump must match a long gap")
	}
	if p.Match([]byte{0x6A, 0, 0x68}) {
		t.Error("must not match below the minimum gap")
	}
}

func TestHexAlternation(t *testing.T) {
	// { 6A ( 01 | 02 03 ) 6B } — one branch is one byte, the other two.
	p := compileOK([]Element{
		Byte(0x6A),
		Alt{Alts: [][]Element{{Byte(0x01)}, {Byte(0x02), Byte(0x03)}}},
		Byte(0x6B),
	})
	if !p.Match([]byte{0x6A, 0x01, 0x6B}) {
		t.Error("must match the 01 branch")
	}
	if !p.Match([]byte{0x6A, 0x02, 0x03, 0x6B}) {
		t.Error("must match the 02 03 branch")
	}
	if p.Match([]byte{0x6A, 0x02, 0x6B}) {
		t.Error("must not match a half branch")
	}
}

func TestByteSet(t *testing.T) {
	full := fullByteSet()
	for x := 0; x < 256; x++ {
		if !full.has(byte(x)) {
			t.Fatalf("full set missing %d", x)
		}
	}
	var r byteSet
	r.addRange(0x40, 0x4F)
	if r.has(0x3F) || !r.has(0x40) || !r.has(0x4F) || r.has(0x50) {
		t.Error("addRange 0x40..0x4F boundaries wrong")
	}
}

// compileOK compiles elements for tests, asserting no size-cap error.
func compileOK(elems []Element) program {
	p, err := Compile(elems)
	if err != nil {
		panic(err)
	}
	return p
}
