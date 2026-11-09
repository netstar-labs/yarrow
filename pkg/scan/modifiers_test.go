package scan

import "testing"

func TestTextPlain(t *testing.T) {
	p := CompileText([]byte("abc"), TextMods{})
	if !p.Match([]byte("xxabc")) || p.Match([]byte("ABC")) {
		t.Error("plain text pattern wrong")
	}
}

func TestTextNocase(t *testing.T) {
	p := CompileText([]byte("abc"), TextMods{Nocase: true})
	if !p.Match([]byte("ABC")) || !p.Match([]byte("aBc")) {
		t.Error("nocase must match either case")
	}
}

func TestTextWide(t *testing.T) {
	p := CompileText([]byte("abc"), TextMods{Wide: true})
	wide := []byte{'a', 0, 'b', 0, 'c', 0}
	if !p.Match(wide) {
		t.Error("wide must match the UTF-16LE form")
	}
	if p.Match([]byte("abc")) {
		t.Error("wide-only must not match the ascii form")
	}
}

func TestTextWideAscii(t *testing.T) {
	p := CompileText([]byte("abc"), TextMods{Wide: true, Ascii: true})
	if !p.Match([]byte("abc")) {
		t.Error("wide+ascii must match ascii")
	}
	if !p.Match([]byte{'a', 0, 'b', 0, 'c', 0}) {
		t.Error("wide+ascii must match wide")
	}
}

func TestTextXorSingle(t *testing.T) {
	// xor(0x10): the pattern appears XORed with 0x10 in the data.
	p := CompileText([]byte("abc"), TextMods{Xor: true, XorMin: 0x10, XorMax: 0x10})
	enc := []byte{'a' ^ 0x10, 'b' ^ 0x10, 'c' ^ 0x10}
	if !p.Match(enc) {
		t.Error("xor(0x10) must match the XORed form")
	}
	if p.Match([]byte("abc")) {
		t.Error("xor(0x10) must not match the plain form")
	}
}

func TestTextXorRange(t *testing.T) {
	p := CompileText([]byte("KEY"), TextMods{Xor: true, XorMin: 1, XorMax: 255})
	for _, k := range []byte{1, 0x42, 0xFF} {
		if !p.Match(xorBytes([]byte("KEY"), k)) {
			t.Errorf("xor(1-255) must match key %#x", k)
		}
	}
	if p.Match([]byte("KEY")) { // key 0 excluded
		t.Error("xor(1-255) must not match the plain form")
	}
}

func TestTextFullword(t *testing.T) {
	p := CompileText([]byte("cat"), TextMods{Fullword: true})
	if !p.Match([]byte("a cat sat")) {
		t.Error("fullword must match a delimited word")
	}
	if !p.Match([]byte("cat")) {
		t.Error("fullword must match at the very edges")
	}
	if p.Match([]byte("category")) || p.Match([]byte("bobcat")) {
		t.Error("fullword must not match inside a larger word")
	}
	if !p.Match([]byte("the.cat.")) {
		t.Error("fullword: punctuation is a valid delimiter")
	}
}

func TestTextBase64(t *testing.T) {
	p := CompileText([]byte("hello"), TextMods{Base64: true})
	// base64("hello") = "aGVsbG8="; the alignment-0 sub "aGVsbG" is a prefix.
	if !p.Match([]byte("x aGVsbG8= y")) {
		t.Error("base64 must match the encoded form")
	}
	if p.Match([]byte("hello")) {
		t.Error("base64 must not match the plain form")
	}
	// "hello" shifted by one byte: base64("Xhello") = "WGhlbGxv" contains the
	// alignment-1 sub "hlbGxv".
	if !p.Match([]byte("WGhlbGxv")) {
		t.Error("base64 must match a shifted alignment")
	}
}
