package scan

import (
	"bytes"
	"sort"
)

// TextMods are the yarrow string-pattern modifiers the engine applies to a literal
// text pattern. pkg/compile maps the AST PatternModifier list onto this struct.
//
// Supported: nocase, wide, ascii (and wide+ascii together), xor(min-max),
// fullword, and base64/base64wide (see base64.go). The rarer xor+nocase/xor+wide
// combinations and exact base64 character-count parity are differential-validated
// refinements (their byte semantics are best pinned against YARA-X).
type TextMods struct {
	Nocase      bool
	Wide        bool
	Ascii       bool // explicit `ascii`; with Wide, match both the ascii and wide forms
	Xor         bool
	XorMin      int
	XorMax      int
	Fullword    bool
	Base64      bool
	Base64Wide  bool
	Base64Alpha string // custom 64-char alphabet ("" → standard)
}

// Text is a compiled text pattern: either a plain literal (matched with the
// optimized bytes.Index fast path) or the union of one or more NFA programs (wide,
// ascii, and each xor key / base64 alignment each contribute a program), plus an
// optional fullword post-filter.
type Text struct {
	literal  []byte // fast path: a plain literal, matched via bytes.Index
	progs    []program
	fullword bool
}

// CompileText builds a Text pattern from the decoded pattern bytes and modifiers.
func CompileText(value []byte, m TextMods) Text {
	// Fast path: a plain literal (no case/width/encoding transform) is matched by
	// a tuned substring search rather than the NFA — the common case, ~GB/s.
	if len(value) > 0 && !m.Nocase && !m.Wide && !m.Xor && !m.Base64 && !m.Base64Wide {
		return Text{literal: value, fullword: m.Fullword}
	}
	// base64 replaces the plain/wide/xor forms: the pattern is matched only as its
	// base64 encoding(s). base64 → ascii subs; base64wide → the subs widened.
	if m.Base64 || m.Base64Wide {
		var progs []program
		for _, sub := range base64Subs(value, m.Base64Alpha) {
			if m.Base64 {
				progs = append(progs, Literal(sub, false))
			}
			if m.Base64Wide {
				progs = append(progs, Literal(widen(sub), false))
			}
		}
		return Text{progs: progs, fullword: m.Fullword}
	}
	var progs []program
	for _, f := range textForms(value, m) {
		if m.Xor {
			lo, hi := m.XorMin, m.XorMax
			if hi < lo {
				lo, hi = 0, 255
			}
			for k := lo; k <= hi; k++ {
				progs = append(progs, Literal(xorBytes(f, byte(k)), false))
			}
		} else {
			progs = append(progs, Literal(f, m.Nocase))
		}
	}
	return Text{progs: progs, fullword: m.Fullword}
}

// textForms returns the byte forms to match: the ascii form (unless only `wide`
// was given) and/or the wide (UTF-16LE) form.
func textForms(value []byte, m TextMods) [][]byte {
	var out [][]byte
	if !m.Wide || m.Ascii {
		out = append(out, value)
	}
	if m.Wide {
		out = append(out, widen(value))
	}
	return out
}

// widen interleaves each byte with a zero, producing the UTF-16LE ("wide") form.
func widen(b []byte) []byte {
	w := make([]byte, len(b)*2)
	for i, c := range b {
		w[i*2] = c
	}
	return w
}

func xorBytes(b []byte, key byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		out[i] = c ^ key
	}
	return out
}

// FindAll returns every match of any form, fullword-filtered, ordered by start
// then end, with duplicates (same span from different forms) removed.
func (t Text) FindAll(input []byte) []Match {
	if t.literal != nil {
		return indexAll(input, t.literal, t.fullword)
	}
	var all []Match
	for i := range t.progs {
		for _, m := range t.progs[i].FindAll(input) {
			if !t.fullword || fullwordOK(input, m) {
				all = append(all, m)
			}
		}
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].Start != all[j].Start {
			return all[i].Start < all[j].Start
		}
		return all[i].End < all[j].End
	})
	// Dedup adjacent identical spans (e.g. ascii and wide forms cannot collide, but
	// overlapping xor keys on a zero run could).
	out := all[:0]
	var prev Match
	for i, m := range all {
		if i == 0 || m != prev {
			out = append(out, m)
			prev = m
		}
	}
	return out
}

// Match reports whether the text pattern matches anywhere in input.
func (t Text) Match(input []byte) bool {
	if t.literal != nil {
		if !t.fullword {
			return bytes.Contains(input, t.literal)
		}
		return len(indexAll(input, t.literal, true)) > 0
	}
	return len(t.FindAll(input)) > 0
}

// indexAll returns every (overlapping) occurrence of pat in data, applying the
// fullword filter, using the tuned bytes.Index.
func indexAll(data, pat []byte, fullword bool) []Match {
	var out []Match
	for i := 0; i+len(pat) <= len(data); {
		j := bytes.Index(data[i:], pat)
		if j < 0 {
			break
		}
		start := i + j
		m := Match{Start: start, End: start + len(pat)}
		if !fullword || fullwordOK(data, m) {
			out = append(out, m)
		}
		i = start + 1 // +1 so self-overlapping literals report every position
	}
	return out
}

// fullwordOK reports whether match m is bounded by non-word bytes on both sides,
// as the `fullword` modifier requires.
func fullwordOK(input []byte, m Match) bool {
	if m.Start > 0 && isWordByte(input[m.Start-1]) {
		return false
	}
	if m.End < len(input) && isWordByte(input[m.End]) {
		return false
	}
	return true
}

func isWordByte(b byte) bool {
	return b == '_' || (b >= '0' && b <= '9') || ((b|0x20) >= 'a' && (b|0x20) <= 'z')
}
