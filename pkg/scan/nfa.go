// Package scan is yarrow's byte-oriented pattern-matching engine — the load-bearing
// core of the matcher. It compiles a pattern (a literal string, a hex pattern, or a
// regexp) to a Thompson NFA over BYTES (not runes: YARA matches raw bytes,
// unanchored, and reports every match position) and runs it with a Pike VM.
//
// The engine is decoupled from the yarrow AST: it consumes its own byte-level
// Element vocabulary (Class / Jump / Alt / Repeat / assert), so it can be tested in
// isolation. pkg/compile bridges the yarrow AST (TextPattern / HexPattern /
// RegexpPattern + modifiers) to these elements.
//
// Pieces: the NFA program model + literal/hex/regexp compilers (nfa.go, regexp.go),
// the string modifiers (modifiers.go, base64.go), and the Pike VM (vm.go). A
// required-atom (Aho-Corasick) prefilter to prune start positions is the remaining
// performance phase; buffer reuse already keeps a scan's allocation flat.
package scan

import "errors"

// byteSet is a 256-bit set: the bytes a Class instruction accepts. A single byte
// is a one-element set; a hex `??` is the full set; a nibble mask like `4?` is the
// contiguous range 0x40..0x4F; `?4` is the (non-contiguous) set of bytes whose low
// nibble is 4.
type byteSet [4]uint64

func (s *byteSet) add(b byte)      { s[b>>6] |= 1 << (b & 63) }
func (s *byteSet) del(b byte)      { s[b>>6] &^= 1 << (b & 63) }
func (s *byteSet) has(b byte) bool { return s[b>>6]&(1<<(b&63)) != 0 }

func (s *byteSet) addRange(lo, hi int) {
	for b := lo; b <= hi; b++ {
		s.add(byte(b))
	}
}

func (s *byteSet) union(o byteSet) {
	for i := range s {
		s[i] |= o[i]
	}
}

func (s byteSet) complement() byteSet {
	return byteSet{^s[0], ^s[1], ^s[2], ^s[3]}
}

func fullByteSet() byteSet { return byteSet{^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0)} }

// foldSet returns s with, for every ASCII letter it contains, that letter's other
// case added — the case-insensitive expansion.
func foldSet(s byteSet) byteSet {
	out := s
	for b := byte('A'); b <= 'Z'; b++ {
		if s.has(b) {
			out.add(b | 0x20)
		}
	}
	for b := byte('a'); b <= 'z'; b++ {
		if s.has(b) {
			out.add(b &^ 0x20)
		}
	}
	return out
}

// Regexp character-class shorthands.
func classDigit() byteSet {
	var s byteSet
	s.addRange('0', '9')
	return s
}

func classWord() byteSet {
	var s byteSet
	s.addRange('0', '9')
	s.addRange('A', 'Z')
	s.addRange('a', 'z')
	s.add('_')
	return s
}

func classSpace() byteSet {
	var s byteSet
	for _, b := range []byte{' ', '\t', '\n', '\r', '\f', '\v'} {
		s.add(b)
	}
	return s
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func hexNibble(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}

// singleByte returns a set containing exactly b.
func singleByte(b byte) byteSet {
	var s byteSet
	s.add(b)
	return s
}

// maskedByte returns the set of bytes x for which (x & mask) == (value & mask).
// mask=0xFF is an exact byte; mask=0x00 is a wildcard (`??`); mask=0xF0 with
// value=0x40 is `4?`; mask=0x0F with value=0x04 is `?4`.
func maskedByte(value, mask byte) byteSet {
	var s byteSet
	want := value & mask
	for x := 0; x < 256; x++ {
		if byte(x)&mask == want {
			s.add(byte(x))
		}
	}
	return s
}

// opcode is the NFA instruction kind.
type opcode uint8

const (
	opClass       opcode = iota // consume one byte if it is in set; fall through to pc+1
	opSplit                     // epsilon: fork to x (higher priority) and y
	opJmp                       // epsilon: jump to x
	opAssertStart               // epsilon, only at absolute position 0 (regexp `^`)
	opAssertEnd                 // epsilon, only at end of input (regexp `$`)
	opMatch                     // accept
)

type inst struct {
	op   opcode
	set  byteSet // opClass
	x, y int     // opSplit targets / opJmp target
}

// program is a compiled NFA: a flat instruction list. opClass falls through to the
// next instruction, so concatenation is simple appending; opSplit/opJmp encode the
// non-linear control flow (jumps, repetition, alternation).
type program []inst

func (p *program) emit(in inst) int {
	*p = append(*p, in)
	return len(*p) - 1
}

// Element is one unit of a byte pattern the engine compiles.
type Element interface{ isElement() }

// Class matches a single byte in Set.
type Class struct{ Set byteSet }

// Jump is a hex `[Min-Max]` gap of arbitrary bytes. Max < 0 means unbounded (`[n-]`).
type Jump struct{ Min, Max int }

// Alt is a hex `( a | b | ... )` alternation of sub-sequences.
type Alt struct{ Alts [][]Element }

// Repeat is a repetition of a sub-sequence: `{Min,Max}` with Max<0 meaning
// unbounded (`*`/`+`/`{n,}`). Greedy prefers to consume; a lazy (`*?`) repeat
// prefers to stop. It is produced by the regexp frontend (regexp.go).
type Repeat struct {
	Sub      []Element
	Min, Max int
	Greedy   bool
}

// assert is a zero-width position assertion (regexp `^`/`$`).
type assert struct{ atEnd bool }

func (Class) isElement()  {}
func (Jump) isElement()   {}
func (Alt) isElement()    {}
func (Repeat) isElement() {}
func (assert) isElement() {}

// Byte builds a Class element matching exactly b.
func Byte(b byte) Class { return Class{singleByte(b)} }

// AnyByte builds a Class element matching any byte (hex `??`).
func AnyByte() Class { return Class{fullByteSet()} }

// MaskedByte builds a Class element for a hex masked byte (value, mask).
func MaskedByte(value, mask byte) Class { return Class{maskedByte(value, mask)} }

// maxProgramInst caps the compiled NFA size. Repetitions and jumps are unrolled,
// so an enormous bound (a malicious `a{0,99999999}` or `[0-99999999]`) would
// otherwise exhaust memory; compilation refuses it instead.
const maxProgramInst = 1 << 20

// ErrProgramTooLarge is returned when a pattern's compiled NFA would exceed
// maxProgramInst.
var ErrProgramTooLarge = errors.New("scan: compiled pattern too large")

// Compile builds an NFA program from a sequence of elements. It fails rather than
// unroll a repetition/jump whose bound would blow past the instruction cap.
func Compile(elems []Element) (program, error) {
	var p program
	compileSeq(&p, elems)
	if len(p) >= maxProgramInst {
		return nil, ErrProgramTooLarge
	}
	p.emit(inst{op: opMatch})
	return p, nil
}

// Literal compiles a literal byte string. When nocase, each ASCII letter matches
// either case. A literal's length is bounded by the (parser-capped) pattern, so
// it cannot overflow the instruction cap; an empty program is never returned.
func Literal(b []byte, nocase bool) program {
	elems := make([]Element, len(b))
	for i, c := range b {
		if nocase {
			// foldSet adds a case-partner only for ASCII letters, so a non-letter
			// byte folds to itself — one case-folding path shared with the regexp
			// compiler instead of a hand-rolled copy here.
			elems[i] = Class{foldSet(singleByte(c))}
		} else {
			elems[i] = Byte(c)
		}
	}
	p, _ := Compile(elems)
	return p
}

// compileSeq appends the NFA for a concatenation of elements to p.
func compileSeq(p *program, elems []Element) {
	for _, e := range elems {
		switch e := e.(type) {
		case Class:
			p.emit(inst{op: opClass, set: e.Set})
		case Jump:
			compileJump(p, e)
		case Alt:
			compileAlt(p, e)
		case Repeat:
			compileRepeat(p, e)
		case assert:
			if e.atEnd {
				p.emit(inst{op: opAssertEnd})
			} else {
				p.emit(inst{op: opAssertStart})
			}
		}
	}
}

// compileRepeat emits Min mandatory copies of the sub-sequence, then the variable
// part: an unbounded greedy/lazy loop for Max<0, or Max-Min optional copies
// otherwise. Greedy splits prefer the body; lazy splits prefer the exit.
func compileRepeat(p *program, r Repeat) {
	for i := 0; i < r.Min && len(*p) < maxProgramInst; i++ {
		compileSeq(p, r.Sub)
	}
	if len(*p) >= maxProgramInst {
		return
	}
	if r.Max < 0 {
		// L: split(body, exit); body: <Sub>; jmp L; exit:
		sp := p.emit(inst{op: opSplit})
		body := len(*p)
		compileSeq(p, r.Sub)
		p.emit(inst{op: opJmp, x: sp})
		exit := len(*p)
		setSplit(p, sp, body, exit, r.Greedy)
		return
	}
	// Max-Min optional copies, nested so any prefix count can stop at the exit. A
	// backwards bound ({m,n} with n<m) yields no optional copies rather than a
	// negative count.
	opt := r.Max - r.Min
	if opt < 0 {
		opt = 0
	}
	splits := make([]int, 0, min(opt, 4096))
	for i := 0; i < opt && len(*p) < maxProgramInst; i++ {
		sp := p.emit(inst{op: opSplit})
		splits = append(splits, sp)
		body := len(*p)
		compileSeq(p, r.Sub) // falls through to the next split (or the exit)
		if r.Greedy {
			(*p)[sp].x = body
		} else {
			(*p)[sp].y = body
		}
	}
	exit := len(*p)
	for _, sp := range splits {
		if r.Greedy {
			(*p)[sp].y = exit
		} else {
			(*p)[sp].x = exit
		}
	}
}

// setSplit wires a split to prefer body (greedy) or exit (lazy).
func setSplit(p *program, sp, body, exit int, greedy bool) {
	if greedy {
		(*p)[sp].x, (*p)[sp].y = body, exit
	} else {
		(*p)[sp].x, (*p)[sp].y = exit, body
	}
}

// compileJump emits a hex `[Min-Max]` gap. A gap is exactly a greedy repetition
// of the any-byte class, so it reuses compileRepeat — one code path for the
// mandatory-copy / unbounded-loop / bounded-optional wiring and the instruction
// cap. (A jump has no lazy form, hence Greedy: true.) FindAll reports every match
// position, so greedy vs. lazy thread priority cannot change the result.
func compileJump(p *program, j Jump) {
	compileRepeat(p, Repeat{Sub: []Element{AnyByte()}, Min: j.Min, Max: j.Max, Greedy: true})
}

// compileAlt emits split/jmp wiring for an alternation, each branch jumping to a
// common end.
func compileAlt(p *program, a Alt) {
	if len(a.Alts) == 0 {
		return
	}
	jmpEnds := make([]int, 0, len(a.Alts))
	for i, alt := range a.Alts {
		last := i == len(a.Alts)-1
		var sp int
		if !last {
			sp = p.emit(inst{op: opSplit})
			(*p)[sp].x = len(*p) // this branch starts next
		}
		compileSeq(p, alt)
		if !last {
			j := p.emit(inst{op: opJmp}) // jump to the shared end (patched below)
			jmpEnds = append(jmpEnds, j)
			(*p)[sp].y = len(*p) // the other branch(es) start after this jmp
		}
	}
	end := len(*p)
	for _, j := range jmpEnds {
		(*p)[j].x = end
	}
}
