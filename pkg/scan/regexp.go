package scan

import "fmt"

// Regexp compiles a YARA regular expression body (without the slashes) to an NFA
// program. caseInsensitive is the `i` flag; dotAll is the `s` flag (`.` also
// matches newline). It supports literals, `.`, character classes `[...]` with
// ranges/negation, the class escapes \d \w \s (and negations), the byte escapes
// \n \r \t \f \v \0 \xNN, groups `(...)` and `(?:...)`, alternation `|`, the
// quantifiers `* + ? {n} {n,} {n,m}` (greedy, or lazy with a trailing `?`), and
// the anchors `^` `$` (position assertions in the VM).
//
// Not yet supported (an error, not a silent mismatch): word boundaries `\b` `\B`.
func Regexp(body string, caseInsensitive, dotAll bool) (program, error) {
	p := &reParser{src: []byte(body), nocase: caseInsensitive, dotAll: dotAll}
	elems, err := p.parseAlt()
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.src) {
		return nil, fmt.Errorf("regexp: unexpected %q at offset %d", p.src[p.pos], p.pos)
	}
	return Compile(elems)
}

type reParser struct {
	src    []byte
	pos    int
	nocase bool
	dotAll bool
}

func (p *reParser) peek() (byte, bool) {
	if p.pos < len(p.src) {
		return p.src[p.pos], true
	}
	return 0, false
}

// parseAlt := parseConcat ('|' parseConcat)*
func (p *reParser) parseAlt() ([]Element, error) {
	first, err := p.parseConcat()
	if err != nil {
		return nil, err
	}
	if c, ok := p.peek(); !ok || c != '|' {
		return first, nil
	}
	alts := [][]Element{first}
	for {
		c, ok := p.peek()
		if !ok || c != '|' {
			break
		}
		p.pos++ // consume '|'
		next, err := p.parseConcat()
		if err != nil {
			return nil, err
		}
		alts = append(alts, next)
	}
	return []Element{Alt{Alts: alts}}, nil
}

// parseConcat := parseRepeat* (until '|' or ')' or end)
func (p *reParser) parseConcat() ([]Element, error) {
	var out []Element
	for {
		c, ok := p.peek()
		if !ok || c == '|' || c == ')' {
			break
		}
		part, err := p.parseRepeat()
		if err != nil {
			return nil, err
		}
		out = append(out, part...)
	}
	return out, nil
}

// parseRepeat := parseAtom quantifier?
func (p *reParser) parseRepeat() ([]Element, error) {
	atom, err := p.parseAtom()
	if err != nil {
		return nil, err
	}
	c, ok := p.peek()
	if !ok {
		return atom, nil
	}
	var min, max int
	switch c {
	case '*':
		min, max = 0, -1
		p.pos++
	case '+':
		min, max = 1, -1
		p.pos++
	case '?':
		min, max = 0, 1
		p.pos++
	case '{':
		var parsed bool
		min, max, parsed = p.parseBound()
		if !parsed {
			return atom, nil // a literal '{' that isn't a valid bound
		}
		if max >= 0 && max < min {
			return nil, fmt.Errorf("regexp: invalid repetition bound {%d,%d}", min, max)
		}
	default:
		return atom, nil
	}
	greedy := true
	if c, ok := p.peek(); ok && c == '?' { // lazy
		greedy = false
		p.pos++
	}
	return []Element{Repeat{Sub: atom, Min: min, Max: max, Greedy: greedy}}, nil
}

// parseBound parses `{n}`, `{n,}`, or `{n,m}` at pos (which is '{'). Returns
// parsed=false and does not advance if it is not a valid bound.
func (p *reParser) parseBound() (min, max int, parsed bool) {
	save := p.pos
	p.pos++ // '{'
	n, okN := p.parseInt()
	if !okN {
		p.pos = save
		return 0, 0, false
	}
	min = n
	max = n
	if c, ok := p.peek(); ok && c == ',' {
		p.pos++
		if m, okM := p.parseInt(); okM {
			max = m
		} else {
			max = -1 // {n,}
		}
	}
	if c, ok := p.peek(); !ok || c != '}' {
		p.pos = save
		return 0, 0, false
	}
	p.pos++ // '}'
	return min, max, true
}

func (p *reParser) parseInt() (int, bool) {
	start := p.pos
	n := 0
	for p.pos < len(p.src) && p.src[p.pos] >= '0' && p.src[p.pos] <= '9' {
		n = n*10 + int(p.src[p.pos]-'0')
		if n > maxProgramInst {
			n = maxProgramInst + 1 // clamp: a bound this large is refused by the
			// instruction cap. Clamping also stops an overflow to a NEGATIVE n,
			// which compileRepeat would misread as an unbounded (`*`) loop.
		}
		p.pos++
	}
	return n, p.pos > start
}

// parseAtom := '(' parseAlt ')' | '[' class ']' | '.' | escape | literal
func (p *reParser) parseAtom() ([]Element, error) {
	c, ok := p.peek()
	if !ok {
		return nil, fmt.Errorf("regexp: unexpected end of pattern")
	}
	switch c {
	case '(':
		p.pos++
		// Non-capturing group prefix (?:...) — yarrow does not track captures, so a
		// plain group and (?:...) compile identically.
		if p.pos+1 < len(p.src) && p.src[p.pos] == '?' && p.src[p.pos+1] == ':' {
			p.pos += 2
		}
		inner, err := p.parseAlt()
		if err != nil {
			return nil, err
		}
		if c, ok := p.peek(); !ok || c != ')' {
			return nil, fmt.Errorf("regexp: unterminated group")
		}
		p.pos++
		return inner, nil
	case ')':
		return nil, fmt.Errorf("regexp: unmatched ')'")
	case '[':
		return p.parseClass()
	case '.':
		p.pos++
		s := fullByteSet()
		if !p.dotAll {
			s.del('\n') // `.` matches any byte except newline unless the `s` flag
		}
		return []Element{Class{s}}, nil
	case '^':
		p.pos++
		return []Element{assert{atEnd: false}}, nil
	case '$':
		p.pos++
		return []Element{assert{atEnd: true}}, nil
	case '*', '+', '?':
		return nil, fmt.Errorf("regexp: quantifier %q with nothing to repeat", c)
	case '\\':
		s, err := p.parseEscape(false)
		if err != nil {
			return nil, err
		}
		return []Element{Class{p.fold(s)}}, nil
	default:
		p.pos++
		return []Element{Class{p.fold(singleByte(c))}}, nil
	}
}

// parseClass parses `[...]` (with optional leading `^` negation) into one Class.
func (p *reParser) parseClass() ([]Element, error) {
	p.pos++ // '['
	negate := false
	if c, ok := p.peek(); ok && c == '^' {
		negate = true
		p.pos++
	}
	var set byteSet
	first := true
	for {
		c, ok := p.peek()
		if !ok {
			return nil, fmt.Errorf("regexp: unterminated character class")
		}
		if c == ']' && !first {
			p.pos++
			break
		}
		first = false
		// Range a-z: lookahead for '-' followed by a non-']' char.
		if c != '\\' && p.pos+2 < len(p.src) && p.src[p.pos+1] == '-' && p.src[p.pos+2] != ']' {
			lo := c
			hi := p.src[p.pos+2]
			p.pos += 3
			set.addRange(int(lo), int(hi))
			continue
		}
		if c == '\\' {
			sub, err := p.parseEscape(true)
			if err != nil {
				return nil, err
			}
			set.union(sub)
			continue
		}
		set.add(c)
		p.pos++
	}
	if p.nocase {
		set = foldSet(set)
	}
	if negate {
		set = set.complement()
	}
	return []Element{Class{set}}, nil
}

// parseEscape parses a `\x` escape at pos (which is '\'), returning the byteSet it
// denotes. inClass allows the class shorthands to contribute a set.
func (p *reParser) parseEscape(inClass bool) (byteSet, error) {
	p.pos++ // '\'
	c, ok := p.peek()
	if !ok {
		return byteSet{}, fmt.Errorf("regexp: trailing backslash")
	}
	p.pos++
	switch c {
	case 'd':
		return classDigit(), nil
	case 'D':
		return classDigit().complement(), nil
	case 'w':
		return classWord(), nil
	case 'W':
		return classWord().complement(), nil
	case 's':
		return classSpace(), nil
	case 'S':
		return classSpace().complement(), nil
	case 'n':
		return singleByte('\n'), nil
	case 'r':
		return singleByte('\r'), nil
	case 't':
		return singleByte('\t'), nil
	case 'f':
		return singleByte('\f'), nil
	case 'v':
		return singleByte('\v'), nil
	case '0':
		return singleByte(0), nil
	case 'b', 'B':
		if inClass {
			return singleByte(c), nil // \b in a class is backspace-ish; keep literal 'b'
		}
		return byteSet{}, fmt.Errorf("regexp: word boundary (\\%c) is not yet supported", c)
	case 'x':
		if p.pos+1 < len(p.src) && isHex(p.src[p.pos]) && isHex(p.src[p.pos+1]) {
			b := hexNibble(p.src[p.pos])<<4 | hexNibble(p.src[p.pos+1])
			p.pos += 2
			return singleByte(b), nil
		}
		return byteSet{}, fmt.Errorf("regexp: expected two hex digits after \\x")
	default:
		return singleByte(c), nil // escaped metacharacter → literal
	}
}

// fold applies case-insensitivity to a single-byte-derived set when nocase is on.
func (p *reParser) fold(s byteSet) byteSet {
	if p.nocase {
		return foldSet(s)
	}
	return s
}
