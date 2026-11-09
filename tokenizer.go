package yarrow

import "unicode/utf8"

// Mode is a tokenizer operating mode.
//
// Some lexemes are ambiguous without context. Inside a hex pattern `a0` is a
// byte literal; outside it is an identifier. `10` is an integer in normal
// mode, a byte in hex-pattern mode, and an integer again inside a hex jump.
// The tokenizer cannot know which context it is in, so the parser drives it:
// it calls EnterHexPatternMode after the opening `{` of a hex pattern and
// EnterHexJumpMode after the opening `[` of a jump. The tokenizer leaves each
// mode on its own when a lexeme appears that the mode cannot represent.
type Mode uint8

const (
	// ModeNormal recognises the full YARA syntax.
	ModeNormal Mode = iota
	// ModeHexPattern recognises only what may appear between `{` and `}`
	// in a hex pattern.
	ModeHexPattern
	// ModeHexJump recognises only what may appear between `[` and `]`
	// in a hex jump.
	ModeHexJump
)

// Tokenizer converts YARA source into a sequence of tokens.
//
// The input need not be valid UTF-8. Invalid sequences outside string
// literals, regexps and comments yield T_INVALID_UTF8 tokens and tokenizing
// continues, so a single bad byte does not abort the parse.
//
// The zero value is not usable; call NewTokenizer.
type Tokenizer struct {
	src  []byte
	pos  int
	mode Mode
}

// NewTokenizer returns a Tokenizer reading from src.
//
// src is retained, not copied; the caller must not modify it while the
// tokenizer is in use. Spans index into src.
func NewTokenizer(src []byte) *Tokenizer {
	return &Tokenizer{src: src}
}

// Source returns the source being tokenized.
func (t *Tokenizer) Source() []byte { return t.src }

// EnterHexPatternMode switches to hex-pattern mode.
//
// The parser calls this after consuming the `{` that opens a hex pattern.
// The tokenizer returns to normal mode by itself on the first lexeme that
// hex-pattern mode cannot represent, which in well-formed input is the
// closing `}`.
func (t *Tokenizer) EnterHexPatternMode() { t.mode = ModeHexPattern }

// EnterHexJumpMode switches to hex-jump mode.
//
// The parser calls this after consuming the `[` that opens a jump. The
// tokenizer falls back to hex-pattern mode on the first lexeme hex-jump mode
// cannot represent, which in well-formed input is the closing `]`.
func (t *Tokenizer) EnterHexJumpMode() { t.mode = ModeHexJump }

// Next returns the next token, or ok == false at end of input.
func (t *Tokenizer) Next() (tok Token, ok bool) {
	for {
		if t.pos >= len(t.src) {
			return Token{}, false
		}
		switch t.mode {
		case ModeNormal:
			return t.nextNormal(), true
		case ModeHexPattern:
			if tok, ok := t.nextHexPattern(); ok {
				return tok, true
			}
			// Nothing in hex-pattern mode matches here (normally the
			// closing `}`). Fall back and retry at the same offset.
			t.mode = ModeNormal
		default: // ModeHexJump
			if tok, ok := t.nextHexJump(); ok {
				return tok, true
			}
			// Normally the closing `]`, which hex-pattern mode knows.
			t.mode = ModeHexPattern
		}
	}
}

// ---------------------------------------------------------------------------
// Character classes
// ---------------------------------------------------------------------------

// The tokenizer works on bytes and its character classes are ASCII-only,
// matching the reference implementation, whose regexes run over a byte
// source. The single exception is horizontal whitespace, which accepts a
// fixed set of non-ASCII space characters (see spaceLen).

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isAlpha(c byte) bool { return c|0x20 >= 'a' && c|0x20 <= 'z' }
func isIdent(c byte) bool { return isAlpha(c) || isDigit(c) || c == '_' }
func isOctal(c byte) bool { return c >= '0' && c <= '7' }

func isHex(c byte) bool {
	return isDigit(c) || (c|0x20 >= 'a' && c|0x20 <= 'f')
}

// isHexByteChar reports whether c may appear in a hex-pattern byte,
// i.e. a hex digit or the `?` wildcard.
func isHexByteChar(c byte) bool { return c == '?' || isHex(c) }

// spaceLen returns the encoded length of the horizontal-space character at
// src[i], or 0 if there is none.
//
// Besides space and tab this accepts the Unicode characters the reference
// tokenizer treats as spaces: U+00A0, U+2000..U+200A, U+202F and U+205F.
// Vertical whitespace is excluded; newlines are their own token.
func spaceLen(src []byte, i int) int {
	c := src[i]
	if c == ' ' || c == '\t' {
		return 1
	}
	if c == 0xC2 && i+1 < len(src) && src[i+1] == 0xA0 { // U+00A0
		return 2
	}
	if c == 0xE2 && i+2 < len(src) {
		switch src[i+1] {
		case 0x80:
			// U+2000..U+200A, and U+202F narrow no-break space.
			if b := src[i+2]; (b >= 0x80 && b <= 0x8A) || b == 0xAF {
				return 3
			}
		case 0x81:
			if src[i+2] == 0x9F { // U+205F
				return 3
			}
		}
	}
	return 0
}

// ---------------------------------------------------------------------------
// Shared lexemes
// ---------------------------------------------------------------------------

// emit builds a token spanning [t.pos, end) and advances past it.
func (t *Tokenizer) emit(id TokenID, end int) Token {
	tok := Token{ID: id, Span: Span{Start: uint32(t.pos), End: uint32(end)}}
	t.pos = end
	return tok
}

// scanSpace returns the end of the whitespace run at i, or i if none.
func scanSpace(src []byte, i int) int {
	for i < len(src) {
		n := spaceLen(src, i)
		if n == 0 {
			break
		}
		i += n
	}
	return i
}

// scanNewline returns the end of the line terminator at i, or i if none.
// CRLF is a single terminator.
func scanNewline(src []byte, i int) int {
	switch src[i] {
	case '\n':
		return i + 1
	case '\r':
		if i+1 < len(src) && src[i+1] == '\n' {
			return i + 2
		}
		return i + 1
	}
	return i
}

// scanBlockComment returns the end of the /* */ comment at i, or -1 if the
// comment is unterminated.
func scanBlockComment(src []byte, i int) int {
	for j := i + 2; j+1 < len(src); j++ {
		if src[j] == '*' && src[j+1] == '/' {
			return j + 2
		}
	}
	return -1
}

// scanLineComment returns the end of the // comment at i, which is the next
// newline or end of input. The terminator itself is not part of the comment.
func scanLineComment(src []byte, i int) int {
	for j := i + 2; j < len(src); j++ {
		if src[j] == '\n' {
			return j
		}
	}
	return len(src)
}

// tryComment recognises either comment form at i, returning -1 if src[i]
// does not begin a comment or the comment is unterminated.
func tryComment(src []byte, i int) int {
	if i+1 >= len(src) || src[i] != '/' {
		return -1
	}
	switch src[i+1] {
	case '*':
		return scanBlockComment(src, i)
	case '/':
		return scanLineComment(src, i)
	}
	return -1
}

// ---------------------------------------------------------------------------
// Normal mode
// ---------------------------------------------------------------------------

func (t *Tokenizer) nextNormal() Token {
	src, i := t.src, t.pos
	c := src[i]

	// Whitespace and newlines first: they are the most common bytes.
	if n := spaceLen(src, i); n != 0 {
		return t.emit(T_WHITESPACE, scanSpace(src, i))
	}
	if c == '\n' || c == '\r' {
		return t.emit(T_NEWLINE, scanNewline(src, i))
	}

	switch {
	case isAlpha(c) || c == '_':
		j := scanIdentTail(src, i)
		// A keyword and an identifier match the same text; the reference
		// lexer resolves the tie in favour of the keyword. Longer
		// identifiers (`android` vs `and`) win on length, which is why the
		// lookup happens on the complete identifier.
		if id, isKw := keyword(src[i:j]); isKw {
			return t.emit(id, j)
		}
		return t.emit(T_IDENT, j)

	case isDigit(c):
		// A float and an integer can both match here (`1` and `1.5`);
		// longest wins.
		n := scanInt(src, i)
		if f := scanFloat(src, i); f > n {
			return t.emit(T_FLOAT_LIT, f)
		}
		if n > i {
			return t.emit(T_INTEGER_LIT, n)
		}

	case c == '"':
		// A multi-line literal always outruns the single-line match it
		// contains (`"""` starts with the empty literal `""`), so prefer it
		// when it closes, and fall back otherwise.
		if e := scanMultiLineString(src, i); e > 0 {
			return t.emit(T_STRING_LIT, e)
		}
		if e := scanString(src, i); e > 0 {
			return t.emit(T_STRING_LIT, e)
		}

	case c == '/':
		// `/` opens a comment or a regexp; never division, which YARA
		// spells `\`.
		if e := tryComment(src, i); e > 0 {
			return t.emit(T_COMMENT, e)
		}
		if e := scanRegexp(src, i); e > 0 {
			return t.emit(T_REGEXP, e)
		}

	case c == '$', c == '#', c == '@':
		j := scanIdentTail(src, i)
		switch c {
		case '$':
			return t.emit(T_PATTERN_IDENT, j)
		case '#':
			return t.emit(T_PATTERN_COUNT, j)
		default:
			return t.emit(T_PATTERN_OFFSET, j)
		}

	case c == '!':
		// `!=` outruns the bare `!` that opens a pattern length.
		if i+1 < len(src) && src[i+1] == '=' {
			return t.emit(T_NE, i+2)
		}
		return t.emit(T_PATTERN_LENGTH, scanIdentTail(src, i))

	case c == '<':
		if i+1 < len(src) {
			switch src[i+1] {
			case '<':
				return t.emit(T_SHL, i+2)
			case '=':
				return t.emit(T_LE, i+2)
			}
		}
		return t.emit(T_LT, i+1)

	case c == '>':
		if i+1 < len(src) {
			switch src[i+1] {
			case '>':
				return t.emit(T_SHR, i+2)
			case '=':
				return t.emit(T_GE, i+2)
			}
		}
		return t.emit(T_GT, i+1)

	case c == '=':
		if i+1 < len(src) && src[i+1] == '=' {
			return t.emit(T_EQ, i+2)
		}
		return t.emit(T_EQUAL, i+1)
	}

	if id, ok := punctuation(c); ok {
		return t.emit(id, i+1)
	}
	return t.unexpected()
}

// keyword maps a complete identifier to its keyword token.
//
// The switch is on a string conversion of a byte slice, which the compiler
// performs without allocating in this position.
func keyword(b []byte) (TokenID, bool) {
	switch string(b) {
	case "all":
		return T_ALL_KW, true
	case "and":
		return T_AND_KW, true
	case "any":
		return T_ANY_KW, true
	case "ascii":
		return T_ASCII_KW, true
	case "at":
		return T_AT_KW, true
	case "base64":
		return T_BASE64_KW, true
	case "base64wide":
		return T_BASE64WIDE_KW, true
	case "condition":
		return T_CONDITION_KW, true
	case "contains":
		return T_CONTAINS_KW, true
	case "defined":
		return T_DEFINED_KW, true
	case "endswith":
		return T_ENDSWITH_KW, true
	case "entrypoint":
		return T_ENTRYPOINT_KW, true
	case "false":
		return T_FALSE_KW, true
	case "filesize":
		return T_FILESIZE_KW, true
	case "for":
		return T_FOR_KW, true
	case "fullword":
		return T_FULLWORD_KW, true
	case "global":
		return T_GLOBAL_KW, true
	case "icontains":
		return T_ICONTAINS_KW, true
	case "iendswith":
		return T_IENDSWITH_KW, true
	case "iequals":
		return T_IEQUALS_KW, true
	case "import":
		return T_IMPORT_KW, true
	case "in":
		return T_IN_KW, true
	case "include":
		return T_INCLUDE_KW, true
	case "istartswith":
		return T_ISTARTSWITH_KW, true
	case "matches":
		return T_MATCHES_KW, true
	case "meta":
		return T_META_KW, true
	case "nocase":
		return T_NOCASE_KW, true
	case "none":
		return T_NONE_KW, true
	case "not":
		return T_NOT_KW, true
	case "of":
		return T_OF_KW, true
	case "or":
		return T_OR_KW, true
	case "private":
		return T_PRIVATE_KW, true
	case "rule":
		return T_RULE_KW, true
	case "startswith":
		return T_STARTSWITH_KW, true
	case "strings":
		return T_STRINGS_KW, true
	case "them":
		return T_THEM_KW, true
	case "true":
		return T_TRUE_KW, true
	case "wide":
		return T_WIDE_KW, true
	case "xor":
		return T_XOR_KW, true
	case "with":
		return T_WITH_KW, true
	}
	return 0, false
}

// punctuation maps a single-byte operator or delimiter to its token.
func punctuation(c byte) (TokenID, bool) {
	switch c {
	case '&':
		return T_AMPERSAND, true
	case '*':
		return T_ASTERISK, true
	case '\\':
		return T_BACKSLASH, true // integer division in YARA
	case '^':
		return T_CARET, true
	case ':':
		return T_COLON, true
	case ',':
		return T_COMMA, true
	case '.':
		return T_DOT, true
	case '-':
		return T_HYPHEN, true
	case '%':
		return T_PERCENT, true
	case '|':
		return T_PIPE, true
	case '+':
		return T_PLUS, true
	case '~':
		return T_TILDE, true
	case '{':
		return T_L_BRACE, true
	case '}':
		return T_R_BRACE, true
	case '[':
		return T_L_BRACKET, true
	case ']':
		return T_R_BRACKET, true
	case '(':
		return T_L_PAREN, true
	case ')':
		return T_R_PAREN, true
	}
	return 0, false
}

// scanFloat matches `([0-9]+_*)+ '.' ([0-9_]+_*)+` and returns its end,
// or -1. Underscores are permitted as digit separators.
func scanFloat(src []byte, i int) int {
	j := i
	for j < len(src) && (isDigit(src[j]) || src[j] == '_') {
		j++
	}
	if j >= len(src) || src[j] != '.' {
		return -1
	}
	j++
	start := j
	for j < len(src) && (isDigit(src[j]) || src[j] == '_') {
		j++
	}
	if j == start {
		return -1
	}
	return j
}

// scanInt matches a hex, octal or decimal integer literal and returns its
// end, or i if none matches. The longest of the three alternatives wins.
func scanInt(src []byte, i int) int {
	best := i
	if i+2 < len(src) && src[i] == '0' {
		switch src[i+1] {
		case 'x':
			if isHex(src[i+2]) {
				j := i + 2
				for j < len(src) && (isHex(src[j]) || src[j] == '_') {
					j++
				}
				best = max(best, j)
			}
		case 'o':
			if isOctal(src[i+2]) {
				j := i + 2
				for j < len(src) && (isOctal(src[j]) || src[j] == '_') {
					j++
				}
				best = max(best, j)
			}
		}
	}
	// Decimal, with an optional KB/MB multiplier suffix.
	if isDigit(src[i]) {
		j := i
		for j < len(src) && (isDigit(src[j]) || src[j] == '_') {
			j++
		}
		if j+1 < len(src) && (src[j] == 'K' || src[j] == 'M') && src[j+1] == 'B' {
			j += 2
		}
		best = max(best, j)
	}
	return best
}

// scanIdentTail returns the offset just past the identifier that starts at
// src[i]. The first byte is taken as given (the caller has already classified
// it, e.g. as a letter, `$`, or `!`); the scan runs over the identifier bytes
// that follow.
func scanIdentTail(src []byte, i int) int {
	j := i + 1
	for j < len(src) && isIdent(src[j]) {
		j++
	}
	return j
}

// advBackslash steps over a `\x` escape beginning at src[j], where src[j] is a
// backslash, and returns the offset just past it. It returns -1 if the escape
// is unterminated or would span a line, which terminates any literal that
// permits escapes.
func advBackslash(src []byte, j int) int {
	if j+1 >= len(src) || src[j+1] == '\n' {
		return -1
	}
	return j + 2
}

// scanString matches a single-line `"..."` literal and returns its end, or
// -1 if unterminated. Escapes consume the following byte, so `\"` does not
// close the literal. A raw newline does.
func scanString(src []byte, i int) int {
	for j := i + 1; j < len(src); {
		switch src[j] {
		case '\\':
			// An escape may not span a line.
			if j = advBackslash(src, j); j < 0 {
				return -1
			}
		case '"':
			return j + 1
		case '\n':
			return -1
		default:
			j++
		}
	}
	return -1
}

// scanMultiLineString matches a `"""..."""` literal and returns its end, or
// -1 if src[i] does not begin one or it is unterminated. Unlike the
// single-line form, raw newlines are allowed in the body.
func scanMultiLineString(src []byte, i int) int {
	if i+2 >= len(src) || src[i+1] != '"' || src[i+2] != '"' {
		return -1
	}
	for j := i + 3; j < len(src); {
		switch src[j] {
		case '\\':
			if j = advBackslash(src, j); j < 0 {
				return -1
			}
		case '"':
			if j+2 < len(src) && src[j+1] == '"' && src[j+2] == '"' {
				return j + 3
			}
			j++
		default:
			j++
		}
	}
	return -1
}

// scanRegexp matches `/.../` with up to two trailing modifier letters and
// returns its end, or -1.
//
// The first body character may not be `*` or `/`, which keeps regexps from
// colliding with the two comment forms. The remaining body may not contain
// an unescaped `/`, so the first one closes the literal.
func scanRegexp(src []byte, i int) int {
	j := i + 1
	if j >= len(src) {
		return -1
	}
	switch c := src[j]; {
	case c == '\\':
		if j = advBackslash(src, j); j < 0 {
			return -1
		}
	case c == '*' || c == '/' || c == '\n':
		return -1
	default:
		j++
	}
	for j < len(src) {
		switch src[j] {
		case '\\':
			if j = advBackslash(src, j); j < 0 {
				return -1
			}
		case '/':
			j++
			for n := 0; n < 2 && j < len(src) && isAlpha(src[j]); n++ {
				j++
			}
			return j
		case '\n':
			return -1
		default:
			j++
		}
	}
	return -1
}

// unexpected produces a token for input that matches no rule.
//
// A byte that cannot start a UTF-8 sequence yields a one-byte
// T_INVALID_UTF8 so that tokenizing can resume immediately after it.
// Otherwise the run of valid UTF-8 up to the next whitespace is reported as
// a single T_UNKNOWN, which keeps one typo from producing one error per
// byte.
func (t *Tokenizer) unexpected() Token {
	src, start := t.src, t.pos
	if r, size := utf8.DecodeRune(src[start:]); r == utf8.RuneError && size <= 1 {
		return t.emit(T_INVALID_UTF8, start+1)
	}
	j := start
	for j < len(src) {
		r, size := utf8.DecodeRune(src[j:])
		if r == utf8.RuneError && size <= 1 {
			break // stop at the first invalid sequence
		}
		if isSpaceRune(r) {
			break
		}
		j += size
	}
	if j == start {
		j = start + 1
	}
	return t.emit(T_UNKNOWN, j)
}

// isSpaceRune reports whether r is whitespace, using the same definition as
// Rust's char::is_whitespace (Unicode White_Space).
func isSpaceRune(r rune) bool {
	switch r {
	case ' ', '\t', '\n', '\v', '\f', '\r', 0x85, 0xA0, 0x1680,
		0x2028, 0x2029, 0x202F, 0x205F, 0x3000:
		return true
	}
	return r >= 0x2000 && r <= 0x200A
}

// ---------------------------------------------------------------------------
// Hex pattern mode
// ---------------------------------------------------------------------------

// nextHexPattern recognises the lexemes valid between `{` and `}`.
// ok is false when the input matches nothing here, which tells Next to leave
// the mode rather than report an error.
func (t *Tokenizer) nextHexPattern() (Token, bool) {
	src, i := t.src, t.pos
	c := src[i]

	if spaceLen(src, i) != 0 {
		return t.emit(T_WHITESPACE, scanSpace(src, i)), true
	}
	if c == '\n' || c == '\r' {
		return t.emit(T_NEWLINE, scanNewline(src, i)), true
	}
	if e := tryComment(src, i); e > 0 {
		return t.emit(T_COMMENT, e), true
	}

	// A byte is two hex digits or `?` wildcards, optionally negated with `~`.
	// Forms such as `~??` are accepted here and rejected later, so that the
	// error can name the construct instead of the raw characters.
	j := i
	if c == '~' {
		j++
	}
	if j+1 < len(src) && isHexByteChar(src[j]) && isHexByteChar(src[j+1]) {
		return t.emit(T_HEX_BYTE, j+2), true
	}

	switch c {
	case '|':
		return t.emit(T_PIPE, i+1), true
	case '(':
		return t.emit(T_L_PAREN, i+1), true
	case ')':
		return t.emit(T_R_PAREN, i+1), true
	case '[':
		return t.emit(T_L_BRACKET, i+1), true
	case ']':
		return t.emit(T_R_BRACKET, i+1), true
	}
	return Token{}, false
}

// ---------------------------------------------------------------------------
// Hex jump mode
// ---------------------------------------------------------------------------

// nextHexJump recognises the lexemes valid between `[` and `]`.
// ok is false when nothing matches, which returns the tokenizer to
// hex-pattern mode; the closing `]` is recognised there.
func (t *Tokenizer) nextHexJump() (Token, bool) {
	src, i := t.src, t.pos
	c := src[i]

	if spaceLen(src, i) != 0 {
		return t.emit(T_WHITESPACE, scanSpace(src, i)), true
	}
	if c == '\n' || c == '\r' {
		return t.emit(T_NEWLINE, scanNewline(src, i)), true
	}
	if c == '-' {
		return t.emit(T_HYPHEN, i+1), true
	}
	// Jump bounds allow no underscore separators and no KB/MB suffix.
	if isDigit(c) {
		j := i
		if c == '0' && i+2 < len(src) {
			switch src[i+1] {
			case 'x':
				if isHex(src[i+2]) {
					j = i + 2
					for j < len(src) && isHex(src[j]) {
						j++
					}
					return t.emit(T_INTEGER_LIT, j), true
				}
			case 'o':
				if isOctal(src[i+2]) {
					j = i + 2
					for j < len(src) && isOctal(src[j]) {
						j++
					}
					return t.emit(T_INTEGER_LIT, j), true
				}
			}
		}
		// j is still i here: the 0x/0o branches above either return or leave
		// it untouched.
		for j < len(src) && isDigit(src[j]) {
			j++
		}
		return t.emit(T_INTEGER_LIT, j), true
	}
	return Token{}, false
}
