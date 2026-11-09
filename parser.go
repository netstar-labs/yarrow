package yarrow

import (
	"strings"
	"unicode/utf8"
)

// pstate is the parser's control state.
type pstate uint8

const (
	// stOK means parsing may continue.
	stOK pstate = iota
	// stFailure means the current production did not match. A failure can
	// be absorbed by an enclosing opt/alt, or cleared by recover.
	stFailure
	// stOutOfFuel means the fuel budget was exhausted. Unlike stFailure it
	// is sticky: nothing clears it, so the parse unwinds to the top.
	stOutOfFuel
)

// defaultFuel bounds the number of non-terminals a single parse may open.
//
// A PEG parser with backtracking can, on adversarial input, explore an
// exponential number of paths. Fuel makes that terminate: every begin costs
// one unit, and running out aborts the parse instead of hanging. The limit
// is far above what any legitimate rule file needs.
const defaultFuel = 100_000_000

// Parser turns YARA source into a stream of CST events.
//
// It is error-resilient: a syntax error does not stop the parse. The
// offending region is wrapped in an ERROR node, a diagnostic is recorded,
// and parsing resumes at the next construct that can start a new item. A
// file with a broken rule still yields a usable tree for every other rule,
// which is what a language server or bulk rule linter needs.
type Parser struct {
	tokens *tokenStream
	out    syntaxStream
	state  pstate
	fuel   int

	// optDepth > 0 means the parser is inside a production whose failure is
	// expected and will be absorbed, so errors must not be reported.
	optDepth int
	// notDepth > 0 means the parser is inside a negative lookahead, where a
	// successful match is the failure case.
	notDepth int

	// cache memoises (token index, kind) pairs that already failed, which
	// stops the same doomed production being re-tried at the same position.
	cache map[cacheKey]struct{}

	pendingErrors []pendingErr
	// expected holds candidate "expecting X" diagnostics. Only those at
	// the largest offset seen since the last flush are retained; see
	// expectedSlot for why the rest can be discarded immediately.
	expected   []expectedErr
	unexpected []Span
	// errMaxStart is the largest offset among the retained candidates.
	errMaxStart uint32
	// haveErrCand distinguishes "no candidates yet" from "candidates at
	// offset zero".
	haveErrCand bool
}

type cacheKey struct {
	index int
	kind  SyntaxKind
}

type pendingErr struct {
	span Span
	msg  string
}

type expKey struct {
	span Span
	tok  TokenID
}

// expectedErr accumulates the descriptions of every token that would have
// been acceptable at one position, in the order they were tried, so the
// message reads in grammar order rather than at random.
type expectedErr struct {
	key   expKey
	descs []string
}

// add appends d unless it is already present. The list holds at most a few
// entries, so a linear scan beats a hash set and avoids allocating one.
func (e *expectedErr) add(d string) {
	for _, x := range e.descs {
		if x == d {
			return
		}
	}
	e.descs = append(e.descs, d)
}

// NewParser returns a Parser for src.
//
// src is retained, not copied. Sources larger than MaxSpan are rejected by
// Parse rather than silently truncated.
func NewParser(src []byte) *Parser {
	return &Parser{
		tokens: newTokenStream(NewTokenizer(src)),
		state:  stOK,
		fuel:   defaultFuel,
		cache:  make(map[cacheKey]struct{}),
	}
}

// SetFuel bounds how many non-terminals a parse may open.
//
// The default is generous enough that no legitimate rule file reaches it.
// A pipeline that ingests rules from untrusted sources may want a tighter
// bound: exhausting the budget aborts the parse and yields a partial tree
// rather than letting a crafted input consume unbounded CPU. A value of
// zero or less restores the default.
func (p *Parser) SetFuel(n int) *Parser {
	if n <= 0 {
		n = defaultFuel
	}
	p.fuel = n
	return p
}

// OutOfFuel reports whether the parse stopped early because the fuel budget
// was exhausted. When true, the tree covers only part of the input.
func (p *Parser) OutOfFuel() bool { return p.state == stOutOfFuel }

// Events runs the parser and returns the complete event stream.
//
// The stream always begins with a SOURCE_FILE Begin and ends with the
// matching End, whose span covers the whole input regardless of errors.
func (p *Parser) Events() []Event {
	src := p.tokens.source()
	whole := Span{Start: 0, End: uint32(len(src))}

	begin := Event{Kind: EventBegin, Syntax: SOURCE_FILE, Span: whole}

	// Each iteration consumes one top-level item, so a failure is contained
	// to that item and the next one still gets parsed.
	for p.state != stOutOfFuel {
		if _, ok := p.tokens.peek(0); !ok {
			break
		}
		p.trivia()
		p.topLevelItem()
		p.flushErrors()
		clear(p.cache)
		p.setState(stOK)
	}

	events := make([]Event, 0, len(p.out.events)+2)
	events = append(events, begin)
	events = append(events, p.out.events...)
	events = append(events, Event{Kind: EventEnd, Syntax: SOURCE_FILE, Span: whole})
	return mergeErrors(events)
}

// ---------------------------------------------------------------------------
// Token sets
// ---------------------------------------------------------------------------

// tokenSet is a set of acceptable syntax kinds.
//
// It maps kinds rather than tokens because several kinds can share a token:
// the byte `-` is HYPHEN, SUB or MINUS depending on where it appears, and
// the kind recorded in the tree is the one the grammar asked for. Sets are
// small, so a linear scan beats hashing.
type tokenSet []SyntaxKind

// contains reports the kind to record if tok is acceptable.
func (ts tokenSet) contains(tok Token) (SyntaxKind, bool) {
	for _, k := range ts {
		if k.TokenID() == tok.ID {
			return k, true
		}
	}
	return 0, false
}

// ---------------------------------------------------------------------------
// Combinator engine
// ---------------------------------------------------------------------------

type bookmark struct{ tok, out int }

func (p *Parser) mark() bookmark {
	return bookmark{tok: p.tokens.bookmark(), out: p.out.bookmark()}
}

func (p *Parser) restore(b bookmark) {
	p.tokens.restore(b.tok)
	p.out.truncate(b.out)
}

func (p *Parser) unmark(b bookmark) { p.tokens.removeBookmark(b.tok) }

func (p *Parser) failed() bool {
	return p.state == stFailure || p.state == stOutOfFuel
}

// setState changes state, except that stOutOfFuel is permanent.
func (p *Parser) setState(s pstate) {
	if p.state != stOutOfFuel {
		p.state = s
	}
}

// begin opens a non-terminal, first flushing any pending trivia so that
// whitespace before a node is attached outside it rather than inside.
func (p *Parser) begin(kind SyntaxKind) *Parser {
	p.trivia()
	if p.fuel > 0 {
		p.fuel--
	} else {
		p.state = stOutOfFuel
	}
	p.out.begin(kind)
	return p
}

// end closes the node opened by begin. On failure the node is relabelled
// ERROR, and the diagnostic is emitted unless an enclosing opt/alt is going
// to absorb the failure anyway.
func (p *Parser) end() *Parser {
	if p.failed() {
		if p.optDepth == 0 {
			p.handleErrors()
		}
		p.out.endWithError()
	} else {
		p.out.end()
	}
	return p
}

// bump consumes one token and emits it with its natural kind.
func (p *Parser) bump() {
	if tok, ok := p.tokens.next(); ok {
		p.out.pushToken(tok.ID.Kind(), tok.Span)
	}
}

// trivia consumes whitespace, newlines and comments, emitting them so the
// tree stays lossless.
func (p *Parser) trivia() *Parser {
	if p.failed() {
		return p
	}
	for {
		tok, ok := p.tokens.peek(0)
		if !ok || !tok.IsTrivia() {
			return p
		}
		p.bump()
	}
}

// expect consumes the next non-trivia token if it is in the set, and fails
// without consuming anything otherwise.
func (p *Parser) expect(set tokenSet) *Parser {
	return p.expectD(set, "")
}

// expectD is expect with a single description that replaces the per-token
// ones in diagnostics, so a long alternation can report "expecting
// expression" instead of listing twenty tokens.
func (p *Parser) expectD(set tokenSet, desc string) *Parser {
	if p.failed() {
		return p
	}

	var (
		span    Span
		tokID   = T_UNKNOWN
		matched SyntaxKind
		ok      bool
	)
	if tok, has := p.tokens.peekNonTrivia(); has {
		span, tokID = tok.Span, tok.ID
		matched, ok = set.contains(tok)
	} else {
		// At end of input, point at a zero-length span past the last byte
		// so the caret lands after the final token rather than on it.
		end := uint32(len(p.tokens.source()))
		span = Span{Start: end, End: end}
	}

	switch {
	case ok && p.notDepth > 0:
		// Inside a negative lookahead a match is what we did not want.
		p.recordUnexpected(span)
	case !ok && p.notDepth == 0:
		if desc != "" {
			p.addExpectedDesc(span, tokID, desc)
		} else {
			p.addExpectedSet(span, tokID, set)
		}
	}

	if ok {
		p.trivia()
		if tok, has := p.tokens.next(); has {
			p.out.pushToken(matched, tok.Span)
		}
	} else {
		p.setState(stFailure)
	}
	return p
}

// advanceErrCand moves the error-candidate high-water mark to span when it
// reaches further into the source, discarding the candidates accumulated at
// any earlier offset. It reports whether span is at or past the mark: a false
// result means span is behind it, so any candidate there is already
// unreachable (see expectedSlot) and should be dropped.
func (p *Parser) advanceErrCand(span Span) bool {
	switch {
	case !p.haveErrCand || span.Start > p.errMaxStart:
		p.expected = p.expected[:0]
		p.unexpected = p.unexpected[:0]
		p.errMaxStart = span.Start
		p.haveErrCand = true
	case span.Start < p.errMaxStart:
		return false
	}
	return true
}

// expectedSlot returns the index of the candidate for (span, tok),
// creating it if needed, or -1 if the candidate can never be reported.
//
// Speculative parsing records a candidate for every alternative it tries,
// and nearly all of them fail; on a real rule file that is hundreds of
// records per error site. But handleErrors reports only the candidate at
// the largest offset, so anything behind the current high-water mark is
// already unreachable and is dropped here instead of being built and then
// thrown away. When a larger offset appears, the earlier candidates become
// unreachable in turn and the list is reset.
func (p *Parser) expectedSlot(span Span, tok TokenID) int {
	if !p.advanceErrCand(span) {
		return -1
	}
	k := expKey{span: span, tok: tok}
	for i := range p.expected {
		if p.expected[i].key == k {
			return i
		}
	}
	p.expected = append(p.expected, expectedErr{key: k})
	return len(p.expected) - 1
}

// addExpectedSet records every token in set as acceptable at this position.
func (p *Parser) addExpectedSet(span Span, tok TokenID, set tokenSet) {
	i := p.expectedSlot(span, tok)
	if i < 0 {
		return
	}
	for _, k := range set {
		p.expected[i].add(k.TokenID().Description())
	}
}

// addExpectedDesc records a single description in place of a token list.
func (p *Parser) addExpectedDesc(span Span, tok TokenID, desc string) {
	if i := p.expectedSlot(span, tok); i >= 0 {
		p.expected[i].add(desc)
	}
}

func (p *Parser) recordUnexpected(span Span) {
	if !p.advanceErrCand(span) {
		return
	}
	for _, s := range p.unexpected {
		if s == span {
			return
		}
	}
	p.unexpected = append(p.unexpected, span)
}

// opt applies f, rewinding and clearing the failure if it does not match.
func (p *Parser) opt(f func(*Parser) *Parser) *Parser {
	if p.failed() {
		return p
	}
	b := p.mark()
	p.trivia()
	p.optDepth++
	f(p)
	p.optDepth--
	if p.state == stFailure {
		p.setState(stOK)
		p.restore(b)
	}
	p.unmark(b)
	return p
}

// optExpect is opt around a single expect.
func (p *Parser) optExpect(set tokenSet) *Parser {
	return p.opt(func(p *Parser) *Parser { return p.expect(set) })
}

// not inverts f's result and always rewinds, giving negative lookahead.
func (p *Parser) not(f func(*Parser) *Parser) *Parser {
	if p.failed() {
		return p
	}
	b := p.mark()
	p.trivia()
	p.notDepth++
	f(p)
	p.notDepth--
	switch p.state {
	case stOK:
		p.state = stFailure
	case stFailure:
		p.state = stOK
	}
	p.restore(b)
	p.unmark(b)
	return p
}

// ifNext applies f when the next non-trivia token is in set.
//
// Unlike opt this never backtracks, so it is the right choice when one token
// decides the branch. When the token does not match, the set is still
// recorded as expected, which improves the message if a later production
// fails at the same spot.
func (p *Parser) ifNext(set tokenSet, f func(*Parser) *Parser) *Parser {
	if p.failed() {
		return p
	}
	tok, ok := p.tokens.peekNonTrivia()
	if !ok {
		return p
	}
	if _, in := set.contains(tok); in {
		p.trivia()
		f(p)
		return p
	}
	p.addExpectedSet(tok.Span, tok.ID, set)
	return p
}

// cond is ifNext that also consumes the deciding token before applying f.
func (p *Parser) cond(set tokenSet, f func(*Parser) *Parser) *Parser {
	return p.ifNext(set, func(p *Parser) *Parser {
		return p.expect(set).then(f)
	})
}

// then applies f once, after trivia.
func (p *Parser) then(f func(*Parser) *Parser) *Parser {
	if p.failed() {
		return p
	}
	p.trivia()
	return f(p)
}

func (p *Parser) zeroOrMore(f func(*Parser) *Parser) *Parser {
	return p.nOrMore(0, f)
}

func (p *Parser) oneOrMore(f func(*Parser) *Parser) *Parser {
	return p.nOrMore(1, f)
}

// nOrMore requires n matches and then takes as many more as it can.
func (p *Parser) nOrMore(n int, f func(*Parser) *Parser) *Parser {
	if p.failed() {
		return p
	}
	for i := 0; i < n; i++ {
		p.trivia()
		f(p)
		if p.failed() {
			return p
		}
	}
	for {
		b := p.mark()
		p.trivia()
		p.optDepth++
		f(p)
		p.optDepth--
		if p.failed() {
			p.setState(stOK)
			p.restore(b)
			p.unmark(b)
			return p
		}
		p.unmark(b)
	}
}

// cached suppresses re-attempting a production that already failed at this
// token position.
//
// The expression grammar is deeply recursive and several alternatives begin
// by trying the same sub-production. Without this the parser re-derives the
// same failure repeatedly, which is what turns some rules into pathological
// cases.
func (p *Parser) cached(kind SyntaxKind, f func(*Parser) *Parser) *Parser {
	if p.failed() {
		return p
	}
	k := cacheKey{index: p.tokens.index(), kind: kind}
	if _, hit := p.cache[k]; hit {
		p.setState(stFailure)
		return p
	}
	f(p)
	if p.state == stFailure {
		p.cache[k] = struct{}{}
	}
	return p
}

// recover clears a failure and discards tokens until one in set is found.
//
// Everything skipped goes into an ERROR node, so no source is lost. Because
// set holds the tokens that can start the next construct, parsing resumes at
// a sane boundary instead of cascading.
func (p *Parser) recover(set tokenSet) *Parser {
	if p.state == stOutOfFuel {
		return p
	}
	wasOK := p.state == stOK
	p.setState(stOK)

	tok, ok := p.tokens.peekNonTrivia()
	if !ok {
		return p
	}
	_, inSet := set.contains(tok)

	// With no error recorded yet, say what could have appeared here.
	if len(p.pendingErrors) == 0 && !inSet {
		p.addExpectedSet(tok.Span, tok.ID, set)
	}
	if !wasOK || !inSet {
		p.handleErrors()
	}
	if !inSet {
		p.trivia()
		p.begin(ERROR)
		p.bump()
		for {
			t, ok := p.tokens.peekNonTrivia()
			if !ok {
				break
			}
			if _, in := set.contains(t); in {
				break
			}
			p.trivia()
			p.bump()
		}
		p.end()
	}
	return p
}

// alt drives an ordered choice: the first alternative that matches wins and
// the rest are skipped.
type alt struct {
	p       *Parser
	matched bool
	b       bookmark
}

func (p *Parser) beginAlt() alt {
	return alt{p: p, b: p.mark()}
}

// alt is returned and taken by value so that it stays on the stack; an
// ordered choice is evaluated on nearly every production, so a heap
// allocation here would dominate.
func (a alt) alt(f func(*Parser) *Parser) alt {
	p := a.p
	if p.failed() || a.matched {
		return a
	}
	p.trivia()
	p.optDepth++
	f(p)
	p.optDepth--
	switch p.state {
	case stOK:
		a.matched = true
	case stFailure:
		p.setState(stOK)
		p.restore(a.b)
	}
	return a
}

func (a alt) endAlt() *Parser {
	p := a.p
	p.unmark(a.b)
	if a.matched {
		p.setState(stOK)
	} else {
		p.setState(stFailure)
	}
	return p
}

// ---------------------------------------------------------------------------
// Diagnostics
// ---------------------------------------------------------------------------

func (p *Parser) flushErrors() {
	for _, e := range p.pendingErrors {
		p.out.pushError(e.msg, e.span)
	}
	p.pendingErrors = p.pendingErrors[:0]
}

// handleErrors turns the accumulated candidate errors into one message.
//
// Many productions fail on the way to a successful parse, so most candidates
// are noise. The one furthest into the source is the most informative: it
// reflects the interpretation that got closest to working. Ties go to the
// most recently recorded.
func (p *Parser) handleErrors() {
	var (
		exp    *expectedErr
		unexp  Span
		hasUn  bool
		hasExp bool
	)
	for i := range p.expected {
		if e := &p.expected[i]; !hasExp || e.key.span.Start >= exp.key.span.Start {
			exp, hasExp = e, true
		}
	}
	for _, s := range p.unexpected {
		if !hasUn || s.Start >= unexp.Start {
			unexp, hasUn = s, true
		}
	}
	// The chosen candidate is copied out before the lists are reset,
	// because exp points into p.expected.
	var chosen expectedErr
	if hasExp {
		chosen = *exp
		exp = &chosen
	}
	p.expected = p.expected[:0]
	p.unexpected = p.unexpected[:0]
	p.haveErrCand = false
	p.errMaxStart = 0

	var (
		span     Span
		withExp  *expectedErr
		haveWith bool
	)
	switch {
	case hasExp && hasUn && unexp.Start > exp.key.span.Start:
		span = unexp
	case !hasExp && hasUn:
		span = unexp
	case hasExp:
		span, withExp, haveWith = exp.key.span, exp, true
	default:
		return
	}

	// One message per position is enough; the first is the most specific.
	for _, e := range p.pendingErrors {
		if e.span == span {
			return
		}
	}

	src := p.tokens.source()
	var found string
	if int(span.End) <= len(src) {
		found = string(src[span.Start:span.End])
	}
	if !utf8.ValidString(found) {
		p.pendingErrors = append(p.pendingErrors,
			pendingErr{span: span, msg: "invalid UTF-8 character"})
		return
	}

	p.pendingErrors = append(p.pendingErrors, pendingErr{
		span: span,
		msg:  errorMessage(found, withExp, haveWith),
	})
}

// maxQuotedLen is the longest offending text that is quoted back to the
// user. Beyond it the quote is dropped: a long token adds noise, and the
// span already locates the problem.
const maxQuotedLen = 15

func errorMessage(found string, exp *expectedErr, haveExp bool) string {
	if !haveExp {
		if found == "" {
			return "unexpected end of file"
		}
		return "unexpected `" + found + "`"
	}

	// An unrecognised token starting with a delimiter almost always means
	// the delimiter was never closed. Saying so is far more useful than
	// listing the tokens that could have followed.
	if exp.key.tok == T_UNKNOWN {
		switch {
		case strings.HasPrefix(found, "/*"):
			return "unclosed comment"
		case strings.HasPrefix(found, `"`):
			return "unclosed literal string"
		case strings.HasPrefix(found, "/"):
			return "unclosed regular expression"
		}
	}

	descs := exp.descs
	if len(descs) == 0 {
		return "unexpected `" + found + "`"
	}
	last := descs[len(descs)-1]
	rest := descs[:len(descs)-1]

	var b strings.Builder
	b.WriteString("expecting ")
	if len(rest) > 0 {
		b.WriteString(strings.Join(rest, ", "))
		b.WriteString(" or ")
	}
	b.WriteString(last)
	switch {
	case found == "":
		b.WriteString(", found end of file")
	case len(found) > maxQuotedLen:
		// Nothing appended: the span carries the location.
	default:
		b.WriteString(", found `")
		b.WriteString(found)
		b.WriteString("`")
	}
	return b.String()
}
