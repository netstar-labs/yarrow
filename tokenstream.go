package yarrow

// tokenStream adds unbounded lookahead and rewinding on top of Tokenizer.
//
// A PEG parser tries alternatives in order and rewinds when one fails, so it
// needs to look arbitrarily far ahead and then go back. Tokens are pulled
// from the tokenizer on demand and buffered.
//
// Buffered tokens deliberately survive a tokenizer mode switch. The
// tokenizer's mode affects only tokens produced from that point on; anything
// already read stays as it was. The reference implementation behaves the
// same way, and matching it matters because the parser peeks before it
// decides to enter hex-pattern mode.
type tokenStream struct {
	tz *Tokenizer
	// buf holds tokens read from the tokenizer but not yet passed the
	// current position. Index i in buf is absolute index i+purged.
	buf []Token
	// pos is the absolute index of the next token to return.
	pos int
	// purged counts tokens dropped off the front of buf.
	purged int
	// bookmarks holds absolute indices that must remain reachable, sorted
	// ascending. The leftmost one bounds what may be purged.
	bookmarks []int
	// eof is set once the tokenizer is exhausted.
	eof bool
}

func newTokenStream(tz *Tokenizer) *tokenStream {
	return &tokenStream{tz: tz}
}

func (s *tokenStream) source() []byte { return s.tz.Source() }

// fill reads from the tokenizer until absolute index abs is buffered.
func (s *tokenStream) fill(abs int) {
	for !s.eof && abs-s.purged >= len(s.buf) {
		tok, ok := s.tz.Next()
		if !ok {
			s.eof = true
			return
		}
		s.buf = append(s.buf, tok)
	}
}

// peek returns the token n positions ahead without consuming it.
func (s *tokenStream) peek(n int) (Token, bool) {
	abs := s.pos + n
	s.fill(abs)
	i := abs - s.purged
	if i < 0 || i >= len(s.buf) {
		return Token{}, false
	}
	return s.buf[i], true
}

// peekNonTrivia returns the next token that is not whitespace, a newline or
// a comment, without consuming anything.
func (s *tokenStream) peekNonTrivia() (Token, bool) {
	for n := 0; ; n++ {
		tok, ok := s.peek(n)
		if !ok {
			return Token{}, false
		}
		if !tok.IsTrivia() {
			return tok, true
		}
	}
}

// next consumes and returns the next token.
func (s *tokenStream) next() (Token, bool) {
	tok, ok := s.peek(0)
	if !ok {
		return Token{}, false
	}
	s.pos++
	s.purge()
	return tok, true
}

// index returns the absolute position, used as a memoisation key.
func (s *tokenStream) index() int { return s.pos }

func (s *tokenStream) bookmark() int {
	s.bookmarks = append(s.bookmarks, s.pos)
	// Keep ascending order; a new bookmark is usually already the largest,
	// so this is an insertion into a nearly-sorted tail.
	for i := len(s.bookmarks) - 1; i > 0 && s.bookmarks[i-1] > s.bookmarks[i]; i-- {
		s.bookmarks[i-1], s.bookmarks[i] = s.bookmarks[i], s.bookmarks[i-1]
	}
	return s.pos
}

func (s *tokenStream) restore(bookmark int) { s.pos = bookmark }

func (s *tokenStream) removeBookmark(bookmark int) {
	// Bookmarks nest, so the one being dropped is almost always the last.
	if n := len(s.bookmarks); n > 0 && s.bookmarks[n-1] == bookmark {
		s.bookmarks = s.bookmarks[:n-1]
		return
	}
	for i, b := range s.bookmarks {
		if b == bookmark {
			s.bookmarks = append(s.bookmarks[:i], s.bookmarks[i+1:]...)
			return
		}
	}
}

// purge drops buffered tokens that can no longer be reached, which bounds
// memory on long inputs. Anything at or after the leftmost bookmark, or the
// current position when there are none, must be kept.
func (s *tokenStream) purge() {
	keep := s.pos
	if len(s.bookmarks) > 0 && s.bookmarks[0] < keep {
		keep = s.bookmarks[0]
	}
	n := keep - s.purged
	if n <= 0 {
		return
	}
	s.buf = append(s.buf[:0], s.buf[n:]...)
	s.purged += n
}
