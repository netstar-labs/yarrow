package yarrow

// EventKind distinguishes the four kinds of CST event.
type EventKind uint8

const (
	// EventBegin opens a non-terminal node.
	EventBegin EventKind = iota
	// EventEnd closes the most recently opened node.
	EventEnd
	// EventToken is a terminal, including trivia.
	EventToken
	// EventError carries a diagnostic. It does not open or close a node.
	EventError
)

// Event is one item in the flat stream the parser produces.
//
// Begin/End events nest and always balance, so the stream can be rebuilt
// into a tree without re-parsing. Token events appear in source order and
// cover the source exhaustively, which is what makes the tree lossless.
type Event struct {
	Kind    EventKind
	Syntax  SyntaxKind
	Span    Span
	Message string // set only when Kind is EventError
}

// syntaxStream accumulates events and supports speculative parsing.
//
// The parser explores alternatives that may fail, so the stream records
// bookmarks and can be truncated back to one. A node's span is not known
// when it opens, so Begin events are patched in place when the matching End
// arrives.
type syntaxStream struct {
	events []Event
	// openBegins holds indices of Begin events not yet closed, innermost last.
	openBegins []int
	// lastTokenSpan is the span of the most recent Token event, which
	// determines where the enclosing nodes end.
	lastTokenSpan Span
}

func (s *syntaxStream) pushToken(kind SyntaxKind, span Span) {
	s.lastTokenSpan = span
	s.events = append(s.events, Event{Kind: EventToken, Syntax: kind, Span: span})
}

func (s *syntaxStream) pushError(msg string, span Span) {
	s.events = append(s.events, Event{Kind: EventError, Span: span, Message: msg})
}

// begin opens a node starting where the last token ended. Any trivia between
// that point and the node's first token has already been emitted, so the
// node's start is corrected implicitly by the tokens it contains.
func (s *syntaxStream) begin(kind SyntaxKind) {
	pos := len(s.events)
	s.events = append(s.events, Event{
		Kind:   EventBegin,
		Syntax: kind,
		Span:   Span{Start: s.lastTokenSpan.End, End: s.lastTokenSpan.End},
	})
	s.openBegins = append(s.openBegins, pos)
}

// end closes the innermost open node, fixing up its span.
func (s *syntaxStream) end() {
	beginIdx := s.popBegin()
	if beginIdx < 0 {
		return
	}
	ev := &s.events[beginIdx]
	ev.Span.End = s.lastTokenSpan.End
	s.events = append(s.events, Event{
		Kind:   EventEnd,
		Syntax: ev.Syntax,
		Span:   ev.Span,
	})
}

// endWithError closes the innermost open node, relabelling it ERROR.
//
// A node that consumed nothing is dropped entirely rather than left as an
// empty ERROR, which keeps failed speculative parses out of the tree.
func (s *syntaxStream) endWithError() {
	beginIdx := s.popBegin()
	if beginIdx < 0 {
		return
	}
	if beginIdx == len(s.events)-1 {
		s.events = s.events[:beginIdx]
		return
	}
	ev := &s.events[beginIdx]
	ev.Syntax = ERROR
	ev.Span.End = s.lastTokenSpan.End
	s.events = append(s.events, Event{
		Kind:   EventEnd,
		Syntax: ERROR,
		Span:   ev.Span,
	})
}

func (s *syntaxStream) popBegin() int {
	n := len(s.openBegins)
	if n == 0 {
		return -1
	}
	idx := s.openBegins[n-1]
	s.openBegins = s.openBegins[:n-1]
	return idx
}

// bookmark records the current stream length for a later truncate.
func (s *syntaxStream) bookmark() int { return len(s.events) }

// truncate discards everything emitted since the bookmark and recomputes the
// last token span, so that nodes opened afterwards start in the right place.
func (s *syntaxStream) truncate(bookmark int) {
	if bookmark > len(s.events) {
		return
	}
	s.events = s.events[:bookmark]
	s.lastTokenSpan = Span{}
	for i := len(s.events) - 1; i >= 0; i-- {
		if s.events[i].Kind == EventToken {
			s.lastTokenSpan = s.events[i].Span
			break
		}
	}
	// Drop any Begin that the truncation removed.
	for len(s.openBegins) > 0 && s.openBegins[len(s.openBegins)-1] >= bookmark {
		s.openBegins = s.openBegins[:len(s.openBegins)-1]
	}
}

// mergeErrors collapses runs of adjacent ERROR nodes into one.
//
// A single mistake often trips several productions in a row: the enclosing
// rule fails, and then recovery skips ahead, each step emitting its own
// ERROR node. Reporting them separately would suggest several unrelated
// problems, so ERROR nodes that touch with nothing between them are joined.
func mergeErrors(events []Event) []Event {
	// Most files parse without a single ERROR node, so check before
	// building a second copy of the stream.
	hasError := false
	for _, e := range events {
		if e.Kind == EventBegin && e.Syntax == ERROR {
			hasError = true
			break
		}
	}
	if !hasError {
		return events
	}

	out := make([]Event, 0, len(events))
	var openBegins []int

	isErr := func(e Event, k EventKind) bool {
		return e.Kind == k && e.Syntax == ERROR
	}

	for i := 0; i < len(events); i++ {
		ev := events[i]
		switch {
		case isErr(ev, EventBegin):
			openBegins = append(openBegins, len(out))
			out = append(out, ev)

		case isErr(ev, EventEnd):
			if len(openBegins) == 0 {
				out = append(out, ev)
				continue
			}
			// Absorb the next error when it starts immediately.
			if i+1 < len(events) && isErr(events[i+1], EventBegin) {
				bi := openBegins[len(openBegins)-1]
				out[bi].Span.End = events[i+1].Span.End
				i++ // drop this End and the following Begin
				continue
			}
			bi := openBegins[len(openBegins)-1]
			openBegins = openBegins[:len(openBegins)-1]
			ev.Span = out[bi].Span
			out = append(out, ev)

		default:
			out = append(out, ev)
		}
	}
	return out
}
