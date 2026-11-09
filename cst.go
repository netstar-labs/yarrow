package yarrow

import (
	"errors"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Node is a node in the concrete syntax tree.
//
// A node is either a token (IsToken, no children) or a non-terminal. The
// tokens of a tree, read left to right, reconstruct the source exactly,
// including whitespace and comments.
type Node struct {
	Kind     SyntaxKind
	Span     Span
	IsToken  bool
	Children []*Node
}

// CST is a parsed source file plus any diagnostics produced along the way.
//
// Errors do not prevent a tree from being built. Root is always present.
type CST struct {
	Root   *Node
	Errors []Diagnostic
	src    []byte
}

// DiagKind selects which reference Error variant a diagnostic renders as in the
// AST dump. The zero value is a plain SyntaxError; an out-of-range integer
// literal is an InvalidInteger, matching YARA-X's typed Error enum.
type DiagKind uint8

const (
	DiagSyntaxError DiagKind = iota
	DiagInvalidInteger
)

// Diagnostic is a syntax error with the source range it refers to.
type Diagnostic struct {
	Message string
	Span    Span
	Kind    DiagKind
}

// ErrSourceTooLarge is returned for sources exceeding MaxSpan bytes.
var ErrSourceTooLarge = errors.New("yarrow: source exceeds maximum size")

// Parse parses src into a CST.
//
// A non-nil error means the source could not be parsed at all (only
// ErrSourceTooLarge today). Syntax errors are reported in CST.Errors, and
// the tree is still returned.
func Parse(src []byte) (*CST, error) {
	if len(src) > MaxSpan {
		return nil, ErrSourceTooLarge
	}
	return BuildCST(NewParser(src).Events(), src), nil
}

// BuildCST assembles a tree from an event stream.
//
// Exported so that callers who want the raw events (a formatter, say) can
// still get a tree without parsing twice.
func BuildCST(events []Event, src []byte) *CST {
	cst := &CST{src: src}
	var stack []*Node
	for _, ev := range events {
		switch ev.Kind {
		case EventBegin:
			n := &Node{Kind: ev.Syntax, Span: ev.Span}
			if len(stack) > 0 {
				parent := stack[len(stack)-1]
				parent.Children = append(parent.Children, n)
			}
			stack = append(stack, n)
		case EventEnd:
			if len(stack) == 0 {
				continue
			}
			n := stack[len(stack)-1]
			n.Span = ev.Span
			stack = stack[:len(stack)-1]
			if len(stack) == 0 {
				cst.Root = n
			}
		case EventToken:
			if len(stack) == 0 {
				continue
			}
			parent := stack[len(stack)-1]
			parent.Children = append(parent.Children, &Node{
				Kind: ev.Syntax, Span: ev.Span, IsToken: true,
			})
		case EventError:
			cst.Errors = append(cst.Errors, Diagnostic{
				Message: ev.Message, Span: ev.Span,
			})
		}
	}
	// An unbalanced stream would leave nodes open; keep the outermost so
	// callers always get a root.
	if cst.Root == nil && len(stack) > 0 {
		cst.Root = stack[0]
	}
	return cst
}

// Text returns the source text covered by the node.
func (c *CST) Text(n *Node) string {
	if int(n.Span.End) > len(c.src) {
		return ""
	}
	return string(c.src[n.Span.Start:n.Span.End])
}

// String renders the tree in the reference implementation's debug format:
// one node per line, two spaces of indent per level, each line carrying the
// kind and span, and tokens additionally carrying their quoted text.
func (c *CST) String() string {
	var b strings.Builder
	c.writeNode(&b, c.Root, 0)
	if len(c.Errors) > 0 {
		b.WriteString("\nERRORS:\n")
		for _, e := range c.Errors {
			b.WriteString("- [")
			b.WriteString(strconv.FormatUint(uint64(e.Span.Start), 10))
			b.WriteString("..")
			b.WriteString(strconv.FormatUint(uint64(e.Span.End), 10))
			b.WriteString("]: ")
			b.WriteString(e.Message)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func (c *CST) writeNode(b *strings.Builder, n *Node, depth int) {
	if n == nil {
		return
	}
	for i := 0; i < depth; i++ {
		b.WriteString("  ")
	}
	b.WriteString(n.Kind.String())
	b.WriteByte('@')
	b.WriteString(strconv.FormatUint(uint64(n.Span.Start), 10))
	b.WriteString("..")
	b.WriteString(strconv.FormatUint(uint64(n.Span.End), 10))
	if n.IsToken {
		b.WriteByte(' ')
		b.WriteString(quoteRust(truncateTokenText(c.Text(n))))
	}
	b.WriteByte('\n')
	for _, ch := range n.Children {
		c.writeNode(b, ch, depth+1)
	}
}

// FormatEvents renders an event stream in the reference debug format, one
// event per line. Used to compare against the reference implementation.
func FormatEvents(events []Event) string {
	var b strings.Builder
	for _, ev := range events {
		switch ev.Kind {
		case EventBegin:
			b.WriteString("Begin { kind: ")
			b.WriteString(ev.Syntax.String())
		case EventEnd:
			b.WriteString("End { kind: ")
			b.WriteString(ev.Syntax.String())
		case EventToken:
			b.WriteString("Token { kind: ")
			b.WriteString(ev.Syntax.String())
		case EventError:
			b.WriteString("Error { message: ")
			b.WriteString(quoteRust(ev.Message))
		}
		b.WriteString(", span: Span(")
		b.WriteString(strconv.FormatUint(uint64(ev.Span.Start), 10))
		b.WriteString("..")
		b.WriteString(strconv.FormatUint(uint64(ev.Span.End), 10))
		b.WriteString(") }\n")
	}
	return b.String()
}

// tokenTextLimit is the byte length at or above which a token's text is
// elided in a tree dump.
const tokenTextLimit = 25

// truncateTokenText shortens long token text for display.
//
// A block comment or a long string literal would otherwise swamp the tree
// dump, so text of tokenTextLimit bytes or more is cut short and marked with
// an ellipsis. The cut lands on the first UTF-8 boundary at or after offset
// 21, so a multi-byte rune is never split. This reproduces the reference
// implementation's output exactly, which is what lets the dumps be compared
// byte for byte.
func truncateTokenText(s string) string {
	if len(s) < tokenTextLimit {
		return s
	}
	for i := tokenTextLimit - 4; i < tokenTextLimit; i++ {
		if utf8.RuneStart(s[i]) {
			return s[:i] + " ..."
		}
	}
	// Unreachable for valid UTF-8: any four consecutive bytes contain at
	// least one rune start.
	return s
}

// quoteRust quotes s the way Rust's {:?} formats a string.
//
// Go's strconv.Quote is close but not identical: it escapes non-ASCII as
// \xNN or \uNNNN, whereas Rust uses \u{N} with no zero padding. The dumps
// are compared byte-for-byte against the reference, so the difference
// matters.
func quoteRust(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\t':
			b.WriteString(`\t`)
		case '\r':
			b.WriteString(`\r`)
		case '\n':
			b.WriteString(`\n`)
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\x00':
			b.WriteString(`\0`)
		default:
			if r < 0x20 || r == 0x7f || (r > 0x7f && !unicode.IsPrint(r)) ||
				r == utf8.RuneError {
				b.WriteString(`\u{`)
				b.WriteString(strconv.FormatUint(uint64(r), 16))
				b.WriteString(`}`)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}
