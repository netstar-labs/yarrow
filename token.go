// Package yarrow implements a parser for the YARA rule language.
//
// It is a port of the parser from YARA-X (github.com/VirusTotal/yara-x),
// reproducing its architecture: a three-mode tokenizer feeding an
// error-resilient PEG parser that emits a stream of events, from which a
// lossless concrete syntax tree (CST) and an abstract syntax tree (AST)
// are built.
//
// "Lossless" means every byte of the source is represented in the CST,
// including whitespace, newlines and comments. This makes the tree suitable
// for formatters, linters and language servers, not just compilation.
//
// The package depends only on the Go standard library.
package yarrow

// Span is a half-open byte range [Start, End) into the source.
//
// Offsets are byte offsets, not rune offsets, and are stored as uint32,
// which caps source size at MaxSpan.
type Span struct {
	Start uint32
	End   uint32
}

// MaxSpan is the largest source size the parser accepts.
const MaxSpan = 1<<32 - 1

// Len returns the number of bytes covered by the span.
func (s Span) Len() int { return int(s.End - s.Start) }

// Token is a lexical token: an identity plus its location in the source.
type Token struct {
	ID   TokenID
	Span Span
}

// IsTrivia reports whether the token carries no syntactic meaning.
//
// Trivia is preserved in the CST but skipped by the grammar rules.
func (t Token) IsTrivia() bool {
	return t.ID == T_NEWLINE || t.ID == T_WHITESPACE || t.ID == T_COMMENT
}
