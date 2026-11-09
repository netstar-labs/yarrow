package yarrow

// This file defines the abstract syntax tree produced by lowering a CST.
//
// The CST is lossless and mirrors the grammar; the AST is semantic. The two
// differ in three ways that matter:
//
//   - Operator precedence and associativity are resolved. The CST holds a
//     flat EXPR node with interleaved operator tokens; the AST holds a
//     proper tree, built by a Pratt parser, so `1 + 2 * 3` groups correctly.
//   - Associative chains are flattened. `a + b + c` becomes one Add node
//     with three operands rather than nested pairs, which keeps traversal
//     depth down.
//   - Trivia and delimiters are dropped. Whitespace, comments, parentheses
//     and commas leave no node behind; only meaning remains.
//
// The node set and the field names follow the YARA-X reference so that the
// rendered trees can be compared against it.

// Item is a top-level element of a source file: an import, an include, or a
// rule.
type Item interface{ isItem() }

func (*Import) isItem()  {}
func (*Include) isItem() {}
func (*Rule) isItem()    {}

// AST is a parsed source file: its items in source order, plus any syntax
// errors encountered. Errors do not stop AST construction; a broken rule is
// skipped and the rest are still lowered.
type AST struct {
	Items  []Item
	Errors []Diagnostic
	src    []byte
}

// Import is `import "module"`.
type Import struct {
	Module string
	Span   Span
}

// Include is `include "path"`.
type Include struct {
	Path string
	Span Span
}

// RuleFlags is the set of modifiers on a rule.
type RuleFlags uint8

const (
	// FlagPrivate marks a rule whose matches are not reported directly.
	FlagPrivate RuleFlags = 1 << iota
	// FlagGlobal marks a rule that must match for any rule in its
	// namespace to match.
	FlagGlobal
)

func (f RuleFlags) Has(flag RuleFlags) bool { return f&flag != 0 }

// Rule is a single rule declaration.
type Rule struct {
	Flags      RuleFlags
	Identifier Ident
	Tags       []Ident
	Meta       []Meta
	Patterns   []Pattern
	Condition  Expr
	Span       Span
}

// Ident is an identifier together with the source range it came from.
type Ident struct {
	Name string
	Span Span
}

// Meta is one `key = value` entry in a meta block.
type Meta struct {
	Identifier Ident
	Value      MetaValue
	Span       Span
}

// MetaValue is the value side of a meta entry: bool, integer, float or
// string. The concrete type carries the go value plus its source literal.
type MetaValue interface{ isMetaValue() }

// MetaBool is `true` or `false`.
type MetaBool struct{ Value bool }

// MetaInteger is a signed integer meta value.
type MetaInteger struct {
	Value   int64
	Literal string
}

// MetaFloat is a floating-point meta value.
type MetaFloat struct {
	Value   float64
	Literal string
}

// MetaString is a string meta value. Literal is the raw source form including
// quotes; Value is the escape-decoded value the reference renders (see
// decodeMetaString) — a literal with no escapes equals its source substring.
type MetaString struct {
	Value   string
	Literal string
}

func (MetaBool) isMetaValue()    {}
func (MetaInteger) isMetaValue() {}
func (MetaFloat) isMetaValue()   {}
func (MetaString) isMetaValue()  {}

// ---------------------------------------------------------------------------
// Patterns
// ---------------------------------------------------------------------------

// Pattern is a string, regexp or hex pattern definition, with its modifiers.
type Pattern interface {
	isPattern()
	Ident() Ident
}

// TextPattern is a literal-string pattern (`$a = "..."`).
type TextPattern struct {
	Identifier Ident
	Value      string
	Modifiers  []PatternModifier
	Span       Span
}

// RegexpPattern is a regular-expression pattern (`$a = /.../`).
type RegexpPattern struct {
	Identifier Ident
	Regexp     Regexp
	Modifiers  []PatternModifier
	Span       Span
}

// HexPattern is a hex pattern (`$a = { ... }`).
type HexPattern struct {
	Identifier Ident
	Tokens     HexSubPattern
	Modifiers  []PatternModifier
	Span       Span
}

func (*TextPattern) isPattern()       {}
func (*RegexpPattern) isPattern()     {}
func (*HexPattern) isPattern()        {}
func (p *TextPattern) Ident() Ident   { return p.Identifier }
func (p *RegexpPattern) Ident() Ident { return p.Identifier }
func (p *HexPattern) Ident() Ident    { return p.Identifier }

// PatternModifier is one modifier on a pattern (`ascii`, `xor(0-255)`, ...).
type PatternModifier struct {
	Kind PatternModifierKind
	// For base64/base64wide: the optional custom alphabet.
	Alphabet string
	// For xor: the inclusive range; XorMin==XorMax when a single value or
	// no range is given.
	XorMin, XorMax int64
	HasXorRange    bool
	Span           Span
}

// PatternModifierKind identifies a pattern modifier.
type PatternModifierKind uint8

const (
	ModAscii PatternModifierKind = iota
	ModWide
	ModNocase
	ModPrivate
	ModFullword
	ModBase64
	ModBase64Wide
	ModXor
)

// Regexp is a regular-expression literal with its flags.
type Regexp struct {
	Src               string // pattern body, without the slashes or flags
	CaseInsensitive   bool   // `i` flag
	DotMatchesNewLine bool   // `s` flag
	Span              Span
}

// HexSubPattern is a sequence of hex tokens.
type HexSubPattern []HexToken

// HexToken is one element of a hex pattern: a byte, a jump, or an
// alternation.
type HexToken interface{ isHexToken() }

// HexByte is a masked byte. Mask bits that are 1 are significant; `??`
// yields value 0, mask 0.
type HexByte struct {
	Value uint8
	Mask  uint8
	// negated is set for `~` bytes; it changes only the rendered label.
	negated bool
	Span    Span
}

// HexJump is `[n]`, `[n-m]`, `[n-]` or `[-m]`. A nil bound is unbounded.
type HexJump struct {
	Start *uint32
	End   *uint32
	Span  Span
}

// HexAlternative is `( a | b | ... )` inside a hex pattern.
type HexAlternative struct {
	Alternatives []HexSubPattern
	Span         Span
}

func (HexByte) isHexToken()        {}
func (HexJump) isHexToken()        {}
func (HexAlternative) isHexToken() {}

// ---------------------------------------------------------------------------
// Expressions
// ---------------------------------------------------------------------------

// Expr is a condition expression. The concrete types below distinguish the
// operators and forms.
type Expr interface {
	isExpr()
	// Span returns the source range the expression covers.
	span() Span
}

// LiteralBool is `true` or `false`.
type LiteralBool struct {
	Value bool
	Sp    Span
}

// Filesize is the `filesize` keyword.
type Filesize struct{ Sp Span }

// Entrypoint is the `entrypoint` keyword.
type Entrypoint struct{ Sp Span }

// LiteralString is a string literal used in a condition.
type LiteralString struct {
	Literal string
	Sp      Span
}

// LiteralInteger is an integer literal.
type LiteralInteger struct {
	Value   int64
	Literal string
	Sp      Span
}

// LiteralFloat is a float literal.
type LiteralFloat struct {
	Value   float64
	Literal string
	Sp      Span
}

// RegexpExpr is a regexp literal used in a condition.
type RegexpExpr struct {
	Regexp Regexp
	Sp     Span
}

// IdentExpr is a bare identifier reference.
type IdentExpr struct {
	Name string
	Sp   Span
}

// UnaryExpr is a one-operand operation (`not`, `defined`, `-`, `~`).
type UnaryExpr struct {
	Op      UnaryOp
	Operand Expr
	Sp      Span
}

// UnaryOp identifies a unary operator.
type UnaryOp uint8

const (
	OpNot UnaryOp = iota
	OpDefined
	OpMinus
	OpBitwiseNot
)

// BinaryExpr is a two-operand, non-associative operation (comparisons, shifts,
// bitwise and/or/xor). Associative operators use NAryExpr instead.
type BinaryExpr struct {
	Op       BinaryOp
	LHS, RHS Expr
	Sp       Span
}

// BinaryOp identifies a binary operator.
type BinaryOp uint8

const (
	OpEq BinaryOp = iota
	OpNe
	OpLt
	OpLe
	OpGt
	OpGe
	OpContains
	OpIContains
	OpStartsWith
	OpIStartsWith
	OpEndsWith
	OpIEndsWith
	OpIEquals
	OpMatches
	OpBitwiseAnd
	OpBitwiseOr
	OpBitwiseXor
	OpShl
	OpShr
)

// NAryExpr is an associative operation flattened to N operands (`and`, `or`,
// `+`, `-`, `*`, `\`, `%`, and field access `.`).
type NAryExpr struct {
	Op       NAryOp
	Operands []Expr
	Sp       Span
}

// NAryOp identifies an n-ary operator.
type NAryOp uint8

const (
	OpAnd NAryOp = iota
	OpOr
	OpAdd
	OpSub
	OpMul
	OpDiv
	OpMod
	OpFieldAccess
)

// Lookup is an index expression `primary[index]`.
type Lookup struct {
	Primary Expr
	Index   Expr
	Sp      Span
}

// FuncCall is `ident(args...)`, optionally with a receiver object
// (`obj.method(...)`).
type FuncCall struct {
	Object     Expr // nil when there is no receiver
	Identifier Ident
	Args       []Expr
	Sp         Span
}

// PatternMatch is a pattern-identifier expression, optionally anchored
// (`$a`, `$a at 100`, `$a in (0..10)`).
type PatternMatch struct {
	Identifier Ident
	Anchor     MatchAnchor // nil when unanchored
	Sp         Span
}

// MatchAnchor is `at <expr>` or `in <range>`.
type MatchAnchor interface{ isAnchor() }

// AnchorAt is `at <expr>`.
type AnchorAt struct{ Expr Expr }

// AnchorIn is `in (<start>..<end>)`.
type AnchorIn struct{ Range Range }

func (AnchorAt) isAnchor() {}
func (AnchorIn) isAnchor() {}

// Range is `(<start>..<end>)`.
type Range struct {
	Start Expr
	End   Expr
	Sp    Span
}

// PatternCount is `#a`, optionally with a range (`#a in (0..10)`).
type PatternCount struct {
	Identifier Ident
	Range      *Range
	Sp         Span
}

// PatternOffsetLength is `@a`/`!a`, optionally indexed (`@a[1]`). IsLength
// distinguishes the two.
type PatternOffsetLength struct {
	Identifier Ident
	Index      Expr // nil when not indexed
	IsLength   bool
	Sp         Span
}

// Of is `<quantifier> of <items> [anchor]`.
type Of struct {
	Quantifier Quantifier
	Items      OfItems
	Anchor     MatchAnchor
	Sp         Span
}

// OfItems is the item set of an `of` expression.
type OfItems interface{ isOfItems() }

// PatternSetItems is `them` or a list of pattern identifiers, possibly with
// `*` wildcards.
type PatternSetItems struct {
	Them  bool
	Items []PatternSetItem
	// sp is the span of the `them` keyword, when Them is set.
	sp Span
}

// BoolExprItems is a tuple of boolean expressions.
type BoolExprItems struct{ Exprs []Expr }

func (PatternSetItems) isOfItems() {}
func (BoolExprItems) isOfItems()   {}

// PatternSetItem is one entry in a pattern set, e.g. `$a` or `$a*`.
type PatternSetItem struct {
	Identifier string
	Wildcard   bool
	Span       Span
}

// ForOf is `for <quantifier> of <pattern_set> : ( <condition> )`.
type ForOf struct {
	Quantifier Quantifier
	PatternSet PatternSetItems
	Condition  Expr
	Sp         Span
}

// ForIn is `for <quantifier> <vars> in <iterable> : ( <condition> )`.
type ForIn struct {
	Quantifier Quantifier
	Variables  []Ident
	Iterable   Iterable
	Condition  Expr
	Sp         Span
}

// With is `with <decls> : ( <body> )`.
type With struct {
	Declarations []WithDeclaration
	Body         Expr
	Sp           Span
}

// WithDeclaration is one `ident = expr` in a with expression.
type WithDeclaration struct {
	Identifier Ident
	Expr       Expr
	Span       Span
}

// Quantifier is the quantity in a `for`/`of` expression.
type Quantifier interface{ isQuantifier() }

// QuantifierKeyword is `all`, `any` or `none`.
type QuantifierKeyword struct{ Kind QuantifierKind }

// QuantifierExpr is an explicit count (`3 of ...`).
type QuantifierExpr struct{ Expr Expr }

// QuantifierPercentage is a percentage (`51% of ...`).
type QuantifierPercentage struct{ Expr Expr }

func (QuantifierKeyword) isQuantifier()    {}
func (QuantifierExpr) isQuantifier()       {}
func (QuantifierPercentage) isQuantifier() {}

// QuantifierKind identifies a keyword quantifier.
type QuantifierKind uint8

const (
	QuantAll QuantifierKind = iota
	QuantAny
	QuantNone
)

// Iterable is the source of a `for ... in` loop.
type Iterable interface{ isIterable() }

// IterableRange is `(start..end)`.
type IterableRange struct{ Range Range }

// IterableExprTuple is `(e1, e2, ...)`.
type IterableExprTuple struct{ Exprs []Expr }

// IterableExpr is a single expression yielding an iterable value.
type IterableExpr struct{ Expr Expr }

func (IterableRange) isIterable()     {}
func (IterableExprTuple) isIterable() {}
func (IterableExpr) isIterable()      {}

// isExpr / span markers.
func (*LiteralBool) isExpr()         {}
func (*Filesize) isExpr()            {}
func (*Entrypoint) isExpr()          {}
func (*LiteralString) isExpr()       {}
func (*LiteralInteger) isExpr()      {}
func (*LiteralFloat) isExpr()        {}
func (*RegexpExpr) isExpr()          {}
func (*IdentExpr) isExpr()           {}
func (*UnaryExpr) isExpr()           {}
func (*BinaryExpr) isExpr()          {}
func (*NAryExpr) isExpr()            {}
func (*Lookup) isExpr()              {}
func (*FuncCall) isExpr()            {}
func (*PatternMatch) isExpr()        {}
func (*PatternCount) isExpr()        {}
func (*PatternOffsetLength) isExpr() {}
func (*Of) isExpr()                  {}
func (*ForOf) isExpr()               {}
func (*ForIn) isExpr()               {}
func (*With) isExpr()                {}

func (e *LiteralBool) span() Span         { return e.Sp }
func (e *Filesize) span() Span            { return e.Sp }
func (e *Entrypoint) span() Span          { return e.Sp }
func (e *LiteralString) span() Span       { return e.Sp }
func (e *LiteralInteger) span() Span      { return e.Sp }
func (e *LiteralFloat) span() Span        { return e.Sp }
func (e *RegexpExpr) span() Span          { return e.Sp }
func (e *IdentExpr) span() Span           { return e.Sp }
func (e *UnaryExpr) span() Span           { return e.Sp }
func (e *BinaryExpr) span() Span          { return e.Sp }
func (e *NAryExpr) span() Span            { return e.Sp }
func (e *Lookup) span() Span              { return e.Sp }
func (e *FuncCall) span() Span            { return e.Sp }
func (e *PatternMatch) span() Span        { return e.Sp }
func (e *PatternCount) span() Span        { return e.Sp }
func (e *PatternOffsetLength) span() Span { return e.Sp }
func (e *Of) span() Span                  { return e.Sp }
func (e *ForOf) span() Span               { return e.Sp }
func (e *ForIn) span() Span               { return e.Sp }
func (e *With) span() Span                { return e.Sp }

// combine returns the smallest span covering both a and b.
func combine(a, b Span) Span {
	return Span{Start: a.Start, End: b.End}
}
