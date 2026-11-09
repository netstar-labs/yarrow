package yarrow

import (
	"math"
	"strconv"
	"strings"
)

// maxASTDepth bounds recursion during lowering.
//
// The CST is already fuel-bounded, but lowering recurses independently and a
// deeply nested condition could still overflow the goroutine stack. Reaching
// the limit abandons the current rule rather than crashing.
const maxASTDepth = 3000 // matches YARA-X's Builder::MAX_AST_DEPTH exactly

// BuildAST lowers a CST event stream into an AST.
//
// The event stream is the same one Parser.Events produces. Lowering resolves
// operator precedence, flattens associative chains, and drops trivia, so the
// result is a semantic tree rather than a faithful copy of the source. Syntax
// errors carried by the stream are collected into AST.Errors; a rule that
// cannot be lowered is skipped and the remaining rules are still built.
func BuildAST(events []Event, src []byte) *AST {
	b := &builder{events: events, src: src}
	return b.run()
}

// ParseAST parses src straight to an AST.
func ParseAST(src []byte) (*AST, error) {
	if len(src) > MaxSpan {
		return nil, ErrSourceTooLarge
	}
	return BuildAST(NewParser(src).Events(), src), nil
}

// abortErr is a sentinel signalling that the current item cannot be lowered.
//
// It is a panic value rather than a returned error so that the deeply nested
// builder methods stay readable; run recovers it at the item boundary, mirroring
// the reference implementation's Result/Abort split without threading an error
// return through every method.
type abortErr struct{ maxDepth bool }

type builder struct {
	events []Event
	pos    int
	src    []byte
	errors []Diagnostic
	depth  int
	items  []Item
}

func (b *builder) run() *AST {
	ast := &AST{src: b.src}
	defer func() {
		ast.Items = b.items
		ast.Errors = b.errors
	}()
	b.mustBegin(SOURCE_FILE)
	for {
		ev := b.peek()
		switch {
		case ev.Kind == EventBegin && ev.Syntax == RULE_DECL:
			b.guarded(func() { b.items = append(b.items, b.ruleDecl()) })
		case ev.Kind == EventBegin && ev.Syntax == IMPORT_STMT:
			b.guarded(func() { b.items = append(b.items, b.importStmt()) })
		case ev.Kind == EventBegin && ev.Syntax == INCLUDE_STMT:
			b.guarded(func() { b.items = append(b.items, b.includeStmt()) })
		case ev.Kind == EventEnd && ev.Syntax == SOURCE_FILE:
			b.next()
			b.drainTrailingErrors()
			return ast
		default:
			b.recoverItem()
		}
	}
}

// guarded runs f, absorbing an abort by skipping to the next item.
func (b *builder) guarded(f func()) {
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(abortErr); ok {
				b.recoverItem()
				return
			}
			panic(r)
		}
	}()
	f()
}

// ---------------------------------------------------------------------------
// Event navigation
// ---------------------------------------------------------------------------

// peek returns the next event that is not a bare Error, skipping any Error
// events (diagnostics) and collecting them. A Begin(ERROR) node is *not*
// skipped: it marks unparsed source and forces an abort when a value is
// needed there.
func (b *builder) peek() Event {
	b.consumeErrors()
	return b.events[b.pos]
}

func (b *builder) consumeErrors() {
	for b.pos < len(b.events) {
		ev := b.events[b.pos]
		switch {
		case ev.Kind == EventError:
			b.errors = append(b.errors, Diagnostic{Message: ev.Message, Span: ev.Span})
			b.pos++
		case ev.Kind == EventToken && isTrivia(ev.Syntax):
			b.pos++
		default:
			return
		}
	}
}

// isTrivia reports whether a syntax kind is trivia in the CST stream.
func isTrivia(k SyntaxKind) bool {
	return k == WHITESPACE || k == NEWLINE || k == COMMENT
}

// next consumes the next event. Encountering a Begin(ERROR) aborts, because
// the builder has reached source the parser could not interpret.
func (b *builder) next() Event {
	if ev := b.peek(); ev.Kind == EventBegin && ev.Syntax == ERROR {
		panic(abortErr{})
	}
	ev := b.events[b.pos]
	b.pos++
	return ev
}

func (b *builder) mustBegin(kind SyntaxKind) {
	ev := b.next()
	if ev.Kind != EventBegin || ev.Syntax != kind {
		panic(abortErr{})
	}
	if b.depth == maxASTDepth {
		panic(abortErr{maxDepth: true})
	}
	b.depth++
}

func (b *builder) end(kind SyntaxKind) {
	ev := b.next()
	if ev.Kind != EventEnd || ev.Syntax != kind {
		panic(abortErr{})
	}
	if b.depth > 0 {
		b.depth--
	}
}

// expect consumes a token of the given kind and returns its span.
func (b *builder) expect(kind SyntaxKind) Span {
	ev := b.next()
	if ev.Kind != EventToken || ev.Syntax != kind {
		panic(abortErr{})
	}
	return ev.Span
}

// peekToken reports whether the next non-trivia event is a token of kind.
func (b *builder) peekToken(kind SyntaxKind) bool {
	ev := b.peek()
	return ev.Kind == EventToken && ev.Syntax == kind
}

// peekBegin reports whether the next event opens a node of kind.
func (b *builder) peekBegin(kind SyntaxKind) bool {
	ev := b.peek()
	return ev.Kind == EventBegin && ev.Syntax == kind
}

func (b *builder) text(sp Span) string {
	if int(sp.End) > len(b.src) {
		return ""
	}
	return string(b.src[sp.Start:sp.End])
}

// recoverItem discards events until the next item boundary, so one broken
// rule does not abort the whole file. It balances Begin/End depth to avoid
// stopping in the middle of a nested node.
func (b *builder) recoverItem() {
	// The reference's recover() resets the AST-depth counter to 0 on every
	// recovery. Without this, an item that aborts while deeply nested (the
	// end()-decrements are skipped by the panic unwind) leaks its depth into
	// the next item, which could then trip maxASTDepth and be wrongly dropped.
	b.depth = 0
	depth := 0
	for b.pos < len(b.events) {
		ev := b.events[b.pos]
		if ev.Kind == EventEnd && ev.Syntax == SOURCE_FILE && depth == 0 {
			return
		}
		b.pos++
		switch ev.Kind {
		case EventBegin:
			if depth == 0 && (ev.Syntax == RULE_DECL || ev.Syntax == IMPORT_STMT || ev.Syntax == INCLUDE_STMT) {
				// Reached the start of the next item; step back so run sees it.
				b.pos--
				return
			}
			depth++
		case EventEnd:
			if depth > 0 {
				depth--
			}
		case EventError:
			b.errors = append(b.errors, Diagnostic{Message: ev.Message, Span: ev.Span})
		}
	}
}

func (b *builder) drainTrailingErrors() {
	for b.pos < len(b.events) {
		ev := b.events[b.pos]
		if ev.Kind == EventError {
			b.errors = append(b.errors, Diagnostic{Message: ev.Message, Span: ev.Span})
		}
		b.pos++
	}
}

// ---------------------------------------------------------------------------
// Top-level items
// ---------------------------------------------------------------------------

func (b *builder) importStmt() Item {
	b.mustBegin(IMPORT_STMT)
	start := b.expect(IMPORT_KW)
	strSpan := b.expect(STRING_LIT)
	b.end(IMPORT_STMT)
	return &Import{Module: unquote(b.text(strSpan)), Span: combine(start, strSpan)}
}

func (b *builder) includeStmt() Item {
	b.mustBegin(INCLUDE_STMT)
	start := b.expect(INCLUDE_KW)
	strSpan := b.expect(STRING_LIT)
	b.end(INCLUDE_STMT)
	return &Include{Path: unquote(b.text(strSpan)), Span: combine(start, strSpan)}
}

func (b *builder) ruleDecl() Item {
	b.mustBegin(RULE_DECL)
	r := &Rule{}
	if b.peekBegin(RULE_MODS) {
		r.Flags = b.ruleMods()
	}
	kwSpan := b.expect(RULE_KW)
	r.Identifier = b.identifier()
	if b.peekBegin(RULE_TAGS) {
		r.Tags = b.ruleTags()
	}
	b.expect(L_BRACE)
	if b.peekBegin(META_BLK) {
		r.Meta = b.metaBlk()
	}
	if b.peekBegin(PATTERNS_BLK) {
		r.Patterns = b.patternsBlk()
	}
	b.mustBegin(CONDITION_BLK)
	b.expect(CONDITION_KW)
	b.expect(COLON)
	r.Condition = b.booleanExpr()
	b.end(CONDITION_BLK)
	endSpan := b.expect(R_BRACE)
	b.end(RULE_DECL)
	r.Span = combine(kwSpan, endSpan)
	return r
}

func (b *builder) ruleMods() RuleFlags {
	b.mustBegin(RULE_MODS)
	var flags RuleFlags
	for {
		ev := b.peek()
		if ev.Kind == EventToken && ev.Syntax == GLOBAL_KW {
			b.next()
			flags |= FlagGlobal
		} else if ev.Kind == EventToken && ev.Syntax == PRIVATE_KW {
			b.next()
			flags |= FlagPrivate
		} else {
			break
		}
	}
	b.end(RULE_MODS)
	return flags
}

func (b *builder) ruleTags() []Ident {
	b.mustBegin(RULE_TAGS)
	b.expect(COLON)
	var tags []Ident
	for b.peekToken(IDENT) {
		tags = append(tags, b.identifier())
	}
	b.end(RULE_TAGS)
	return tags
}

func (b *builder) metaBlk() []Meta {
	b.mustBegin(META_BLK)
	b.expect(META_KW)
	b.expect(COLON)
	var meta []Meta
	for b.peekBegin(META_DEF) {
		meta = append(meta, b.metaDef())
	}
	b.end(META_BLK)
	return meta
}

func (b *builder) metaDef() Meta {
	b.mustBegin(META_DEF)
	id := b.identifier()
	b.expect(EQUAL)
	neg := int64(1)
	if b.peekToken(MINUS) {
		b.expect(MINUS)
		neg = -1
	}
	var val MetaValue
	var end Span
	switch ev := b.peek(); ev.Syntax {
	case INTEGER_LIT:
		v, lit, sp := b.integerLit()
		val = MetaInteger{Value: neg * v, Literal: lit}
		end = sp
	case FLOAT_LIT:
		v, lit, sp := b.floatLit()
		val = MetaFloat{Value: float64(neg) * v, Literal: lit}
		end = sp
	case STRING_LIT:
		sp := b.expect(STRING_LIT)
		val = MetaString{Value: decodeMetaString(b.text(sp)), Literal: b.text(sp)}
		end = sp
	case TRUE_KW:
		end = b.expect(TRUE_KW)
		val = MetaBool{Value: true}
	case FALSE_KW:
		end = b.expect(FALSE_KW)
		val = MetaBool{Value: false}
	default:
		panic(abortErr{})
	}
	b.end(META_DEF)
	return Meta{Identifier: id, Value: val, Span: combine(id.Span, end)}
}

func (b *builder) patternsBlk() []Pattern {
	b.mustBegin(PATTERNS_BLK)
	b.expect(STRINGS_KW)
	b.expect(COLON)
	var pats []Pattern
	for b.peekBegin(PATTERN_DEF) {
		pats = append(pats, b.patternDef())
	}
	b.end(PATTERNS_BLK)
	return pats
}

func (b *builder) patternDef() Pattern {
	b.mustBegin(PATTERN_DEF)
	id := b.patternIdent()
	b.expect(EQUAL)
	var pat Pattern
	switch ev := b.peek(); {
	case ev.Kind == EventToken && ev.Syntax == STRING_LIT:
		sp := b.expect(STRING_LIT)
		mods := b.patternModsOpt()
		pat = &TextPattern{Identifier: id, Value: b.text(sp), Modifiers: mods, Span: combine(id.Span, sp)}
	case ev.Kind == EventToken && ev.Syntax == REGEXP:
		re := b.regexp()
		mods := b.patternModsOpt()
		pat = &RegexpPattern{Identifier: id, Regexp: re, Modifiers: mods, Span: combine(id.Span, re.Span)}
	case ev.Kind == EventBegin && ev.Syntax == HEX_PATTERN:
		hexSpan := ev.Span
		toks := b.hexPattern()
		mods := b.patternModsOpt()
		pat = &HexPattern{Identifier: id, Tokens: toks, Modifiers: mods, Span: hexSpan}
	default:
		panic(abortErr{})
	}
	b.end(PATTERN_DEF)
	return pat
}

func (b *builder) patternModsOpt() []PatternModifier {
	if b.peekBegin(PATTERN_MODS) {
		return b.patternMods()
	}
	return nil
}

func (b *builder) patternMods() []PatternModifier {
	b.mustBegin(PATTERN_MODS)
	var mods []PatternModifier
	for b.peekBegin(PATTERN_MOD) {
		b.mustBegin(PATTERN_MOD)
		ev := b.next()
		switch ev.Syntax {
		case ASCII_KW:
			mods = append(mods, PatternModifier{Kind: ModAscii, Span: ev.Span})
		case WIDE_KW:
			mods = append(mods, PatternModifier{Kind: ModWide, Span: ev.Span})
		case PRIVATE_KW:
			mods = append(mods, PatternModifier{Kind: ModPrivate, Span: ev.Span})
		case FULLWORD_KW:
			mods = append(mods, PatternModifier{Kind: ModFullword, Span: ev.Span})
		case NOCASE_KW:
			mods = append(mods, PatternModifier{Kind: ModNocase, Span: ev.Span})
		case XOR_KW:
			m := PatternModifier{Kind: ModXor, XorMin: 0, XorMax: 255, Span: ev.Span}
			if b.peekToken(L_PAREN) {
				b.expect(L_PAREN)
				start, _, _ := b.integerLitRange(0, 255) // xor keys are u8
				m.XorMin = start
				nx := b.next()
				switch nx.Syntax {
				case R_PAREN:
					// Single value: `xor(N)`.
					m.XorMax = start
					m.Span = combine(ev.Span, nx.Span)
				case HYPHEN:
					// Range: `xor(N-M)`.
					end, _, _ := b.integerLitRange(0, 255)
					m.XorMax = end
					m.Span = combine(ev.Span, b.expect(R_PAREN))
					m.HasXorRange = true
				default:
					panic(abortErr{})
				}
			}
			mods = append(mods, m)
		case BASE64_KW, BASE64WIDE_KW:
			kind := ModBase64
			if ev.Syntax == BASE64WIDE_KW {
				kind = ModBase64Wide
			}
			m := PatternModifier{Kind: kind, Span: ev.Span}
			if b.peekToken(L_PAREN) {
				b.expect(L_PAREN)
				sp := b.expect(STRING_LIT)
				m.Alphabet = b.text(sp)
				b.expect(R_PAREN)
			}
			mods = append(mods, m)
		default:
			panic(abortErr{})
		}
		b.end(PATTERN_MOD)
	}
	b.end(PATTERN_MODS)
	return mods
}

// ---------------------------------------------------------------------------
// Hex patterns
// ---------------------------------------------------------------------------

func (b *builder) hexPattern() HexSubPattern {
	b.mustBegin(HEX_PATTERN)
	b.expect(L_BRACE)
	sub := b.hexSubPattern()
	b.expect(R_BRACE)
	b.end(HEX_PATTERN)
	return sub
}

func (b *builder) hexSubPattern() HexSubPattern {
	b.mustBegin(HEX_SUB_PATTERN)
	var toks []HexToken
	for {
		ev := b.peek()
		switch {
		case ev.Kind == EventToken && ev.Syntax == HEX_BYTE:
			sp := b.expect(HEX_BYTE)
			toks = append(toks, decodeHexByte(b.text(sp), sp))
		case ev.Kind == EventBegin && ev.Syntax == HEX_ALTERNATIVE:
			toks = append(toks, b.hexAlternative())
		case ev.Kind == EventBegin && ev.Syntax == HEX_JUMP:
			toks = append(toks, b.hexJump())
		default:
			b.end(HEX_SUB_PATTERN)
			return toks
		}
	}
}

// decodeHexByte turns a hex-byte literal into value and mask.
//
// Each `?` nibble masks out its half of the byte. A leading `~` is recorded
// by widening the mask semantics elsewhere; here it only sets the negated
// flag via a sentinel, matching the reference's NotByte split at render time.
func decodeHexByte(lit string, sp Span) HexToken {
	negated := false
	if strings.HasPrefix(lit, "~") {
		negated = true
		lit = lit[1:]
	}
	var value, mask uint8 = 0x00, 0xFF
	high, low := lit[0], lit[1]
	if high == '?' {
		mask &= 0x0F
	} else {
		value |= hexNibble(high) << 4
	}
	if low == '?' {
		mask &= 0xF0
	} else {
		value |= hexNibble(low)
	}
	return HexByte{Value: value, Mask: mask, Span: sp, negated: negated}
}

func hexNibble(c byte) uint8 {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	return 0
}

func (b *builder) hexAlternative() HexToken {
	b.mustBegin(HEX_ALTERNATIVE)
	lp := b.expect(L_PAREN)
	alts := []HexSubPattern{b.hexSubPattern()}
	for b.peekToken(PIPE) {
		b.expect(PIPE)
		alts = append(alts, b.hexSubPattern())
	}
	rp := b.expect(R_PAREN)
	b.end(HEX_ALTERNATIVE)
	return HexAlternative{Alternatives: alts, Span: combine(lp, rp)}
}

func (b *builder) hexJump() HexToken {
	b.mustBegin(HEX_JUMP)
	lb := b.expect(L_BRACKET)
	var start, end *uint32
	if b.peekToken(INTEGER_LIT) {
		v, _, _ := b.integerLitRange(0, 4294967295) // hex jumps are u32
		u := uint32(v)
		start = &u
	}
	if b.peekToken(HYPHEN) {
		b.expect(HYPHEN)
		if b.peekToken(INTEGER_LIT) {
			v, _, _ := b.integerLitRange(0, 4294967295)
			u := uint32(v)
			end = &u
		}
	} else {
		end = start
	}
	rb := b.expect(R_BRACKET)
	b.end(HEX_JUMP)
	return HexJump{Start: start, End: end, Span: combine(lb, rb)}
}

// ---------------------------------------------------------------------------
// Expressions (Pratt parser)
// ---------------------------------------------------------------------------

// bindingPower returns the (left, right) binding powers for a binary
// operator token. Right power exceeds left by one for left-associative
// operators, so equal-precedence chains group left to right. The absolute
// values reproduce the reference precedence table exactly.
func bindingPower(k SyntaxKind) (left, right uint8, ok bool) {
	switch k {
	case OR_KW:
		return 1, 2, true
	case AND_KW:
		return 3, 4, true
	case EQ, NE, CONTAINS_KW, ICONTAINS_KW, STARTSWITH_KW, ISTARTSWITH_KW,
		ENDSWITH_KW, IENDSWITH_KW, IEQUALS_KW, MATCHES_KW:
		return 5, 6, true
	case LT, LE, GT, GE:
		return 7, 8, true
	case BITWISE_OR:
		return 9, 10, true
	case BITWISE_XOR:
		return 11, 12, true
	case BITWISE_AND:
		return 13, 14, true
	case SHL, SHR:
		return 15, 16, true
	case ADD, SUB:
		return 17, 18, true
	case MUL, DIV, MOD:
		return 19, 20, true
	case DOT:
		return 21, 22, true
	}
	return 0, 0, false
}

// pratt parses `parseOperand (operator parseOperand)*` into a precedence-
// correct tree. minBP is the minimum left binding power an operator must have
// to bind at this level; recursion with the operator's right power is what
// makes higher-precedence operators grab their operands first.
func (b *builder) pratt(parseOperand func() Expr, minBP uint8) Expr {
	lhs := parseOperand()
	for {
		ev := b.peek()
		if ev.Kind != EventToken {
			break
		}
		lbp, rbp, ok := bindingPower(ev.Syntax)
		if !ok || lbp < minBP {
			break
		}
		op := ev.Syntax
		b.next()
		rhs := b.pratt(parseOperand, rbp)
		lhs = b.combineOp(op, lhs, rhs)
	}
	return lhs
}

// combineOp builds (or extends) the AST node for a binary operator.
//
// Associative operators reuse an existing node of the same kind on the left,
// so `a + b + c` becomes one Add with three operands rather than nested
// pairs; this keeps the tree shallow and matches the reference's n-ary form.
// Non-associative operators always build a fresh two-operand node.
func (b *builder) combineOp(op SyntaxKind, lhs, rhs Expr) Expr {
	if nop, ok := nAryOp(op); ok {
		if existing, ok := lhs.(*NAryExpr); ok && existing.Op == nop {
			existing.Operands = append(existing.Operands, rhs)
			existing.Sp = combine(existing.Sp, rhs.span())
			return existing
		}
		return &NAryExpr{Op: nop, Operands: []Expr{lhs, rhs}, Sp: combine(lhs.span(), rhs.span())}
	}
	return &BinaryExpr{Op: binaryOp(op), LHS: lhs, RHS: rhs, Sp: combine(lhs.span(), rhs.span())}
}

func nAryOp(k SyntaxKind) (NAryOp, bool) {
	switch k {
	case OR_KW:
		return OpOr, true
	case AND_KW:
		return OpAnd, true
	case ADD:
		return OpAdd, true
	case SUB:
		return OpSub, true
	case MUL:
		return OpMul, true
	case DIV:
		return OpDiv, true
	case MOD:
		return OpMod, true
	case DOT:
		return OpFieldAccess, true
	}
	return 0, false
}

func binaryOp(k SyntaxKind) BinaryOp {
	switch k {
	case EQ:
		return OpEq
	case NE:
		return OpNe
	case LT:
		return OpLt
	case LE:
		return OpLe
	case GT:
		return OpGt
	case GE:
		return OpGe
	case CONTAINS_KW:
		return OpContains
	case ICONTAINS_KW:
		return OpIContains
	case STARTSWITH_KW:
		return OpStartsWith
	case ISTARTSWITH_KW:
		return OpIStartsWith
	case ENDSWITH_KW:
		return OpEndsWith
	case IENDSWITH_KW:
		return OpIEndsWith
	case IEQUALS_KW:
		return OpIEquals
	case MATCHES_KW:
		return OpMatches
	case BITWISE_OR:
		return OpBitwiseOr
	case BITWISE_XOR:
		return OpBitwiseXor
	case BITWISE_AND:
		return OpBitwiseAnd
	case SHL:
		return OpShl
	case SHR:
		return OpShr
	}
	panic(abortErr{})
}

func (b *builder) booleanExpr() Expr {
	b.mustBegin(BOOLEAN_EXPR)
	expr := b.pratt(b.booleanTerm, 0)
	b.end(BOOLEAN_EXPR)
	return expr
}

func (b *builder) booleanExprTuple() []Expr {
	b.mustBegin(BOOLEAN_EXPR_TUPLE)
	b.expect(L_PAREN)
	exprs := []Expr{b.booleanExpr()}
	for b.peekToken(COMMA) {
		b.expect(COMMA)
		exprs = append(exprs, b.booleanExpr())
	}
	b.expect(R_PAREN)
	b.end(BOOLEAN_EXPR_TUPLE)
	return exprs
}

func (b *builder) booleanTerm() Expr {
	b.mustBegin(BOOLEAN_TERM)
	var expr Expr
	switch ev := b.peek(); {
	case ev.Kind == EventToken && ev.Syntax == FALSE_KW:
		expr = &LiteralBool{Value: false, Sp: b.expect(FALSE_KW)}
	case ev.Kind == EventToken && ev.Syntax == TRUE_KW:
		expr = &LiteralBool{Value: true, Sp: b.expect(TRUE_KW)}
	case ev.Kind == EventToken && ev.Syntax == NOT_KW:
		sp := b.expect(NOT_KW)
		term := b.booleanTerm()
		expr = &UnaryExpr{Op: OpNot, Operand: term, Sp: combine(sp, term.span())}
	case ev.Kind == EventToken && ev.Syntax == DEFINED_KW:
		sp := b.expect(DEFINED_KW)
		term := b.booleanTerm()
		expr = &UnaryExpr{Op: OpDefined, Operand: term, Sp: combine(sp, term.span())}
	case ev.Kind == EventToken && ev.Syntax == L_PAREN:
		b.expect(L_PAREN)
		expr = b.booleanExpr()
		b.expect(R_PAREN)
	case ev.Kind == EventToken && ev.Syntax == PATTERN_IDENT:
		id := b.patternIdent()
		anchor := b.anchor()
		sp := id.Span
		if anchor != nil {
			sp = combine(sp, anchorSpan(anchor))
		}
		expr = &PatternMatch{Identifier: id, Anchor: anchor, Sp: sp}
	case ev.Kind == EventBegin && ev.Syntax == FOR_EXPR:
		expr = b.forExpr()
	case ev.Kind == EventBegin && ev.Syntax == OF_EXPR:
		expr = b.ofExpr()
	case ev.Kind == EventBegin && ev.Syntax == WITH_EXPR:
		expr = b.withExpr()
	case ev.Kind == EventBegin && ev.Syntax == EXPR:
		expr = b.pratt(b.expr, 0)
	default:
		panic(abortErr{})
	}
	b.end(BOOLEAN_TERM)
	return expr
}

func (b *builder) expr() Expr {
	b.mustBegin(EXPR)
	expr := b.pratt(b.term, 0)
	b.end(EXPR)
	return expr
}

func (b *builder) exprTuple() []Expr {
	b.mustBegin(EXPR_TUPLE)
	b.expect(L_PAREN)
	exprs := []Expr{b.expr()}
	for b.peekToken(COMMA) {
		b.expect(COMMA)
		exprs = append(exprs, b.expr())
	}
	b.expect(R_PAREN)
	b.end(EXPR_TUPLE)
	return exprs
}

func (b *builder) primaryExpr() Expr {
	b.mustBegin(PRIMARY_EXPR)
	var expr Expr
	switch ev := b.peek(); {
	case ev.Kind == EventBegin && ev.Syntax == FUNC_CALL:
		expr = b.funcCall(nil)
	case ev.Kind == EventToken && ev.Syntax == IDENT:
		id := b.identifier()
		expr = &IdentExpr{Name: id.Name, Sp: id.Span}
	default:
		panic(abortErr{})
	}
	if b.peekToken(L_BRACKET) {
		b.expect(L_BRACKET)
		index := b.expr()
		rb := b.expect(R_BRACKET)
		expr = &Lookup{Primary: expr, Index: index, Sp: combine(expr.span(), rb)}
	}
	b.end(PRIMARY_EXPR)
	return expr
}

func (b *builder) funcCall(object Expr) Expr {
	b.mustBegin(FUNC_CALL)
	id := b.identifier()
	b.expect(L_PAREN)
	var args []Expr
	for b.peekBegin(BOOLEAN_EXPR) {
		args = append(args, b.booleanExpr())
		if b.peekToken(COMMA) {
			b.expect(COMMA)
		}
	}
	rp := b.expect(R_PAREN)
	b.end(FUNC_CALL)
	sp := combine(id.Span, rp)
	if object != nil {
		sp = combine(object.span(), rp)
	}
	return &FuncCall{Object: object, Identifier: id, Args: args, Sp: sp}
}

func (b *builder) term() Expr {
	b.mustBegin(TERM)
	var expr Expr
	switch ev := b.peek(); ev.Syntax {
	case FLOAT_LIT:
		v, lit, sp := b.floatLit()
		expr = &LiteralFloat{Value: v, Literal: lit, Sp: sp}
	case INTEGER_LIT:
		v, lit, sp := b.integerLit()
		expr = &LiteralInteger{Value: v, Literal: lit, Sp: sp}
	case STRING_LIT:
		sp := b.expect(STRING_LIT)
		expr = &LiteralString{Literal: b.text(sp), Sp: sp}
	case REGEXP:
		re := b.regexp()
		expr = &RegexpExpr{Regexp: re, Sp: re.Span}
	case FILESIZE_KW:
		expr = &Filesize{Sp: b.expect(FILESIZE_KW)}
	case ENTRYPOINT_KW:
		expr = &Entrypoint{Sp: b.expect(ENTRYPOINT_KW)}
	case PATTERN_COUNT:
		sp := b.expect(PATTERN_COUNT)
		pc := &PatternCount{Identifier: Ident{Name: b.text(sp), Span: sp}, Sp: sp}
		if b.peekToken(IN_KW) {
			b.expect(IN_KW)
			rng := b.rangeExpr()
			pc.Range = &rng
			pc.Sp = combine(sp, rng.Sp)
		}
		expr = pc
	case PATTERN_OFFSET, PATTERN_LENGTH:
		isLen := ev.Syntax == PATTERN_LENGTH
		sp := b.expect(ev.Syntax)
		pol := &PatternOffsetLength{Identifier: Ident{Name: b.text(sp), Span: sp}, IsLength: isLen, Sp: sp}
		if b.peekToken(L_BRACKET) {
			b.expect(L_BRACKET)
			idx := b.expr()
			rb := b.expect(R_BRACKET)
			pol.Index = idx
			pol.Sp = combine(sp, rb)
		}
		expr = pol
	case BITWISE_NOT:
		sp := b.expect(BITWISE_NOT)
		operand := b.term()
		expr = &UnaryExpr{Op: OpBitwiseNot, Operand: operand, Sp: combine(sp, operand.span())}
	case MINUS:
		opSpan := b.expect(MINUS)
		operand := b.term()
		sp := combine(opSpan, operand.span())
		// `-<positive integer literal>` folds into a single negative
		// literal, but only when the operand is a bare literal (no
		// parentheses), so `-(1)` and `--1` are left as Minus nodes.
		if lit, ok := operand.(*LiteralInteger); ok && lit.Value >= 0 &&
			!strings.Contains(b.text(sp), "(") {
			lit.Value = -lit.Value
			lit.Literal = b.text(sp)
			lit.Sp = sp
			expr = lit
		} else {
			expr = &UnaryExpr{Op: OpMinus, Operand: operand, Sp: sp}
		}
	case L_PAREN:
		b.expect(L_PAREN)
		expr = b.expr()
		b.expect(R_PAREN)
	default:
		if ev.Kind == EventBegin && ev.Syntax == PRIMARY_EXPR {
			expr = b.dotChain()
		} else {
			panic(abortErr{})
		}
	}
	b.end(TERM)
	return expr
}

// dotChain parses `PRIMARY_EXPR (. PRIMARY_EXPR)*` and coalesces the parts.
//
// A run of dot-separated identifiers is a single field access, and a call or
// index at the end binds to the field access as its receiver. The coalescing
// rules below reproduce the reference so that `a.b.c` renders as one
// `field access` node and `a.b()` attaches `a.b` as the call's object.
func (b *builder) dotChain() Expr {
	parts := []Expr{b.primaryExpr()}
	for b.peekToken(DOT) {
		b.expect(DOT)
		parts = append(parts, b.primaryExpr())
	}
	return coalesceDots(parts)
}

func coalesceDots(parts []Expr) Expr {
	out := parts[:0:0]
	for _, y := range parts {
		if len(out) == 0 {
			out = append(out, y)
			continue
		}
		x := out[len(out)-1]
		if merged, ok := mergeDot(x, y); ok {
			out[len(out)-1] = merged
		} else {
			out = append(out, y)
		}
	}
	if len(out) == 1 {
		return out[0]
	}
	return &NAryExpr{Op: OpFieldAccess, Operands: out, Sp: combine(out[0].span(), out[len(out)-1].span())}
}

// mergeDot applies the coalescing rules for two adjacent dot operands,
// returning the merged expression or ok == false when they cannot merge.
func mergeDot(x, y Expr) (Expr, bool) {
	xi, xIsIdent := x.(*IdentExpr)
	_, yIsIdent := y.(*IdentExpr)
	switch {
	case xIsIdent && yIsIdent:
		return &NAryExpr{Op: OpFieldAccess, Operands: []Expr{x, y}, Sp: combine(x.span(), y.span())}, true
	case isFieldAccess(x) && yIsIdent:
		fa := x.(*NAryExpr)
		fa.Operands = append(fa.Operands, y)
		fa.Sp = combine(fa.Sp, y.span())
		return fa, true
	case isFieldAccess(x) && isFuncCall(y):
		fc := y.(*FuncCall)
		fc.Object = x
		fc.Sp = combine(x.span(), fc.Sp)
		return fc, true
	case xIsIdent && isFuncCall(y):
		fc := y.(*FuncCall)
		fc.Object = x
		fc.Sp = combine(x.span(), fc.Sp)
		return fc, true
	case xIsIdent && isLookup(y):
		lk := y.(*Lookup)
		lk.Primary = &NAryExpr{Op: OpFieldAccess, Operands: []Expr{x, lk.Primary}, Sp: combine(xi.span(), lk.Primary.span())}
		lk.Sp = combine(xi.span(), lk.Sp)
		return lk, true
	case isFieldAccess(x) && isLookup(y):
		fa := x.(*NAryExpr)
		lk := y.(*Lookup)
		fa.Operands = append(fa.Operands, lk.Primary)
		fa.Sp = combine(fa.Sp, lk.Primary.span())
		lk.Sp = combine(fa.Sp, lk.Sp)
		lk.Primary = fa
		return lk, true
	}
	return nil, false
}

func isFieldAccess(e Expr) bool {
	n, ok := e.(*NAryExpr)
	return ok && n.Op == OpFieldAccess
}
func isFuncCall(e Expr) bool { _, ok := e.(*FuncCall); return ok }
func isLookup(e Expr) bool   { _, ok := e.(*Lookup); return ok }

func (b *builder) anchor() MatchAnchor {
	switch {
	case b.peekToken(AT_KW):
		b.expect(AT_KW)
		return AnchorAt{Expr: b.expr()}
	case b.peekToken(IN_KW):
		b.expect(IN_KW)
		return AnchorIn{Range: b.rangeExpr()}
	}
	return nil
}

func anchorSpan(a MatchAnchor) Span {
	switch v := a.(type) {
	case AnchorAt:
		return v.Expr.span()
	case AnchorIn:
		return v.Range.Sp
	}
	return Span{}
}

func (b *builder) rangeExpr() Range {
	b.mustBegin(RANGE)
	lp := b.expect(L_PAREN)
	lo := b.expr()
	b.expect(DOT)
	b.expect(DOT)
	hi := b.expr()
	rp := b.expect(R_PAREN)
	b.end(RANGE)
	return Range{Start: lo, End: hi, Sp: combine(lp, rp)}
}

func (b *builder) forExpr() Expr {
	b.mustBegin(FOR_EXPR)
	forSpan := b.expect(FOR_KW)
	q := b.quantifier()
	var (
		patternSet *PatternSetItems
		iterable   Iterable
		variables  []Ident
	)
	switch {
	case b.peekToken(OF_KW):
		b.expect(OF_KW)
		ps := b.ofPatternSet()
		patternSet = &ps
	case b.peekToken(IDENT):
		for {
			variables = append(variables, b.identifier())
			nx := b.next()
			if nx.Syntax == COMMA {
				continue
			}
			if nx.Syntax == IN_KW {
				break
			}
			panic(abortErr{})
		}
		iterable = b.iterable()
	default:
		panic(abortErr{})
	}
	b.expect(COLON)
	b.expect(L_PAREN)
	body := b.booleanExpr()
	rp := b.expect(R_PAREN)
	b.end(FOR_EXPR)
	sp := combine(forSpan, rp)
	if patternSet != nil {
		return &ForOf{Quantifier: q, PatternSet: *patternSet, Condition: body, Sp: sp}
	}
	return &ForIn{Quantifier: q, Variables: variables, Iterable: iterable, Condition: body, Sp: sp}
}

func (b *builder) ofExpr() Expr {
	b.mustBegin(OF_EXPR)
	q := b.quantifier()
	b.expect(OF_KW)
	var items OfItems
	switch {
	case b.peekToken(THEM_KW):
		sp := b.expect(THEM_KW)
		items = PatternSetItems{Them: true, sp: sp}
	case b.peekBegin(PATTERN_IDENT_TUPLE):
		items = b.patternIdentTuple()
	case b.peekBegin(BOOLEAN_EXPR_TUPLE):
		items = BoolExprItems{Exprs: b.booleanExprTuple()}
	default:
		panic(abortErr{})
	}
	anchor := b.anchor()
	b.end(OF_EXPR)
	sp := combine(quantifierSpan(q), ofItemsSpan(items))
	if anchor != nil {
		sp = combine(sp, anchorSpan(anchor))
	}
	return &Of{Quantifier: q, Items: items, Anchor: anchor, Sp: sp}
}

func (b *builder) withExpr() Expr {
	b.mustBegin(WITH_EXPR)
	sp := b.expect(WITH_KW)
	b.mustBegin(WITH_DECLS)
	decl := func() WithDeclaration {
		b.mustBegin(WITH_DECL)
		id := b.identifier()
		s := combine(id.Span, b.expect(EQUAL))
		e := b.expr()
		s = combine(s, e.span())
		b.end(WITH_DECL)
		return WithDeclaration{Identifier: id, Expr: e, Span: s}
	}
	decls := []WithDeclaration{decl()}
	for b.peekToken(COMMA) {
		b.expect(COMMA)
		decls = append(decls, decl())
	}
	b.end(WITH_DECLS)
	b.expect(COLON)
	b.expect(L_PAREN)
	body := b.booleanExpr()
	rp := b.expect(R_PAREN)
	b.end(WITH_EXPR)
	return &With{Declarations: decls, Body: body, Sp: combine(sp, rp)}
}

func (b *builder) quantifier() Quantifier {
	b.mustBegin(QUANTIFIER)
	var q Quantifier
	switch ev := b.peek(); {
	case ev.Kind == EventToken && ev.Syntax == ALL_KW:
		b.expect(ALL_KW)
		q = QuantifierKeyword{Kind: QuantAll}
	case ev.Kind == EventToken && ev.Syntax == NONE_KW:
		b.expect(NONE_KW)
		q = QuantifierKeyword{Kind: QuantNone}
	case ev.Kind == EventToken && ev.Syntax == ANY_KW:
		b.expect(ANY_KW)
		q = QuantifierKeyword{Kind: QuantAny}
	case ev.Kind == EventBegin && ev.Syntax == TERM:
		e := b.term()
		b.expect(PERCENT)
		q = QuantifierPercentage{Expr: e}
	case ev.Kind == EventBegin && ev.Syntax == EXPR:
		q = QuantifierExpr{Expr: b.expr()}
	default:
		panic(abortErr{})
	}
	b.end(QUANTIFIER)
	return q
}

func (b *builder) iterable() Iterable {
	b.mustBegin(ITERABLE)
	var it Iterable
	switch {
	case b.peekBegin(RANGE):
		it = IterableRange{Range: b.rangeExpr()}
	case b.peekBegin(EXPR_TUPLE):
		it = IterableExprTuple{Exprs: b.exprTuple()}
	case b.peekBegin(EXPR):
		it = IterableExpr{Expr: b.expr()}
	default:
		panic(abortErr{})
	}
	b.end(ITERABLE)
	return it
}

// ofPatternSet parses the `them | (idents)` after `of` in a for expression.
func (b *builder) ofPatternSet() PatternSetItems {
	if b.peekToken(THEM_KW) {
		sp := b.expect(THEM_KW)
		return PatternSetItems{Them: true, sp: sp}
	}
	return b.patternIdentTuple()
}

func (b *builder) patternIdentTuple() PatternSetItems {
	b.mustBegin(PATTERN_IDENT_TUPLE)
	b.expect(L_PAREN)
	var items []PatternSetItem
	read := func() {
		sp := b.expect(PATTERN_IDENT)
		item := PatternSetItem{Identifier: b.text(sp), Span: sp}
		if b.peekToken(ASTERISK) {
			b.expect(ASTERISK)
			item.Wildcard = true
		}
		items = append(items, item)
	}
	read()
	for b.peekToken(COMMA) {
		b.expect(COMMA)
		read()
	}
	b.expect(R_PAREN)
	b.end(PATTERN_IDENT_TUPLE)
	return PatternSetItems{Items: items}
}

// ---------------------------------------------------------------------------
// Terminals
// ---------------------------------------------------------------------------

func (b *builder) identifier() Ident {
	sp := b.expect(IDENT)
	return Ident{Name: b.text(sp), Span: sp}
}

func (b *builder) patternIdent() Ident {
	sp := b.expect(PATTERN_IDENT)
	return Ident{Name: b.text(sp), Span: sp}
}

// integerLit parses an INTEGER_LIT as a signed 64-bit value (the width used by
// meta and expression integers), applying KB/MB multipliers, underscore
// separators, and 0x/0o radix prefixes. xor bounds and hex jumps need narrower
// widths — see integerLitRange.
func (b *builder) integerLit() (int64, string, Span) {
	return b.integerLitRange(math.MinInt64, math.MaxInt64)
}

// integerLitRange parses an INTEGER_LIT and range-checks the value to [lo, hi],
// mirroring the reference's integer_lit::<T>(): a value outside the range — or a
// literal that overflows int64, or a KB/MB multiply that does — records
// "this number is out of the valid range: [lo, hi]" and aborts the item, exactly
// as YARA-X does. xor bounds pass [0, 255] (u8); hex jumps pass [0, 4294967295]
// (u32); i64 callers pass the full range, for which the final bound is a no-op.
func (b *builder) integerLitRange(lo, hi int64) (int64, string, Span) {
	sp := b.expect(INTEGER_LIT)
	lit := b.text(sp)
	mult := int64(1)
	if s, ok := strings.CutSuffix(lit, "KB"); ok {
		// The reference strips the multiplier suffix from the stored
		// literal, so `1KB` renders as `1` while its value is 1024.
		lit = s
		mult = 1024
	} else if s, ok := strings.CutSuffix(lit, "MB"); ok {
		lit = s
		mult = 1024 * 1024
	}
	work := strings.ReplaceAll(lit, "_", "")

	outOfRange := func() {
		b.errors = append(b.errors, Diagnostic{
			Message: "this number is out of the valid range: [" +
				strconv.FormatInt(lo, 10) + ", " + strconv.FormatInt(hi, 10) + "]",
			Span: sp,
			Kind: DiagInvalidInteger,
		})
		panic(abortErr{})
	}

	var (
		v   int64
		err error
	)
	switch {
	case strings.HasPrefix(work, "0x"):
		v, err = strconv.ParseInt(work[2:], 16, 64)
	case strings.HasPrefix(work, "0o"):
		v, err = strconv.ParseInt(work[2:], 8, 64)
	default:
		v, err = strconv.ParseInt(work, 10, 64)
	}
	if err != nil {
		outOfRange()
	}
	if mult != 1 && (v > math.MaxInt64/mult || v < math.MinInt64/mult) {
		outOfRange()
	}
	val := v * mult
	if val < lo || val > hi {
		outOfRange()
	}
	return val, lit, sp
}

func (b *builder) floatLit() (float64, string, Span) {
	sp := b.expect(FLOAT_LIT)
	lit := b.text(sp)
	v, err := strconv.ParseFloat(strings.ReplaceAll(lit, "_", ""), 64)
	if err != nil {
		b.errors = append(b.errors, Diagnostic{Message: err.Error(), Span: sp})
		panic(abortErr{})
	}
	return v, lit, sp
}

func (b *builder) regexp() Regexp {
	sp := b.expect(REGEXP)
	re := b.text(sp)
	closing := strings.LastIndex(re, "/")
	var ci, dm bool
	for _, m := range re[closing+1:] {
		switch m {
		case 'i':
			ci = true
		case 's':
			dm = true
		default:
			b.errors = append(b.errors, Diagnostic{Message: string(m), Span: sp})
			panic(abortErr{})
		}
	}
	body := ""
	if closing > 0 {
		body = re[1:closing]
	}
	return Regexp{Src: body, CaseInsensitive: ci, DotMatchesNewLine: dm, Span: sp}
}

// unquote strips surrounding quotes from a string literal for display use.
// It does not process escape sequences; the raw literal is what the tree
// dump needs.
func unquote(s string) string {
	if strings.HasPrefix(s, `"""`) && strings.HasSuffix(s, `"""`) && len(s) >= 6 {
		return s[3 : len(s)-3]
	}
	if strings.HasPrefix(s, `"`) && strings.HasSuffix(s, `"`) && len(s) >= 2 {
		return s[1 : len(s)-1]
	}
	return s
}

// decodeMetaString strips a STRING_LIT's quotes and resolves the YARA escape
// sequences, mirroring the reference's string_lit + MetaValue: a literal with no
// backslash is the source substring verbatim (the borrowed / MetaValue::String
// case); one with escapes is decoded to bytes and rendered lossily as UTF-8 (the
// owned / MetaValue::Bytes case, whose BString Display replaces invalid UTF-8 with
// U+FFFD). Only meta values decode this way — pattern and condition literals keep
// their raw source form, which is why only meta strings diverged in differential
// testing. An invalid escape (which the reference reports as an error) is kept
// verbatim here so a stray sequence degrades gracefully rather than panicking.
func decodeMetaString(lit string) string {
	body := unquote(lit)
	if !strings.ContainsRune(body, '\\') {
		return body // borrowed: no escapes, identical to the source substring
	}
	// The reference renders the decoded bytes lossily as UTF-8 (its BString
	// Display); pattern matching, by contrast, needs the raw bytes — hence the
	// split between DecodeStringLiteral (raw) and this (rendered).
	return strings.ToValidUTF8(string(decodeEscapes(body)), "�")
}

// DecodeStringLiteral returns the raw decoded bytes of a YARA string literal —
// quotes stripped and escape sequences (\\ \" \n \r \t \0 \xNN) resolved. These
// are exactly the bytes a text pattern matches, so unlike meta rendering it does
// NOT apply lossy UTF-8 replacement. Used by the matcher (pkg/compile).
func DecodeStringLiteral(lit string) []byte { return decodeEscapes(unquote(lit)) }

// decodeEscapes resolves the YARA escape sequences in a quote-stripped literal
// body to raw bytes. A body with no backslash is returned verbatim. An invalid
// escape is kept verbatim (the reference reports it as an error; keeping it lets
// callers degrade gracefully).
func decodeEscapes(body string) []byte {
	if !strings.ContainsRune(body, '\\') {
		return []byte(body)
	}
	b := make([]byte, 0, len(body))
	for i := 0; i < len(body); i++ {
		if body[i] != '\\' || i+1 >= len(body) {
			b = append(b, body[i])
			continue
		}
		i++
		switch body[i] {
		case '\\':
			b = append(b, '\\')
		case 'n':
			b = append(b, '\n')
		case 'r':
			b = append(b, '\r')
		case 't':
			b = append(b, '\t')
		case '0':
			b = append(b, 0)
		case '"':
			b = append(b, '"')
		case 'x':
			if i+2 < len(body) && isHex(body[i+1]) && isHex(body[i+2]) {
				b = append(b, hexNibble(body[i+1])<<4|hexNibble(body[i+2]))
				i += 2
			} else {
				b = append(b, '\\', 'x')
			}
		default:
			b = append(b, '\\', body[i])
		}
	}
	return b
}

func quantifierSpan(q Quantifier) Span {
	switch v := q.(type) {
	case QuantifierExpr:
		return v.Expr.span()
	case QuantifierPercentage:
		return v.Expr.span()
	}
	return Span{}
}

func ofItemsSpan(items OfItems) Span {
	switch v := items.(type) {
	case PatternSetItems:
		if v.Them {
			return v.sp
		}
		if len(v.Items) > 0 {
			return combine(v.Items[0].Span, v.Items[len(v.Items)-1].Span)
		}
	case BoolExprItems:
		if len(v.Exprs) > 0 {
			return combine(v.Exprs[0].span(), v.Exprs[len(v.Exprs)-1].span())
		}
	}
	return Span{}
}
