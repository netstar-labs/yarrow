package yarrow

import (
	"strconv"
	"strings"
)

// asciiTree is the intermediate tree the AST is rendered through.
//
// It mirrors the `ascii_tree` crate the reference uses: a node is either a
// Leaf carrying one or more text lines, or a Node carrying a title and
// children. Rendering happens in two stages (AST to asciiTree, then
// asciiTree to string) because several node titles interleave synthetic
// labels like <quantifier> with real children, which is far clearer to build
// as an explicit tree than to stream directly.
type asciiTree struct {
	// leaf lines; non-nil means this is a leaf.
	leaf []string
	// title and children; used when leaf is nil.
	title    string
	children []asciiTree
}

func leaf(lines ...string) asciiTree { return asciiTree{leaf: lines} }
func node(title string, ch ...asciiTree) asciiTree {
	return asciiTree{title: title, children: ch}
}

// String renders the AST in the reference debug format: each rule as an
// ASCII tree followed by a blank line, then an ERRORS block if any errors
// were recorded. Imports and includes are not shown, matching the reference.
func (a *AST) String() string {
	var b strings.Builder
	for _, it := range a.Items {
		r, ok := it.(*Rule)
		if !ok {
			continue
		}
		writeTree(&b, ruleTree(r), "", true)
		b.WriteByte('\n')
	}
	if len(a.Errors) > 0 {
		b.WriteString("ERRORS:\n")
		for _, e := range a.Errors {
			b.WriteString("- ")
			b.WriteString(formatASTError(e))
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// formatASTError renders a diagnostic the way the reference's Error Debug does:
// the variant name (SyntaxError / InvalidInteger) then `{ message, span }`.
func formatASTError(d Diagnostic) string {
	var b strings.Builder
	if d.Kind == DiagInvalidInteger {
		b.WriteString(`InvalidInteger { message: `)
	} else {
		b.WriteString(`SyntaxError { message: `)
	}
	b.WriteString(quoteRust(d.Message))
	b.WriteString(`, span: Span(`)
	b.WriteString(strconv.FormatUint(uint64(d.Span.Start), 10))
	b.WriteString("..")
	b.WriteString(strconv.FormatUint(uint64(d.Span.End), 10))
	b.WriteString(") }")
	return b.String()
}

// writeTree renders one asciiTree. The `ascii_tree` crate prefixes the whole
// output with a single leading space, draws the last child with └─ and the
// rest with ├─, and continues sibling lines with │. Multi-line leaves indent
// their continuation lines to sit under the first.
func writeTree(b *strings.Builder, t asciiTree, prefix string, root bool) {
	if root {
		// The crate emits a leading space before the root title.
		b.WriteByte(' ')
		if t.leaf != nil {
			writeLeafLines(b, t.leaf, " ")
		} else {
			b.WriteString(t.title)
			b.WriteByte('\n')
			writeChildren(b, t.children, " ")
		}
		return
	}
	// Non-root nodes are written by writeChildren, which owns the
	// connector; this branch is unused but kept for symmetry.
}

// writeChildren draws each child of a node under the running prefix.
func writeChildren(b *strings.Builder, children []asciiTree, prefix string) {
	for i, c := range children {
		last := i == len(children)-1
		connector := "├─ "
		childPrefix := prefix + "│  "
		if last {
			connector = "└─ "
			childPrefix = prefix + "   "
		}
		b.WriteString(prefix)
		b.WriteString(connector)
		if c.leaf != nil {
			writeLeafLines(b, c.leaf, childPrefix)
		} else {
			b.WriteString(c.title)
			b.WriteByte('\n')
			writeChildren(b, c.children, childPrefix)
		}
	}
}

// writeLeafLines writes a leaf's lines. The first line is already positioned
// after the connector; continuation lines are indented by contPrefix so they
// align under the first character of the first line.
func writeLeafLines(b *strings.Builder, lines []string, contPrefix string) {
	for i, ln := range lines {
		if i > 0 {
			b.WriteString(contPrefix)
		}
		b.WriteString(ln)
		b.WriteByte('\n')
	}
}

// ---------------------------------------------------------------------------
// AST to asciiTree
// ---------------------------------------------------------------------------

func ruleTree(r *Rule) asciiTree {
	var children []asciiTree
	if len(r.Meta) > 0 {
		var metaLeaves []asciiTree
		for _, m := range r.Meta {
			metaLeaves = append(metaLeaves, leaf(m.Identifier.Name+" = "+metaValueString(m.Value)))
		}
		children = append(children, node("meta", metaLeaves...))
	}
	if len(r.Patterns) > 0 {
		var pats []asciiTree
		for _, p := range r.Patterns {
			pats = append(pats, patternTree(p))
		}
		children = append(children, node("strings", pats...))
	}
	children = append(children, node("condition", exprTree(r.Condition)))

	var mods []string
	if r.Flags.Has(FlagPrivate) {
		mods = append(mods, "private")
	}
	if r.Flags.Has(FlagGlobal) {
		mods = append(mods, "global")
	}
	title := "rule " + r.Identifier.Name
	if len(mods) > 0 {
		title = strings.Join(mods, " ") + " rule " + r.Identifier.Name
	}
	return node(title, children...)
}

// metaValueString formats a meta value as the reference Display does:
// booleans and integers verbatim, floats with one decimal place, strings
// wrapped in quotes.
func metaValueString(v MetaValue) string {
	switch m := v.(type) {
	case MetaBool:
		if m.Value {
			return "true"
		}
		return "false"
	case MetaInteger:
		return strconv.FormatInt(m.Value, 10)
	case MetaFloat:
		return formatFloat1(m.Value)
	case MetaString:
		return `"` + m.Value + `"`
	}
	return ""
}

// formatFloat1 renders a float with exactly one decimal place, matching
// Rust's {:.1} used by the reference for meta and literal floats.
func formatFloat1(f float64) string {
	return strconv.FormatFloat(f, 'f', 1, 64)
}

func patternTree(p Pattern) asciiTree {
	switch pat := p.(type) {
	case *TextPattern:
		return leaf(joinNonEmpty(pat.Identifier.Name+" = "+pat.Value, modifiersString(pat.Modifiers)))
	case *RegexpPattern:
		flags := ""
		if pat.Regexp.CaseInsensitive {
			flags += "i"
		}
		if pat.Regexp.DotMatchesNewLine {
			flags += "s"
		}
		re := "/" + pat.Regexp.Src + "/" + flags
		return leaf(joinNonEmpty(pat.Identifier.Name+" = "+re, modifiersString(pat.Modifiers)))
	case *HexPattern:
		title := joinNonEmpty(pat.Identifier.Name, modifiersString(pat.Modifiers))
		return node(title, hexTokensTree(pat.Tokens))
	}
	return leaf("")
}

// joinNonEmpty joins with a space, matching the reference which always
// appends the modifier string even when empty. The reference's format string
// leaves a trailing space when there are no modifiers, so this preserves it.
func joinNonEmpty(base, mods string) string {
	return base + " " + mods
}

// modifiersString renders a modifier list space-separated, in the reference's
// textual form (`xor(0-255)`, `base64("...")`, etc).
func modifiersString(mods []PatternModifier) string {
	parts := make([]string, 0, len(mods))
	for _, m := range mods {
		parts = append(parts, modifierString(m))
	}
	return strings.Join(parts, " ")
}

func modifierString(m PatternModifier) string {
	switch m.Kind {
	case ModAscii:
		return "ascii"
	case ModWide:
		return "wide"
	case ModNocase:
		return "nocase"
	case ModPrivate:
		return "private"
	case ModFullword:
		return "fullword"
	case ModBase64:
		if m.Alphabet != "" {
			return "base64(" + m.Alphabet + ")"
		}
		return "base64"
	case ModBase64Wide:
		if m.Alphabet != "" {
			return "base64wide(" + m.Alphabet + ")"
		}
		return "base64wide"
	case ModXor:
		switch {
		case m.XorMin == 0 && m.XorMax == 255 && !m.HasXorRange:
			// Bare `xor`, no parentheses in the source.
			return "xor"
		case !m.HasXorRange:
			// `xor(N)` single value.
			return "xor(" + strconv.FormatInt(m.XorMin, 10) + ")"
		default:
			return "xor(" + strconv.FormatInt(m.XorMin, 10) + "-" + strconv.FormatInt(m.XorMax, 10) + ")"
		}
	}
	return ""
}

// hexTokensTree renders a hex sub-pattern under a "hex" node. Bytes show as
// `0xNN mask: 0xNN`, negated bytes with a leading `~`, jumps as `[start-end]`,
// and alternatives recurse under an "alt" node.
func hexTokensTree(sub HexSubPattern) asciiTree {
	var nodes []asciiTree
	for _, t := range sub {
		switch tok := t.(type) {
		case HexByte:
			label := hexByteLabel(tok.Value) + " mask: " + hexByteLabel(tok.Mask)
			if tok.negated {
				label = "~ " + label
			}
			nodes = append(nodes, leaf(label))
		case HexAlternative:
			var alts []asciiTree
			for _, a := range tok.Alternatives {
				alts = append(alts, hexTokensTree(a))
			}
			nodes = append(nodes, node("alt", alts...))
		case HexJump:
			start, end := "", ""
			if tok.Start != nil {
				start = strconv.FormatUint(uint64(*tok.Start), 10)
			}
			if tok.End != nil {
				end = strconv.FormatUint(uint64(*tok.End), 10)
			}
			nodes = append(nodes, leaf("["+start+"-"+end+"]"))
		}
	}
	return node("hex", nodes...)
}

// hexByteLabel formats a byte as the reference's {:#04X}: `0x` followed by
// two uppercase hex digits.
func hexByteLabel(v uint8) string {
	const digits = "0123456789ABCDEF"
	return "0x" + string([]byte{digits[v>>4], digits[v&0xF]})
}

// ---------------------------------------------------------------------------
// Expression trees
// ---------------------------------------------------------------------------

func exprTree(e Expr) asciiTree {
	switch x := e.(type) {
	case *LiteralBool:
		if x.Value {
			return leaf("true")
		}
		return leaf("false")
	case *Filesize:
		return leaf("filesize")
	case *Entrypoint:
		return leaf("entrypoint")
	case *LiteralString:
		return leaf(x.Literal)
	case *LiteralInteger:
		return leaf(x.Literal)
	case *LiteralFloat:
		return leaf(x.Literal)
	case *RegexpExpr:
		flags := ""
		if x.Regexp.CaseInsensitive {
			flags += "i"
		}
		if x.Regexp.DotMatchesNewLine {
			flags += "s"
		}
		return leaf("/" + x.Regexp.Src + "/" + flags)
	case *IdentExpr:
		return leaf(x.Name)
	case *UnaryExpr:
		return node(unaryLabel(x.Op), exprTree(x.Operand))
	case *BinaryExpr:
		return node(binaryLabel(x.Op), exprTree(x.LHS), exprTree(x.RHS))
	case *NAryExpr:
		ch := make([]asciiTree, len(x.Operands))
		for i, o := range x.Operands {
			ch[i] = exprTree(o)
		}
		return node(nAryLabel(x.Op), ch...)
	case *Lookup:
		return node("<expr>[<index>]",
			node("<expr>", exprTree(x.Primary)),
			node("<index>", exprTree(x.Index)))
	case *FuncCall:
		return funcCallTree(x)
	case *PatternMatch:
		return patternMatchTree(x)
	case *PatternCount:
		if x.Range != nil {
			return node(x.Identifier.Name+" in <range>",
				node("<range>", exprTree(x.Range.Start), exprTree(x.Range.End)))
		}
		return leaf(x.Identifier.Name)
	case *PatternOffsetLength:
		if x.Index != nil {
			return node(x.Identifier.Name+"[<index>]",
				node("<index>", exprTree(x.Index)))
		}
		return leaf(x.Identifier.Name)
	case *Of:
		return ofTree(x)
	case *ForOf:
		return forOfTree(x)
	case *ForIn:
		return forInTree(x)
	case *With:
		return withTree(x)
	}
	return leaf("<unknown>")
}

func unaryLabel(op UnaryOp) string {
	switch op {
	case OpNot:
		return "not"
	case OpDefined:
		return "defined"
	case OpMinus:
		return "minus"
	case OpBitwiseNot:
		return "bitwise_not"
	}
	return "?"
}

func binaryLabel(op BinaryOp) string {
	switch op {
	case OpEq:
		return "eq"
	case OpNe:
		return "ne"
	case OpLt:
		return "lt"
	case OpLe:
		return "le"
	case OpGt:
		return "gt"
	case OpGe:
		return "ge"
	case OpContains:
		return "contains"
	case OpIContains:
		return "icontains"
	case OpStartsWith:
		return "startswith"
	case OpIStartsWith:
		return "istartswith"
	case OpEndsWith:
		return "endswith"
	case OpIEndsWith:
		return "iendswith"
	case OpIEquals:
		return "iequals"
	case OpMatches:
		return "matches"
	case OpBitwiseAnd:
		return "bitwise_and"
	case OpBitwiseOr:
		return "bitwise_or"
	case OpBitwiseXor:
		return "bitwise_xor"
	case OpShl:
		return "shl"
	case OpShr:
		return "shr"
	}
	return "?"
}

func nAryLabel(op NAryOp) string {
	switch op {
	case OpAnd:
		return "and"
	case OpOr:
		return "or"
	case OpAdd:
		return "add"
	case OpSub:
		return "sub"
	case OpMul:
		return "mul"
	case OpDiv:
		return "div"
	case OpMod:
		return "mod"
	case OpFieldAccess:
		return "field access"
	}
	return "?"
}

func funcCallTree(fc *FuncCall) asciiTree {
	var children []asciiTree
	if fc.Object != nil {
		children = append(children, node("<object>", exprTree(fc.Object)))
	}
	labels := make([]string, len(fc.Args))
	for i := range fc.Args {
		labels[i] = "<arg" + strconv.Itoa(i) + ">"
	}
	for i, a := range fc.Args {
		children = append(children, node(labels[i], exprTree(a)))
	}
	title := fc.Identifier.Name + "(" + strings.Join(labels, ", ") + ")"
	return node(title, children...)
}

// rangeNodes renders a range's bounds as the standard <start>/<end> node pair,
// the form used by every `in (start, end)` anchor in the dump.
func rangeNodes(r Range) []asciiTree {
	return []asciiTree{
		node("<start>", exprTree(r.Start)),
		node("<end>", exprTree(r.End)),
	}
}

func patternMatchTree(pm *PatternMatch) asciiTree {
	if pm.Anchor == nil {
		return leaf(pm.Identifier.Name)
	}
	switch a := pm.Anchor.(type) {
	case AnchorAt:
		return node(pm.Identifier.Name+" at <expr>",
			node("<expr>", exprTree(a.Expr)))
	case AnchorIn:
		return node(pm.Identifier.Name+" in (<start>, <end>)", rangeNodes(a.Range)...)
	}
	return leaf(pm.Identifier.Name)
}

func ofTree(of *Of) asciiTree {
	children := []asciiTree{node("<quantifier>", quantifierTree(of.Quantifier))}

	var itemsNode asciiTree
	switch it := of.Items.(type) {
	case PatternSetItems:
		itemsNode = node("<items: pattern_set>", patternSetTree(it))
	case BoolExprItems:
		ch := make([]asciiTree, len(it.Exprs))
		for i, e := range it.Exprs {
			ch[i] = exprTree(e)
		}
		itemsNode = node("<items: boolean_expr_set>", ch...)
	}
	children = append(children, itemsNode)

	title := "<quantifier> of <items>"
	if of.Anchor != nil {
		switch a := of.Anchor.(type) {
		case AnchorAt:
			children = append(children, node("<expr>", exprTree(a.Expr)))
			title = "<quantifier> of <items> at <expr>"
		case AnchorIn:
			children = append(children, rangeNodes(a.Range)...)
			title = "<quantifier> of <items> in (<start>..<end>)"
		}
	}
	return node(title, children...)
}

func forOfTree(f *ForOf) asciiTree {
	return node("for <quantifier> of <items> : ( <condition> )",
		node("<quantifier>", quantifierTree(f.Quantifier)),
		node("<items>", patternSetTree(f.PatternSet)),
		node("<condition>", exprTree(f.Condition)))
}

func forInTree(f *ForIn) asciiTree {
	children := []asciiTree{
		node("<quantifier>", quantifierTree(f.Quantifier)),
		node("<vars>", varsLeaf(f.Variables)),
	}
	var title string
	switch it := f.Iterable.(type) {
	case IterableRange:
		children = append(children, rangeNodes(it.Range)...)
		title = "for <quantifier> <vars> in (<start>..<end>) : ( <condition> )"
	case IterableExprTuple:
		labels := make([]string, len(it.Exprs))
		for i := range it.Exprs {
			labels[i] = "<expr" + strconv.Itoa(i) + ">"
		}
		for i, e := range it.Exprs {
			children = append(children, node(labels[i], exprTree(e)))
		}
		title = "for <quantifier> <vars> in (" + strings.Join(labels, ", ") + ") : ( <condition> )"
	case IterableExpr:
		children = append(children, node("<expr>", exprTree(it.Expr)))
		title = "for <quantifier> <vars> in <expr> : ( <condition> )"
	}
	children = append(children, node("<condition>", exprTree(f.Condition)))
	return node(title, children...)
}

// varsLeaf renders the loop variables as a single multi-line leaf, one
// variable per line, matching the reference which collects the names into one
// Leaf.
func varsLeaf(vars []Ident) asciiTree {
	lines := make([]string, len(vars))
	for i, v := range vars {
		lines[i] = v.Name
	}
	return leaf(lines...)
}

func withTree(w *With) asciiTree {
	var idChildren []asciiTree
	for _, d := range w.Declarations {
		idChildren = append(idChildren, leaf(d.Identifier.Name), exprTree(d.Expr))
	}
	return node("with <identifiers> : ( <boolean expression> )",
		node("<identifiers>", idChildren...),
		node("<boolean expression>", exprTree(w.Body)))
}

// quantifierTree renders a quantifier. `all`/`any`/`none` are leaves, an
// explicit expression renders as itself, and a percentage wraps its
// expression under a "percentage" node.
func quantifierTree(q Quantifier) asciiTree {
	switch v := q.(type) {
	case QuantifierKeyword:
		switch v.Kind {
		case QuantAll:
			return leaf("all")
		case QuantAny:
			return leaf("any")
		case QuantNone:
			return leaf("none")
		}
	case QuantifierExpr:
		return exprTree(v.Expr)
	case QuantifierPercentage:
		return node("percentage", exprTree(v.Expr))
	}
	return leaf("?")
}

func patternSetTree(ps PatternSetItems) asciiTree {
	if ps.Them {
		return leaf("them")
	}
	lines := make([]string, len(ps.Items))
	for i, it := range ps.Items {
		if it.Wildcard {
			lines[i] = it.Identifier + "*"
		} else {
			lines[i] = it.Identifier
		}
	}
	return leaf(lines...)
}
