package compile

import (
	"fmt"
	"strings"

	"github.com/netstar-labs/yarrow"
	"github.com/netstar-labs/yarrow/pkg/scan"
)

// Scan runs every rule against data and returns the names of the rules that
// match, in declaration order. A global rule that does not match suppresses the
// whole set (YARA namespace semantics); private rules are evaluated but never
// reported.
func (rs *RuleSet) Scan(data []byte) ([]string, error) {
	mods := loadModules(rs.imports, data)
	states := make([]*scanState, len(rs.rules))
	for i, r := range rs.rules {
		st, ok, err := r.evalOn(data, mods)
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", r.name, err)
		}
		if r.global && !ok {
			return nil, nil // a failing global suppresses everything
		}
		states[i] = st
		st.matched = ok
	}
	var hits []string
	for i, r := range rs.rules {
		if states[i].matched && !r.private {
			hits = append(hits, r.name)
		}
	}
	return hits, nil
}

// scanState holds one rule's per-scan match results and file context.
type scanState struct {
	matches  map[string][]scan.Match // base pattern id → matches, ascending by start
	order    []string                // pattern ids in declaration order
	filesize int64
	modules  map[string]value // imported module objects, bound to the data
	matched  bool
}

func (r *rule) evalOn(data []byte, mods map[string]value) (*scanState, bool, error) {
	st := &scanState{
		matches:  make(map[string][]scan.Match, len(r.patterns)),
		filesize: int64(len(data)),
		modules:  mods,
	}
	for _, p := range r.patterns {
		st.matches[p.id] = p.matcher.FindAll(data)
		st.order = append(st.order, p.id)
	}
	v, err := st.eval(r.condition)
	if err != nil {
		return nil, false, err
	}
	return st, v.asBool(), nil
}

// value is a YARA condition value. An undefined value coerces to false in a
// boolean context and propagates through arithmetic/comparison. Beyond scalars it
// also models module namespaces: 'o' an object (named fields/methods), 'c' a
// callable (a module function), 'a' an array (indexable).
type value struct {
	kind byte // u i f b s o c a
	i    int64
	f    float64
	b    bool
	s    string
	obj  map[string]value
	call func([]value) (value, error)
	arr  []value
}

func undef() value                                { return value{kind: 'u'} }
func vInt(i int64) value                          { return value{kind: 'i', i: i} }
func vFloat(f float64) value                      { return value{kind: 'f', f: f} }
func vBool(b bool) value                          { return value{kind: 'b', b: b} }
func vStr(s string) value                         { return value{kind: 's', s: s} }
func vObj(m map[string]value) value               { return value{kind: 'o', obj: m} }
func vCall(fn func([]value) (value, error)) value { return value{kind: 'c', call: fn} }
func vArr(a []value) value                        { return value{kind: 'a', arr: a} }
func (v value) isUndef() bool                     { return v.kind == 'u' }

func (v value) asBool() bool {
	switch v.kind {
	case 'b':
		return v.b
	case 'i':
		return v.i != 0
	case 'f':
		return v.f != 0
	case 's':
		return v.s != ""
	default:
		return false
	}
}

// asFloat coerces an int/float to float; ok is false for other kinds.
func (v value) asFloat() (float64, bool) {
	switch v.kind {
	case 'i':
		return float64(v.i), true
	case 'f':
		return v.f, true
	default:
		return 0, false
	}
}

func (st *scanState) eval(e yarrow.Expr) (value, error) {
	switch x := e.(type) {
	case *yarrow.LiteralBool:
		return vBool(x.Value), nil
	case *yarrow.LiteralInteger:
		return vInt(x.Value), nil
	case *yarrow.LiteralFloat:
		return vFloat(x.Value), nil
	case *yarrow.LiteralString:
		return vStr(string(yarrow.DecodeStringLiteral(x.Literal))), nil
	case *yarrow.Filesize:
		return vInt(st.filesize), nil
	case *yarrow.Entrypoint:
		return undef(), nil // no module loaded → undefined
	case *yarrow.PatternMatch:
		return st.evalPatternMatch(x)
	case *yarrow.PatternCount:
		return st.evalPatternCount(x)
	case *yarrow.PatternOffsetLength:
		return st.evalOffsetLength(x)
	case *yarrow.UnaryExpr:
		return st.evalUnary(x)
	case *yarrow.BinaryExpr:
		return st.evalBinary(x)
	case *yarrow.NAryExpr:
		return st.evalNAry(x)
	case *yarrow.Of:
		return st.evalOf(x)
	case *yarrow.IdentExpr:
		if m, ok := st.modules[x.Name]; ok {
			return m, nil
		}
		return undef(), fmt.Errorf("unknown identifier %q (rule references and unimported modules are not supported)", x.Name)
	case *yarrow.FuncCall:
		return st.evalFuncCall(x)
	case *yarrow.Lookup:
		return st.evalLookup(x)
	case *yarrow.ForOf, *yarrow.ForIn, *yarrow.With:
		return undef(), fmt.Errorf("`for`/`with` expressions are not yet supported")
	case *yarrow.RegexpExpr:
		return undef(), fmt.Errorf("a bare regexp is only valid on the right of `matches`")
	default:
		return undef(), fmt.Errorf("unsupported expression %T", e)
	}
}

// evalFieldAccess walks a `.`-chain: the first operand is evaluated to an object,
// each subsequent operand is a field name looked up on it. An unknown field is
// undefined (not an error), matching YARA.
func (st *scanState) evalFieldAccess(x *yarrow.NAryExpr) (value, error) {
	v, err := st.eval(x.Operands[0])
	if err != nil {
		return undef(), err
	}
	for _, op := range x.Operands[1:] {
		if v.isUndef() {
			return undef(), nil
		}
		if v.kind != 'o' {
			return undef(), fmt.Errorf("field access on a non-object value")
		}
		id, ok := op.(*yarrow.IdentExpr)
		if !ok {
			return undef(), fmt.Errorf("field access operand is not an identifier")
		}
		fv, ok := v.obj[id.Name]
		if !ok {
			return undef(), nil // unknown field → undefined
		}
		v = fv
	}
	return v, nil
}

func (st *scanState) evalFuncCall(x *yarrow.FuncCall) (value, error) {
	if x.Object == nil {
		return undef(), fmt.Errorf("bare function call %q is not supported", x.Identifier.Name)
	}
	obj, err := st.eval(x.Object)
	if err != nil {
		return undef(), err
	}
	if obj.isUndef() {
		return undef(), nil
	}
	if obj.kind != 'o' {
		return undef(), fmt.Errorf("method call on a non-object value")
	}
	fn, ok := obj.obj[x.Identifier.Name]
	if !ok || fn.kind != 'c' {
		return undef(), fmt.Errorf("unknown method %q", x.Identifier.Name)
	}
	args := make([]value, len(x.Args))
	for i, a := range x.Args {
		if args[i], err = st.eval(a); err != nil {
			return undef(), err
		}
	}
	return fn.call(args)
}

func (st *scanState) evalLookup(x *yarrow.Lookup) (value, error) {
	prim, err := st.eval(x.Primary)
	if err != nil {
		return undef(), err
	}
	if prim.isUndef() {
		return undef(), nil
	}
	if prim.kind != 'a' {
		return undef(), fmt.Errorf("index of a non-array value")
	}
	idx, err := st.eval(x.Index)
	if err != nil {
		return undef(), err
	}
	if idx.kind != 'i' || idx.i < 0 || idx.i >= int64(len(prim.arr)) {
		return undef(), nil // out of range / non-int index → undefined
	}
	return prim.arr[idx.i], nil
}

func (st *scanState) matchesFor(name string) []scan.Match { return st.matches[baseID(name)] }

func (st *scanState) evalPatternMatch(x *yarrow.PatternMatch) (value, error) {
	ms := st.matchesFor(x.Identifier.Name)
	if x.Anchor == nil {
		return vBool(len(ms) > 0), nil
	}
	switch a := x.Anchor.(type) {
	case yarrow.AnchorAt:
		at, err := st.eval(a.Expr)
		if err != nil {
			return undef(), err
		}
		if at.isUndef() {
			return vBool(false), nil
		}
		for _, m := range ms {
			if int64(m.Start) == at.i {
				return vBool(true), nil
			}
		}
		return vBool(false), nil
	case yarrow.AnchorIn:
		lo, hi, ok, err := st.evalRange(a.Range)
		if err != nil {
			return undef(), err
		}
		if !ok {
			return undef(), nil // undefined range bound → undefined
		}
		for _, m := range ms {
			if int64(m.Start) >= lo && int64(m.Start) <= hi {
				return vBool(true), nil
			}
		}
		return vBool(false), nil
	}
	return vBool(false), nil
}

func (st *scanState) evalPatternCount(x *yarrow.PatternCount) (value, error) {
	ms := st.matchesFor(x.Identifier.Name)
	if x.Range == nil {
		return vInt(int64(len(ms))), nil
	}
	lo, hi, ok, err := st.evalRange(*x.Range)
	if err != nil {
		return undef(), err
	}
	if !ok {
		return undef(), nil
	}
	n := int64(0)
	for _, m := range ms {
		if int64(m.Start) >= lo && int64(m.Start) <= hi {
			n++
		}
	}
	return vInt(n), nil
}

func (st *scanState) evalOffsetLength(x *yarrow.PatternOffsetLength) (value, error) {
	ms := st.matchesFor(x.Identifier.Name)
	idx := int64(1)
	if x.Index != nil {
		iv, err := st.eval(x.Index)
		if err != nil {
			return undef(), err
		}
		if iv.kind != 'i' {
			return undef(), nil
		}
		idx = iv.i
	}
	if idx < 1 || idx > int64(len(ms)) {
		return undef(), nil // out of range → undefined
	}
	m := ms[idx-1]
	if x.IsLength {
		return vInt(int64(m.End - m.Start)), nil
	}
	return vInt(int64(m.Start)), nil
}

// evalRange evaluates a `(start..end)` range. ok is false when either bound is
// undefined (or not an integer): the range is then undefined, not 0..end — an
// undefined bound must not silently collapse to zero (which would make `$a in
// (pe.entry_point..filesize)` on a non-PE file match everywhere).
func (st *scanState) evalRange(r yarrow.Range) (lo, hi int64, ok bool, err error) {
	l, err := st.eval(r.Start)
	if err != nil {
		return 0, 0, false, err
	}
	h, err := st.eval(r.End)
	if err != nil {
		return 0, 0, false, err
	}
	if l.kind != 'i' || h.kind != 'i' {
		return 0, 0, false, nil
	}
	return l.i, h.i, true, nil
}

func (st *scanState) evalUnary(x *yarrow.UnaryExpr) (value, error) {
	v, err := st.eval(x.Operand)
	if err != nil {
		return undef(), err
	}
	switch x.Op {
	case yarrow.OpNot:
		return vBool(!v.asBool()), nil
	case yarrow.OpMinus:
		if v.kind == 'f' {
			return vFloat(-v.f), nil
		}
		if v.kind == 'i' {
			return vInt(-v.i), nil
		}
		return undef(), nil
	case yarrow.OpBitwiseNot:
		if v.kind == 'i' {
			return vInt(^v.i), nil
		}
		return undef(), nil
	case yarrow.OpDefined:
		return vBool(!v.isUndef()), nil
	}
	return undef(), nil
}

func (st *scanState) evalBinary(x *yarrow.BinaryExpr) (value, error) {
	if x.Op == yarrow.OpMatches {
		return st.evalMatches(x)
	}
	l, err := st.eval(x.LHS)
	if err != nil {
		return undef(), err
	}
	r, err := st.eval(x.RHS)
	if err != nil {
		return undef(), err
	}
	if l.isUndef() || r.isUndef() {
		return undef(), nil
	}
	switch x.Op {
	case yarrow.OpEq, yarrow.OpNe, yarrow.OpLt, yarrow.OpLe, yarrow.OpGt, yarrow.OpGe:
		return compare(x.Op, l, r), nil
	case yarrow.OpContains:
		return vBool(strings.Contains(l.s, r.s)), nil
	case yarrow.OpIContains:
		return vBool(strings.Contains(strings.ToLower(l.s), strings.ToLower(r.s))), nil
	case yarrow.OpStartsWith:
		return vBool(strings.HasPrefix(l.s, r.s)), nil
	case yarrow.OpIStartsWith:
		return vBool(strings.HasPrefix(strings.ToLower(l.s), strings.ToLower(r.s))), nil
	case yarrow.OpEndsWith:
		return vBool(strings.HasSuffix(l.s, r.s)), nil
	case yarrow.OpIEndsWith:
		return vBool(strings.HasSuffix(strings.ToLower(l.s), strings.ToLower(r.s))), nil
	case yarrow.OpIEquals:
		return vBool(strings.EqualFold(l.s, r.s)), nil
	case yarrow.OpBitwiseAnd:
		return vInt(l.i & r.i), nil
	case yarrow.OpBitwiseOr:
		return vInt(l.i | r.i), nil
	case yarrow.OpBitwiseXor:
		return vInt(l.i ^ r.i), nil
	case yarrow.OpShl:
		return vInt(l.i << uint(r.i)), nil
	case yarrow.OpShr:
		return vInt(l.i >> uint(r.i)), nil
	}
	return undef(), fmt.Errorf("unsupported binary operator")
}

// evalMatches handles `<string> matches /<regexp>/`.
func (st *scanState) evalMatches(x *yarrow.BinaryExpr) (value, error) {
	l, err := st.eval(x.LHS)
	if err != nil {
		return undef(), err
	}
	if l.isUndef() || l.kind != 's' {
		return undef(), nil
	}
	re, ok := x.RHS.(*yarrow.RegexpExpr)
	if !ok {
		return undef(), fmt.Errorf("`matches`: right operand must be a regexp literal")
	}
	prog, err := scan.Regexp(re.Regexp.Src, re.Regexp.CaseInsensitive, re.Regexp.DotMatchesNewLine)
	if err != nil {
		return undef(), err
	}
	return vBool(prog.Match([]byte(l.s))), nil
}

// compare evaluates a relational operator with int/float promotion (and string
// ordering for == / !=).
func compare(op yarrow.BinaryOp, l, r value) value {
	if l.kind == 's' && r.kind == 's' {
		switch op {
		case yarrow.OpEq:
			return vBool(l.s == r.s)
		case yarrow.OpNe:
			return vBool(l.s != r.s)
		}
	}
	lf, lok := l.asFloat()
	rf, rok := r.asFloat()
	if !lok || !rok {
		return undef()
	}
	switch op {
	case yarrow.OpEq:
		return vBool(lf == rf)
	case yarrow.OpNe:
		return vBool(lf != rf)
	case yarrow.OpLt:
		return vBool(lf < rf)
	case yarrow.OpLe:
		return vBool(lf <= rf)
	case yarrow.OpGt:
		return vBool(lf > rf)
	case yarrow.OpGe:
		return vBool(lf >= rf)
	}
	return undef()
}

func (st *scanState) evalNAry(x *yarrow.NAryExpr) (value, error) {
	switch x.Op {
	case yarrow.OpAnd:
		for _, op := range x.Operands {
			v, err := st.eval(op)
			if err != nil {
				return undef(), err
			}
			if !v.asBool() {
				return vBool(false), nil
			}
		}
		return vBool(true), nil
	case yarrow.OpOr:
		for _, op := range x.Operands {
			v, err := st.eval(op)
			if err != nil {
				return undef(), err
			}
			if v.asBool() {
				return vBool(true), nil
			}
		}
		return vBool(false), nil
	case yarrow.OpAdd, yarrow.OpSub, yarrow.OpMul, yarrow.OpDiv, yarrow.OpMod:
		return st.arith(x)
	case yarrow.OpFieldAccess:
		return st.evalFieldAccess(x)
	}
	return undef(), fmt.Errorf("unsupported n-ary operator")
}

func (st *scanState) arith(x *yarrow.NAryExpr) (value, error) {
	acc, err := st.eval(x.Operands[0])
	if err != nil {
		return undef(), err
	}
	for _, op := range x.Operands[1:] {
		v, err := st.eval(op)
		if err != nil {
			return undef(), err
		}
		if acc.isUndef() || v.isUndef() {
			return undef(), nil
		}
		// Integer arithmetic unless either side is float.
		if acc.kind == 'f' || v.kind == 'f' {
			af, _ := acc.asFloat()
			bf, _ := v.asFloat()
			acc = vFloat(applyFloat(x.Op, af, bf))
		} else {
			r, ok := applyInt(x.Op, acc.i, v.i)
			if !ok {
				return undef(), nil // division by zero → undefined
			}
			acc = vInt(r)
		}
	}
	return acc, nil
}

func applyInt(op yarrow.NAryOp, a, b int64) (int64, bool) {
	switch op {
	case yarrow.OpAdd:
		return a + b, true
	case yarrow.OpSub:
		return a - b, true
	case yarrow.OpMul:
		return a * b, true
	case yarrow.OpDiv:
		if b == 0 {
			return 0, false
		}
		return a / b, true
	case yarrow.OpMod:
		if b == 0 {
			return 0, false
		}
		return a % b, true
	}
	return 0, false
}

func applyFloat(op yarrow.NAryOp, a, b float64) float64 {
	switch op {
	case yarrow.OpAdd:
		return a + b
	case yarrow.OpSub:
		return a - b
	case yarrow.OpMul:
		return a * b
	case yarrow.OpDiv:
		return a / b
	}
	return 0
}

// evalOf handles `<quantifier> of <items> [anchor]`.
func (st *scanState) evalOf(x *yarrow.Of) (value, error) {
	sat, total, err := st.countSatisfied(x.Items, x.Anchor)
	if err != nil {
		return undef(), err
	}
	switch q := x.Quantifier.(type) {
	case yarrow.QuantifierKeyword:
		switch q.Kind {
		case yarrow.QuantAll:
			return vBool(sat == total), nil
		case yarrow.QuantAny:
			return vBool(sat >= 1), nil
		case yarrow.QuantNone:
			return vBool(sat == 0), nil
		}
	case yarrow.QuantifierExpr:
		n, err := st.eval(q.Expr)
		if err != nil {
			return undef(), err
		}
		if n.kind != 'i' {
			return undef(), nil // an undefined count → the whole `of` is undefined
		}
		return vBool(int64(sat) >= n.i), nil
	case yarrow.QuantifierPercentage:
		n, err := st.eval(q.Expr)
		if err != nil {
			return undef(), err
		}
		if n.kind != 'i' {
			return undef(), nil
		}
		return vBool(int64(sat)*100 >= n.i*int64(total)), nil
	}
	return undef(), fmt.Errorf("unsupported quantifier")
}

// countSatisfied returns how many of the of-items are satisfied and the total.
func (st *scanState) countSatisfied(items yarrow.OfItems, anchor yarrow.MatchAnchor) (sat, total int, err error) {
	switch it := items.(type) {
	case yarrow.PatternSetItems:
		ids := st.resolveSet(it)
		for _, id := range ids {
			ok, err := st.patternSatisfied(id, anchor)
			if err != nil {
				return 0, 0, err
			}
			if ok {
				sat++
			}
		}
		return sat, len(ids), nil
	case yarrow.BoolExprItems:
		for _, e := range it.Exprs {
			v, err := st.eval(e)
			if err != nil {
				return 0, 0, err
			}
			if v.asBool() {
				sat++
			}
		}
		return sat, len(it.Exprs), nil
	}
	return 0, 0, fmt.Errorf("unsupported of-items")
}

// resolveSet expands `them` or a list (with `$a*` wildcards) to base ids.
func (st *scanState) resolveSet(it yarrow.PatternSetItems) []string {
	if it.Them {
		return append([]string(nil), st.order...)
	}
	var ids []string
	for _, item := range it.Items {
		base := baseID(item.Identifier)
		if item.Wildcard {
			for _, id := range st.order {
				if strings.HasPrefix(id, base) {
					ids = append(ids, id)
				}
			}
		} else {
			ids = append(ids, base)
		}
	}
	return ids
}

func (st *scanState) patternSatisfied(id string, anchor yarrow.MatchAnchor) (bool, error) {
	pm := &yarrow.PatternMatch{Identifier: yarrow.Ident{Name: id}, Anchor: anchor}
	v, err := st.evalPatternMatch(pm)
	if err != nil {
		return false, err
	}
	return v.asBool(), nil
}
