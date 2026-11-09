// Package compile turns a parsed yarrow AST into a runnable RuleSet: each pattern
// becomes a pkg/scan matcher (literal/hex/regexp + modifiers) and the rule's
// condition is evaluated by a tree-walking VM (eval.go) over the match results.
//
// This is the end-to-end scanner MVP. Supported: text/hex/regexp patterns with
// nocase/wide/ascii/xor/fullword/base64/base64wide; conditions over booleans,
// arithmetic and comparisons, `$a`/`#a`/`@a`/`!a` (with `at`/`in` anchors and
// count ranges), `N of (...)`/`all|any|none of them`, `filesize`, and the
// hash/math/pe/elf modules. Not yet supported (a clear error, not a silent
// mismatch): `for`/`with` loops, `entrypoint`, and rule references by name.
package compile

import (
	"fmt"
	"strings"

	"github.com/netstar-labs/yarrow"
	"github.com/netstar-labs/yarrow/pkg/scan"
)

// RuleSet is a compiled set of rules ready to scan data.
type RuleSet struct {
	rules   []*rule
	imports []string // imported module names (import "pe", …)
}

type rule struct {
	name            string
	tags            []string
	private, global bool
	patterns        []patternDef
	condition       yarrow.Expr
}

type patternDef struct {
	id      string // base identifier, without the leading $
	matcher scan.Matcher
}

// Compile parses src and compiles every rule in it. It fails on a syntax error or
// an unsupported construct rather than silently producing a rule that cannot match
// what the author wrote.
func Compile(src []byte) (*RuleSet, error) {
	ast, err := yarrow.ParseAST(src)
	if err != nil {
		return nil, err
	}
	if len(ast.Errors) > 0 {
		d := ast.Errors[0]
		return nil, fmt.Errorf("compile: syntax error: %s at %d", d.Message, d.Span.Start)
	}
	rs := &RuleSet{}
	for _, item := range ast.Items {
		if imp, ok := item.(*yarrow.Import); ok {
			rs.imports = append(rs.imports, imp.Module)
			continue
		}
		r, ok := item.(*yarrow.Rule)
		if !ok {
			continue // include statements: nothing to compile
		}
		cr, err := compileRule(r)
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", r.Identifier.Name, err)
		}
		rs.rules = append(rs.rules, cr)
	}
	return rs, nil
}

func compileRule(r *yarrow.Rule) (*rule, error) {
	cr := &rule{
		name:      r.Identifier.Name,
		private:   r.Flags.Has(yarrow.FlagPrivate),
		global:    r.Flags.Has(yarrow.FlagGlobal),
		condition: r.Condition,
	}
	for _, t := range r.Tags {
		cr.tags = append(cr.tags, t.Name)
	}
	for _, p := range r.Patterns {
		m, err := compilePattern(p)
		if err != nil {
			return nil, err
		}
		cr.patterns = append(cr.patterns, patternDef{id: baseID(p.Ident().Name), matcher: m})
	}
	return cr, nil
}

func compilePattern(p yarrow.Pattern) (scan.Matcher, error) {
	switch p := p.(type) {
	case *yarrow.TextPattern:
		mods, err := textMods(p.Modifiers)
		if err != nil {
			return nil, err
		}
		return scan.CompileText(yarrow.DecodeStringLiteral(p.Value), mods), nil
	case *yarrow.HexPattern:
		elems, err := hexElements(p.Tokens)
		if err != nil {
			return nil, err
		}
		return scan.Compile(elems)
	case *yarrow.RegexpPattern:
		return scan.Regexp(p.Regexp.Src, p.Regexp.CaseInsensitive, p.Regexp.DotMatchesNewLine)
	default:
		return nil, fmt.Errorf("unsupported pattern kind %T", p)
	}
}

// textMods maps the AST modifier list to the engine's TextMods. base64/base64wide
// are not yet supported.
func textMods(mods []yarrow.PatternModifier) (scan.TextMods, error) {
	var m scan.TextMods
	for _, mod := range mods {
		switch mod.Kind {
		case yarrow.ModNocase:
			m.Nocase = true
		case yarrow.ModWide:
			m.Wide = true
		case yarrow.ModAscii:
			m.Ascii = true
		case yarrow.ModFullword:
			m.Fullword = true
		case yarrow.ModXor:
			m.Xor = true
			m.XorMin, m.XorMax = int(mod.XorMin), int(mod.XorMax)
			if !mod.HasXorRange {
				m.XorMin, m.XorMax = 0, 255
			}
		case yarrow.ModPrivate:
			// affects reporting only; no effect on matching
		case yarrow.ModBase64:
			m.Base64 = true
			m.Base64Alpha = mod.Alphabet
		case yarrow.ModBase64Wide:
			m.Base64Wide = true
			m.Base64Alpha = mod.Alphabet
		}
	}
	return m, nil
}

// hexElements maps a hex sub-pattern to the engine's Element vocabulary.
func hexElements(tokens yarrow.HexSubPattern) ([]scan.Element, error) {
	var out []scan.Element
	for _, tok := range tokens {
		switch t := tok.(type) {
		case yarrow.HexByte:
			switch t.Mask {
			case 0xFF:
				out = append(out, scan.Byte(t.Value))
			case 0x00:
				out = append(out, scan.AnyByte())
			default:
				out = append(out, scan.MaskedByte(t.Value, t.Mask))
			}
		case yarrow.HexJump:
			min := 0
			if t.Start != nil {
				min = int(*t.Start)
			}
			max := -1
			if t.End != nil {
				max = int(*t.End)
			}
			out = append(out, scan.Jump{Min: min, Max: max})
		case yarrow.HexAlternative:
			alts := make([][]scan.Element, 0, len(t.Alternatives))
			for _, sub := range t.Alternatives {
				e, err := hexElements(sub)
				if err != nil {
					return nil, err
				}
				alts = append(alts, e)
			}
			out = append(out, scan.Alt{Alts: alts})
		default:
			return nil, fmt.Errorf("unsupported hex token %T", tok)
		}
	}
	return out, nil
}

// baseID strips a leading pattern yarrow ($ # @ !) so a definition ($a) and its
// references (#a, @a, !a) share one key.
func baseID(name string) string {
	if len(name) > 0 && strings.IndexByte("$#@!", name[0]) >= 0 {
		return name[1:]
	}
	return name
}
