package yarrow

// This file is a direct transcription of the YARA grammar. Each function
// carries the production it implements in EBNF; the Go below should read as
// that production.

// Token sets used by more than one production, or long enough that naming
// them helps.
var (
	setTopLevelStart = tokenSet{GLOBAL_KW, PRIVATE_KW, RULE_KW, IMPORT_KW, INCLUDE_KW}
	setRuleStart     = tokenSet{GLOBAL_KW, PRIVATE_KW, RULE_KW}

	setComparisonOp = tokenSet{
		EQ, NE, LE, LT, GE, GT,
		CONTAINS_KW, ICONTAINS_KW,
		STARTSWITH_KW, ISTARTSWITH_KW,
		ENDSWITH_KW, IENDSWITH_KW,
		IEQUALS_KW, MATCHES_KW,
	}
	setArithBitwiseOp = tokenSet{
		ADD, SUB, MUL, DIV, MOD,
		SHL, SHR, BITWISE_AND, BITWISE_OR, BITWISE_XOR,
	}
	setTermLiteral = tokenSet{
		FLOAT_LIT, INTEGER_LIT, STRING_LIT, REGEXP,
		FILESIZE_KW, ENTRYPOINT_KW,
	}
	setSimplePatternMod = tokenSet{ASCII_KW, WIDE_KW, NOCASE_KW, PRIVATE_KW, FULLWORD_KW}
	setMetaLiteral      = tokenSet{STRING_LIT, TRUE_KW, FALSE_KW}
	setAtOrIn           = tokenSet{AT_KW, IN_KW}
	setAndOr            = tokenSet{AND_KW, OR_KW}
	setQuantifierKw     = tokenSet{ALL_KW, NONE_KW, ANY_KW}
)

// Descriptions used in place of long token lists.
const (
	descExpression = "expression"
	descOperator   = "operator"
	descPatternMod = "pattern modifier"
)

// topLevelItem parses one import, include or rule declaration.
//
// Anything else is swallowed into an ERROR node up to the next token that
// can start a rule, so one stray construct does not derail the whole file.
func (p *Parser) topLevelItem() *Parser {
	tok, ok := p.tokens.peek(0)
	if !ok {
		p.setState(stFailure)
		return p
	}
	switch tok.ID {
	case T_IMPORT_KW:
		return p.importStmt()
	case T_INCLUDE_KW:
		return p.includeStmt()
	case T_GLOBAL_KW, T_PRIVATE_KW, T_RULE_KW:
		return p.ruleDecl()
	}

	p.out.pushError("expecting import statement or rule definition", tok.Span)
	p.out.begin(ERROR)
	for {
		t, ok := p.tokens.peekNonTrivia()
		if !ok {
			break
		}
		if _, isRuleStart := setRuleStart.contains(t); isRuleStart {
			break
		}
		p.trivia()
		p.bump()
	}
	p.out.end()
	p.setState(stFailure)
	return p
}

// IMPORT_STMT := `import` STRING_LIT
func (p *Parser) importStmt() *Parser {
	return p.begin(IMPORT_STMT).
		expect(tokenSet{IMPORT_KW}).
		expect(tokenSet{STRING_LIT}).
		end()
}

// INCLUDE_STMT := `include` STRING_LIT
func (p *Parser) includeStmt() *Parser {
	return p.begin(INCLUDE_STMT).
		expect(tokenSet{INCLUDE_KW}).
		expect(tokenSet{STRING_LIT}).
		end()
}

// RULE_DECL := RULE_MODS? `rule` IDENT RULE_TAGS? `{`
//
//	META_BLK? PATTERNS_BLK? CONDITION_BLK
//
// `}`
func (p *Parser) ruleDecl() *Parser {
	return p.begin(RULE_DECL).
		opt((*Parser).ruleMods).
		expect(tokenSet{RULE_KW}).
		expect(tokenSet{IDENT}).
		ifNext(tokenSet{COLON}, (*Parser).ruleTags).
		expect(tokenSet{L_BRACE}).
		ifNext(tokenSet{META_KW}, (*Parser).metaBlk).
		ifNext(tokenSet{STRINGS_KW}, (*Parser).patternsBlk).
		then((*Parser).conditionBlk).
		expect(tokenSet{R_BRACE}).
		end().
		recover(setTopLevelStart)
}

// RULE_MODS := `private` `global`? | `global` `private`?
func (p *Parser) ruleMods() *Parser {
	return p.begin(RULE_MODS).
		beginAlt().
		alt(func(p *Parser) *Parser {
			return p.expect(tokenSet{PRIVATE_KW}).optExpect(tokenSet{GLOBAL_KW})
		}).
		alt(func(p *Parser) *Parser {
			return p.expect(tokenSet{GLOBAL_KW}).optExpect(tokenSet{PRIVATE_KW})
		}).
		endAlt().
		end()
}

// RULE_TAGS := `:` IDENT+
func (p *Parser) ruleTags() *Parser {
	return p.begin(RULE_TAGS).
		expect(tokenSet{COLON}).
		oneOrMore(func(p *Parser) *Parser { return p.expect(tokenSet{IDENT}) }).
		end().
		recover(tokenSet{L_BRACE})
}

// META_BLK := `meta` `:` META_DEF+
func (p *Parser) metaBlk() *Parser {
	return p.begin(META_BLK).
		expect(tokenSet{META_KW}).
		expect(tokenSet{COLON}).
		oneOrMore((*Parser).metaDef).
		end().
		recover(tokenSet{STRINGS_KW, CONDITION_KW})
}

// META_DEF := IDENT `=` ( `-`? (INTEGER_LIT | FLOAT_LIT) | STRING_LIT | `true` | `false` )
func (p *Parser) metaDef() *Parser {
	return p.begin(META_DEF).
		expect(tokenSet{IDENT}).
		expect(tokenSet{EQUAL}).
		beginAlt().
		alt(func(p *Parser) *Parser {
			return p.optExpect(tokenSet{MINUS}).expect(tokenSet{INTEGER_LIT, FLOAT_LIT})
		}).
		alt(func(p *Parser) *Parser { return p.expect(setMetaLiteral) }).
		endAlt().
		end()
}

// PATTERNS_BLK := `strings` `:` PATTERN_DEF+
func (p *Parser) patternsBlk() *Parser {
	return p.begin(PATTERNS_BLK).
		expect(tokenSet{STRINGS_KW}).
		expect(tokenSet{COLON}).
		oneOrMore((*Parser).patternDef).
		end().
		recover(tokenSet{CONDITION_KW})
}

// PATTERN_DEF := PATTERN_IDENT `=` ( STRING_LIT | REGEXP | HEX_PATTERN ) PATTERN_MODS?
func (p *Parser) patternDef() *Parser {
	return p.begin(PATTERN_DEF).
		expect(tokenSet{PATTERN_IDENT}).
		expect(tokenSet{EQUAL}).
		beginAlt().
		alt(func(p *Parser) *Parser { return p.expect(tokenSet{STRING_LIT}) }).
		alt(func(p *Parser) *Parser { return p.expect(tokenSet{REGEXP}) }).
		alt((*Parser).hexPattern).
		endAlt().
		opt((*Parser).patternMods).
		end()
}

// PATTERN_MODS := PATTERN_MOD+
func (p *Parser) patternMods() *Parser {
	return p.begin(PATTERN_MODS).oneOrMore((*Parser).patternMod).end()
}

// PATTERN_MOD := `ascii` | `wide` | `nocase` | `private` | `fullword`
//
//	| (`base64` | `base64wide`) ( `(` STRING_LIT `)` )?
//	| `xor` ( `(` INTEGER_LIT ( `-` INTEGER_LIT )? `)` )?
func (p *Parser) patternMod() *Parser {
	return p.begin(PATTERN_MOD).
		beginAlt().
		alt(func(p *Parser) *Parser {
			return p.expectD(setSimplePatternMod, descPatternMod)
		}).
		alt(func(p *Parser) *Parser {
			return p.expectD(tokenSet{BASE64_KW, BASE64WIDE_KW}, descPatternMod).
				cond(tokenSet{L_PAREN}, func(p *Parser) *Parser {
					return p.expect(tokenSet{STRING_LIT}).expect(tokenSet{R_PAREN})
				})
		}).
		alt(func(p *Parser) *Parser {
			return p.expectD(tokenSet{XOR_KW}, descPatternMod).
				cond(tokenSet{L_PAREN}, func(p *Parser) *Parser {
					return p.expect(tokenSet{INTEGER_LIT}).
						cond(tokenSet{HYPHEN}, func(p *Parser) *Parser {
							return p.expect(tokenSet{INTEGER_LIT})
						}).
						expect(tokenSet{R_PAREN})
				})
		}).
		endAlt().
		end()
}

// HEX_PATTERN := `{` HEX_SUB_PATTERN `}`
//
// The tokenizer must be switched into hex-pattern mode after the `{`,
// because the same characters mean different things inside.
func (p *Parser) hexPattern() *Parser {
	return p.begin(HEX_PATTERN).
		expect(tokenSet{L_BRACE}).
		enterHexPatternMode().
		then((*Parser).hexSubPattern).
		expect(tokenSet{R_BRACE}).
		end()
}

func (p *Parser) enterHexPatternMode() *Parser {
	if p.failed() {
		return p
	}
	p.tokens.tz.EnterHexPatternMode()
	return p
}

func (p *Parser) enterHexJumpMode() *Parser {
	if p.failed() {
		return p
	}
	p.tokens.tz.EnterHexJumpMode()
	return p
}

// HEX_SUB_PATTERN := (HEX_BYTE | HEX_ALTERNATIVE) (HEX_JUMP* (HEX_BYTE | HEX_ALTERNATIVE))*
func (p *Parser) hexSubPattern() *Parser {
	byteOrAlt := func(p *Parser) *Parser {
		return p.beginAlt().
			alt(func(p *Parser) *Parser { return p.expect(tokenSet{HEX_BYTE}) }).
			alt((*Parser).hexAlternative).
			endAlt()
	}
	return p.begin(HEX_SUB_PATTERN).
		then(byteOrAlt).
		zeroOrMore(func(p *Parser) *Parser {
			return p.zeroOrMore((*Parser).hexJump).then(byteOrAlt)
		}).
		end()
}

// HEX_ALTERNATIVE := `(` HEX_SUB_PATTERN ( `|` HEX_SUB_PATTERN )* `)`
func (p *Parser) hexAlternative() *Parser {
	return p.begin(HEX_ALTERNATIVE).
		expect(tokenSet{L_PAREN}).
		then((*Parser).hexSubPattern).
		zeroOrMore(func(p *Parser) *Parser {
			return p.expect(tokenSet{PIPE}).then((*Parser).hexSubPattern)
		}).
		expect(tokenSet{R_PAREN}).
		end()
}

// HEX_JUMP := `[` ( INTEGER_LIT? `-` INTEGER_LIT? | INTEGER_LIT ) `]`
func (p *Parser) hexJump() *Parser {
	return p.begin(HEX_JUMP).
		expect(tokenSet{L_BRACKET}).
		enterHexJumpMode().
		beginAlt().
		alt(func(p *Parser) *Parser {
			return p.optExpect(tokenSet{INTEGER_LIT}).
				expect(tokenSet{HYPHEN}).
				optExpect(tokenSet{INTEGER_LIT})
		}).
		alt(func(p *Parser) *Parser { return p.expect(tokenSet{INTEGER_LIT}) }).
		endAlt().
		expect(tokenSet{R_BRACKET}).
		end()
}

// CONDITION_BLK := `condition` `:` BOOLEAN_EXPR
func (p *Parser) conditionBlk() *Parser {
	return p.begin(CONDITION_BLK).
		expect(tokenSet{CONDITION_KW}).
		expect(tokenSet{COLON}).
		boolExprThen(tokenSet{R_BRACE}).
		end().
		recover(tokenSet{R_BRACE})
}

// boolExprThen parses a boolean expression as a `then` step, recovering up to
// the given follow set on error. The condition block, the `for` body, and the
// `with` body all embed a boolean expression this way; they differ only in the
// token that closes them.
func (p *Parser) boolExprThen(follow tokenSet) *Parser {
	return p.then(func(p *Parser) *Parser {
		return p.booleanExpr().recover(follow)
	})
}

// BOOLEAN_EXPR := BOOLEAN_TERM ( (`and` | `or`) BOOLEAN_TERM )*
func (p *Parser) booleanExpr() *Parser {
	return p.begin(BOOLEAN_EXPR).
		then((*Parser).booleanTerm).
		zeroOrMore(func(p *Parser) *Parser {
			return p.expectD(setAndOr, descOperator).then((*Parser).booleanTerm)
		}).
		end()
}

// BOOLEAN_TERM := PATTERN_IDENT ( `at` EXPR | `in` RANGE )?
//
//	| `true` | `false`
//	| (`not` | `defined`) BOOLEAN_TERM
//	| FOR_EXPR | OF_EXPR | WITH_EXPR
//	| EXPR ( comparison_op EXPR )*
//	| `(` BOOLEAN_EXPR `)`
func (p *Parser) booleanTerm() *Parser {
	return p.begin(BOOLEAN_TERM).
		beginAlt().
		alt(func(p *Parser) *Parser {
			return p.expectD(tokenSet{PATTERN_IDENT}, descExpression).
				ifNext(setAtOrIn, (*Parser).atOrIn)
		}).
		alt(func(p *Parser) *Parser {
			return p.expectD(tokenSet{TRUE_KW, FALSE_KW}, descExpression)
		}).
		alt(func(p *Parser) *Parser {
			return p.expectD(tokenSet{NOT_KW, DEFINED_KW}, descExpression).
				then((*Parser).booleanTerm)
		}).
		alt((*Parser).forExpr).
		alt((*Parser).ofExpr).
		alt((*Parser).withExpr).
		alt(func(p *Parser) *Parser {
			return p.expr().zeroOrMore(func(p *Parser) *Parser {
				return p.expectD(setComparisonOp, descExpression).
					then((*Parser).expr)
			})
		}).
		alt(func(p *Parser) *Parser {
			return p.expectD(tokenSet{L_PAREN}, descExpression).
				then((*Parser).booleanExpr).
				expect(tokenSet{R_PAREN})
		}).
		endAlt().
		end()
}

// at_or_in := `at` EXPR | `in` RANGE
func (p *Parser) atOrIn() *Parser {
	return p.beginAlt().
		alt(func(p *Parser) *Parser {
			return p.expect(tokenSet{AT_KW}).then((*Parser).expr)
		}).
		alt(func(p *Parser) *Parser {
			return p.expect(tokenSet{IN_KW}).then((*Parser).rangeExpr)
		}).
		endAlt()
}

// EXPR := TERM ( (arithmetic_op | bitwise_op) TERM )*
func (p *Parser) expr() *Parser {
	return p.cached(EXPR, func(p *Parser) *Parser {
		return p.begin(EXPR).
			then((*Parser).term).
			zeroOrMore(func(p *Parser) *Parser {
				return p.expectD(setArithBitwiseOp, descOperator).
					then((*Parser).term)
			}).
			end()
	})
}

// FUNC_CALL := IDENT `(` ( BOOLEAN_EXPR ( `,` BOOLEAN_EXPR )* )? `)`
func (p *Parser) funcCall() *Parser {
	return p.begin(FUNC_CALL).
		expect(tokenSet{IDENT}).
		expect(tokenSet{L_PAREN}).
		opt(func(p *Parser) *Parser {
			return p.booleanExpr().zeroOrMore(func(p *Parser) *Parser {
				return p.expect(tokenSet{COMMA}).then((*Parser).booleanExpr)
			})
		}).
		expect(tokenSet{R_PAREN}).
		end()
}

// RANGE := `(` EXPR `.` `.` EXPR `)`
//
// The `..` is two DOT tokens; there is no dedicated range operator.
func (p *Parser) rangeExpr() *Parser {
	return p.begin(RANGE).
		expect(tokenSet{L_PAREN}).
		then((*Parser).expr).
		expect(tokenSet{DOT}).
		expect(tokenSet{DOT}).
		then((*Parser).expr).
		expect(tokenSet{R_PAREN}).
		end()
}

// TERM := FLOAT_LIT | INTEGER_LIT | STRING_LIT | REGEXP | `filesize` | `entrypoint`
//
//	| PATTERN_COUNT (`in` RANGE)?
//	| (PATTERN_OFFSET | PATTERN_LENGTH) (`[` EXPR `]`)?
//	| `-` TERM | `~` TERM
//	| `(` EXPR `)`
//	| PRIMARY_EXPR ( `.` PRIMARY_EXPR )*
func (p *Parser) term() *Parser {
	return p.cached(TERM, func(p *Parser) *Parser {
		return p.begin(TERM).
			beginAlt().
			alt(func(p *Parser) *Parser {
				return p.expectD(setTermLiteral, descExpression)
			}).
			alt(func(p *Parser) *Parser {
				return p.expectD(tokenSet{PATTERN_COUNT}, descExpression).
					cond(tokenSet{IN_KW}, (*Parser).rangeExpr)
			}).
			alt(func(p *Parser) *Parser {
				return p.expectD(tokenSet{PATTERN_OFFSET, PATTERN_LENGTH}, descExpression).
					cond(tokenSet{L_BRACKET}, func(p *Parser) *Parser {
						return p.expr().expect(tokenSet{R_BRACKET})
					})
			}).
			alt(func(p *Parser) *Parser {
				return p.expectD(tokenSet{MINUS}, descExpression).then((*Parser).term)
			}).
			alt(func(p *Parser) *Parser {
				return p.expectD(tokenSet{BITWISE_NOT}, descExpression).then((*Parser).term)
			}).
			alt(func(p *Parser) *Parser {
				return p.expectD(tokenSet{L_PAREN}, descExpression).
					then((*Parser).expr).
					expect(tokenSet{R_PAREN})
			}).
			alt(func(p *Parser) *Parser {
				return p.primaryExpr().zeroOrMore(func(p *Parser) *Parser {
					return p.expectD(tokenSet{DOT}, descExpression).
						then((*Parser).primaryExpr)
				})
			}).
			endAlt().
			end()
	})
}

// PRIMARY_EXPR := FUNC_CALL | IDENT `[` EXPR `]` | IDENT
func (p *Parser) primaryExpr() *Parser {
	return p.begin(PRIMARY_EXPR).
		beginAlt().
		alt((*Parser).funcCall).
		alt(func(p *Parser) *Parser {
			return p.expect(tokenSet{IDENT}).
				expect(tokenSet{L_BRACKET}).
				then((*Parser).expr).
				expect(tokenSet{R_BRACKET})
		}).
		alt(func(p *Parser) *Parser { return p.expect(tokenSet{IDENT}) }).
		endAlt().
		end()
}

// FOR_EXPR := `for` QUANTIFIER ( `of` (`them` | PATTERN_IDENT_TUPLE)
//
//	| IDENT (`,` IDENT)* `in` ITERABLE )
//	`:` `(` BOOLEAN_EXPR `)`
func (p *Parser) forExpr() *Parser {
	return p.begin(FOR_EXPR).
		expectD(tokenSet{FOR_KW}, descExpression).
		then((*Parser).quantifier).
		beginAlt().
		alt(func(p *Parser) *Parser {
			return p.expect(tokenSet{OF_KW}).
				beginAlt().
				alt(func(p *Parser) *Parser { return p.expect(tokenSet{THEM_KW}) }).
				alt((*Parser).patternIdentTuple).
				endAlt()
		}).
		alt(func(p *Parser) *Parser {
			return p.expect(tokenSet{IDENT}).
				zeroOrMore(func(p *Parser) *Parser {
					return p.expect(tokenSet{COMMA}).expect(tokenSet{IDENT})
				}).
				expect(tokenSet{IN_KW}).
				iterable()
		}).
		endAlt().
		expect(tokenSet{COLON}).
		expect(tokenSet{L_PAREN}).
		boolExprThen(tokenSet{R_PAREN}).
		expect(tokenSet{R_PAREN}).
		end()
}

// OF_EXPR := QUANTIFIER ( `of` (`them` | PATTERN_IDENT_TUPLE) (`at` EXPR | `in` RANGE)?
//
//	| BOOLEAN_EXPR_TUPLE )
func (p *Parser) ofExpr() *Parser {
	return p.begin(OF_EXPR).
		then((*Parser).quantifier).
		expect(tokenSet{OF_KW}).
		beginAlt().
		alt(func(p *Parser) *Parser {
			return p.beginAlt().
				alt(func(p *Parser) *Parser { return p.expect(tokenSet{THEM_KW}) }).
				alt((*Parser).patternIdentTuple).
				endAlt().
				ifNext(setAtOrIn, (*Parser).atOrIn)
		}).
		alt(func(p *Parser) *Parser {
			// `at`/`in` may not follow a tuple of boolean expressions, so
			// reject that reading here rather than accepting and failing later.
			return p.booleanExprTuple().not(func(p *Parser) *Parser {
				return p.expect(setAtOrIn)
			})
		}).
		endAlt().
		end()
}

// WITH_EXPR := `with` WITH_DECLS `:` `(` BOOLEAN_EXPR `)`
func (p *Parser) withExpr() *Parser {
	return p.begin(WITH_EXPR).
		expectD(tokenSet{WITH_KW}, descExpression).
		then((*Parser).withDeclarations).
		expect(tokenSet{COLON}).
		expect(tokenSet{L_PAREN}).
		boolExprThen(tokenSet{R_PAREN}).
		expect(tokenSet{R_PAREN}).
		end()
}

// WITH_DECLS := WITH_DECL ( `,` WITH_DECL )*
func (p *Parser) withDeclarations() *Parser {
	return p.begin(WITH_DECLS).
		then((*Parser).withDeclaration).
		zeroOrMore(func(p *Parser) *Parser {
			return p.expect(tokenSet{COMMA}).withDeclaration()
		}).
		end().
		recover(tokenSet{COLON, L_PAREN})
}

// WITH_DECL := IDENT `=` EXPR
func (p *Parser) withDeclaration() *Parser {
	return p.begin(WITH_DECL).
		expect(tokenSet{IDENT}).
		expect(tokenSet{EQUAL}).
		then((*Parser).expr).
		end()
}

// QUANTIFIER := `all` | `none` | `any` | TERM `%` | EXPR !`%`
//
// The last two alternatives cannot be collapsed into "EXPR `%`?" because `%`
// is also the modulo operator, so an expression may legitimately contain one.
func (p *Parser) quantifier() *Parser {
	return p.begin(QUANTIFIER).
		beginAlt().
		alt(func(p *Parser) *Parser {
			return p.expectD(setQuantifierKw, descExpression)
		}).
		alt(func(p *Parser) *Parser {
			return p.term().expect(tokenSet{PERCENT})
		}).
		alt(func(p *Parser) *Parser {
			return p.expr().not(func(p *Parser) *Parser {
				return p.expect(tokenSet{PERCENT})
			})
		}).
		endAlt().
		end()
}

// ITERABLE := RANGE | EXPR_TUPLE | EXPR
func (p *Parser) iterable() *Parser {
	return p.begin(ITERABLE).
		beginAlt().
		alt((*Parser).rangeExpr).
		alt((*Parser).exprTuple).
		alt((*Parser).expr).
		endAlt().
		end()
}

// BOOLEAN_EXPR_TUPLE := `(` BOOLEAN_EXPR ( `,` BOOLEAN_EXPR )* `)`
func (p *Parser) booleanExprTuple() *Parser {
	return p.begin(BOOLEAN_EXPR_TUPLE).
		expect(tokenSet{L_PAREN}).
		then((*Parser).booleanExpr).
		zeroOrMore(func(p *Parser) *Parser {
			return p.expect(tokenSet{COMMA}).then((*Parser).booleanExpr)
		}).
		expect(tokenSet{R_PAREN}).
		end()
}

// EXPR_TUPLE := `(` EXPR ( `,` EXPR )* `)`
func (p *Parser) exprTuple() *Parser {
	return p.begin(EXPR_TUPLE).
		expect(tokenSet{L_PAREN}).
		then((*Parser).expr).
		zeroOrMore(func(p *Parser) *Parser {
			return p.expect(tokenSet{COMMA}).then((*Parser).expr)
		}).
		expect(tokenSet{R_PAREN}).
		end()
}

// PATTERN_IDENT_TUPLE := `(` PATTERN_IDENT `*`? ( `,` PATTERN_IDENT `*`? )* `)`
func (p *Parser) patternIdentTuple() *Parser {
	return p.begin(PATTERN_IDENT_TUPLE).
		expect(tokenSet{L_PAREN}).
		expect(tokenSet{PATTERN_IDENT}).
		optExpect(tokenSet{ASTERISK}).
		zeroOrMore(func(p *Parser) *Parser {
			return p.expect(tokenSet{COMMA}).
				expect(tokenSet{PATTERN_IDENT}).
				optExpect(tokenSet{ASTERISK})
		}).
		expect(tokenSet{R_PAREN}).
		end()
}
