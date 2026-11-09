package yarrow

import "testing"

// Differential testing against YARA-X over the corpus surfaced that meta string
// values must be escape-DECODED for rendering (the reference's MetaValue), not
// echoed raw as the fixed goldens happened to allow. These cases pin the decoder
// to the reference's string_lit behaviour.
func TestDecodeMetaString(t *testing.T) {
	cases := map[string]string{
		`"plain"`:               "plain",              // no escapes: verbatim (borrowed case)
		`"a\\b"`:                `a\b`,                // \\ -> one backslash (the corpus divergence)
		`"C:\\Windows\\Temp"`:   `C:\Windows\Temp`,    // dell_bios case
		`"say \"hi\""`:          `say "hi"`,           // \" -> bare quote (webshells/turla case)
		`"tab\there"`:           "tab\there",          // \t -> TAB
		`"nl\nhere"`:            "nl\nhere",           // \n -> LF
		`"cr\rhere"`:            "cr\rhere",           // \r -> CR
		`"nul\0end"`:            "nul\x00end",         // \0 -> NUL
		`"hex\x41Z"`:            "hexAZ",              // \x41 -> 'A'
		`"lit backslash r \\r"`: `lit backslash r \r`, // \\r -> backslash + r (Stampado case)
		`"""triple\\quote"""`:   `triple\quote`,       // triple-quoted decodes the same way
	}
	for in, want := range cases {
		if got := decodeMetaString(in); got != want {
			t.Errorf("decodeMetaString(%s) = %q, want %q", in, got, want)
		}
	}
}

// The rendered meta line wraps the decoded value in quotes, matching the
// reference's `"{v}"` Display.
func TestMetaValueStringRendersDecoded(t *testing.T) {
	ast, err := ParseAST([]byte(`rule r {
  meta:
    path = "C:\\Windows"
    msg = "say \"hi\""
  condition:
    true
}`))
	if err != nil {
		t.Fatal(err)
	}
	rule := ast.Items[0].(*Rule)
	if got := metaValueString(rule.Meta[0].Value); got != `"C:\Windows"` {
		t.Errorf("meta[0] = %s, want %q", got, `"C:\Windows"`)
	}
	if got := metaValueString(rule.Meta[1].Value); got != `"say "hi""` {
		t.Errorf("meta[1] = %s, want %q", got, `"say "hi""`)
	}
}
