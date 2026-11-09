package compile

import "testing"

func TestHashModule(t *testing.T) {
	// md5("abc") and sha256("abc") — known vectors.
	md5rule := `import "hash"
		rule r { condition: hash.md5(0, filesize) == "900150983cd24fb0d6963f7d28e17f72" }`
	wantHits(t, scanRules(t, md5rule, "abc"), "r")
	wantHits(t, scanRules(t, md5rule, "abd")) // different data → different digest

	sha := `import "hash"
		rule r { condition: hash.sha256(0, 3) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" }`
	wantHits(t, scanRules(t, sha, "abc"), "r")
}

func TestMathModule(t *testing.T) {
	// A single repeated byte has zero entropy.
	zero := `import "math" rule r { condition: math.entropy(0, filesize) == 0.0 }`
	wantHits(t, scanRules(t, zero, "aaaaaa"), "r")
	wantHits(t, scanRules(t, zero, "ab")) // two symbols → entropy 1, not 0

	// Two equally likely symbols → entropy exactly 1.0.
	one := `import "math" rule r { condition: math.entropy(0, filesize) == 1.0 }`
	wantHits(t, scanRules(t, one, "abab"), "r")

	inrange := `import "math" rule r { condition: math.in_range(filesize, 3, 5) }`
	wantHits(t, scanRules(t, inrange, "abcd"), "r") // len 4 in [3,5]
	wantHits(t, scanRules(t, inrange, "ab"))        // len 2 out of range
}

func TestPeConstantsAndUndefined(t *testing.T) {
	// A module constant resolves without any PE present.
	konst := `import "pe" rule r { condition: pe.MACHINE_AMD64 == 0x8664 }`
	wantHits(t, scanRules(t, konst, "not a pe"), "r")

	// A structural field over non-PE data is undefined → the condition is false,
	// and indexing an undefined array must not panic.
	fields := `import "pe" rule r {
		condition: pe.number_of_sections == 2 or pe.sections[0].name == ".text"
	}`
	wantHits(t, scanRules(t, fields, "not a pe")) // no match, no panic
}

func TestElfUndefined(t *testing.T) {
	src := `import "elf" rule r { condition: elf.number_of_sections > 0 }`
	wantHits(t, scanRules(t, src, "not an elf")) // undefined → false
}

func TestUnimportedModuleErrors(t *testing.T) {
	// Referencing a module that was not imported is a hard error, not a silent
	// false — the author wrote something that cannot be evaluated.
	rs, err := Compile([]byte(`rule r { condition: pe.number_of_sections == 1 }`))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if _, err := rs.Scan([]byte("data")); err == nil {
		t.Error("expected an error scanning a rule that uses an unimported module")
	}
}

// Audit C (SECURITY): a crafted rule with huge slice args must not panic the
// scanner via int64 overflow in the bounds check.
func TestModuleSliceArgOverflow(t *testing.T) {
	src := `import "hash" rule r { condition: hash.md5(0x4000000000000000, 0x4000000000000000) == "x" }`
	rs, err := Compile([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	hits, err := rs.Scan([]byte("data")) // must return, not panic
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	wantHits(t, hits) // undefined slice → md5 undefined → condition false
}

// Audit C: an undefined `of` count must make the whole `of` undefined (false),
// not silently pass because the count read as 0.
func TestOfUndefinedCount(t *testing.T) {
	src := `import "pe" rule r {
		strings: $a = "x"
		condition: pe.number_of_sections of them
	}`
	// non-PE data → pe.number_of_sections undefined → `of` undefined → no match.
	wantHits(t, scanRules(t, src, "x present"))
}

// Audit C: an undefined range bound must make `$a in (..)` undefined, not
// collapse to 0..hi (which would match anywhere $a matches).
func TestInRangeUndefinedBound(t *testing.T) {
	src := `import "pe" rule r {
		strings: $a = "x"
		condition: $a in (pe.entry_point .. filesize)
	}`
	wantHits(t, scanRules(t, src, "xxxx")) // entry_point undefined → in-range undefined → no match
}
