package scan

import "testing"

// FuzzRegexp exercises the regexp compiler and the Pike VM: neither may panic or
// hang on adversarial input. Bodies are length-capped so the fuzzer explores
// syntax rather than building huge (but legal) programs whose O(n²) scan is slow.
func FuzzRegexp(f *testing.F) {
	for _, s := range []string{"abc", "a[0-9]+", "(a|b)*c", "^x$", `\d{2,4}`, "a.c", `[^\x00-\x1f]+`, "(?:ab){2,5}"} {
		f.Add(s, false, false)
	}
	f.Fuzz(func(t *testing.T, body string, nocase, dotAll bool) {
		if len(body) > 200 {
			return
		}
		p, err := Regexp(body, nocase, dotAll)
		if err != nil {
			return
		}
		_ = p.FindAll([]byte("The quick brown fox 0123456789 \x00\xff jumps."))
	})
}

// FuzzHexElements exercises jump/alt/class compilation via a byte-driven element
// stream: no panic, no OOM (the size cap must hold).
func FuzzHexElements(f *testing.F) {
	f.Add([]byte{0x6A, 0x00, 0x68})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 64 {
			return
		}
		var elems []Element
		for i := 0; i < len(b); i++ {
			switch b[i] % 4 {
			case 0:
				elems = append(elems, Byte(b[i]))
			case 1:
				elems = append(elems, AnyByte())
			case 2:
				elems = append(elems, Jump{Min: int(b[i]) % 8, Max: int(b[i])%8 + int(b[i])%16})
			case 3:
				elems = append(elems, Alt{Alts: [][]Element{{Byte(b[i])}, {AnyByte(), Byte(b[i])}}})
			}
		}
		p, err := Compile(elems)
		if err != nil {
			return
		}
		_ = p.FindAll([]byte("payload\x00\xff data"))
	})
}
