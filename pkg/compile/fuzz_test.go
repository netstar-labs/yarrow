package compile

import "testing"

// FuzzCompileScan runs the whole pipeline — parse+compile a rule, then scan data.
// Compile may reject the rule (fine); nothing may panic, and a scan must return.
func FuzzCompileScan(f *testing.F) {
	seeds := []string{
		`rule r { strings: $a = "x" condition: $a }`,
		`rule r { strings: $a = { 6A ?? 68 } condition: #a > 0 }`,
		`rule r { strings: $a = /a[0-9]+/ condition: $a at 0 }`,
		`import "math" rule r { condition: math.entropy(0, filesize) > 1.0 }`,
		`rule r { strings: $a="a" $b="b" condition: 1 of them and filesize < 100 }`,
	}
	for _, s := range seeds {
		f.Add(s, []byte("some scan data 0123"))
	}
	f.Fuzz(func(t *testing.T, src string, data []byte) {
		if len(src) > 4096 || len(data) > 4096 {
			return
		}
		rs, err := Compile([]byte(src))
		if err != nil {
			return
		}
		_, _ = rs.Scan(data)
	})
}
