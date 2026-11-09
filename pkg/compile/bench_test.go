package compile

import (
	"bytes"
	"testing"
)

const benchRule = `rule bench {
	strings:
		$a = "malware"
		$b = "trojan" nocase
		$c = { 4D 5A ?? ?? }
		$d = /C2_[0-9]{2,4}/
	condition:
		2 of them and filesize < 1000000
}`

func BenchmarkScan16K(b *testing.B) {
	rs, err := Compile([]byte(benchRule))
	if err != nil {
		b.Fatal(err)
	}
	data := bytes.Repeat([]byte("the quick brown fox 0123 "), 16384/25)
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := rs.Scan(data); err != nil {
			b.Fatal(err)
		}
	}
}
