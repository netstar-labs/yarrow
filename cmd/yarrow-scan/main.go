// Command yarrow-scan compiles a YARA rule file and scans a target file, printing
// the name of each rule that matches (one per line). It is a thin driver over
// pkg/compile — the end-to-end matcher.
//
//	yarrow-scan rules.yar sample.bin
//
// Exit status: 0 if one or more rules matched; 1 if none matched; 2 on a
// usage/IO/compile error.
package main

import (
	"fmt"
	"os"

	"github.com/netstar-labs/yarrow/pkg/compile"
)

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: yarrow-scan <rules.yar> <target-file>")
		return 2
	}
	src, err := os.ReadFile(args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, "yarrow-scan:", err)
		return 2
	}
	rs, err := compile.Compile(src)
	if err != nil {
		fmt.Fprintln(os.Stderr, "yarrow-scan:", err)
		return 2
	}
	data, err := os.ReadFile(args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "yarrow-scan:", err)
		return 2
	}
	hits, err := rs.Scan(data)
	if err != nil {
		fmt.Fprintln(os.Stderr, "yarrow-scan:", err)
		return 2
	}
	for _, h := range hits {
		fmt.Println(h)
	}
	if len(hits) == 0 {
		return 1
	}
	return 0
}
