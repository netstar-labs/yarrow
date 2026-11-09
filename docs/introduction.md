# yarrow

> *The mark that reads the marks — YARA, parsed to the byte and run in pure Go.*

A **yarrow** is an inscribed sign — a mark drawn deliberately, believed to hold the
power to detect, to ward, to name a thing so it can be found again. A YARA rule is
exactly that: a signature inscribed by an analyst so a machine can recognise a
threat wherever it next appears. The name carries its own craft, too — **sig**il,
the *signature* at the root of the word.

What it actually is: a parser for the YARA rule language, written in Go, depending
only on the standard library. It reads rule source — the `rule … { strings: …
condition: … }` text that malware analysts write — and turns it into two trees. A
**concrete syntax tree** that is *lossless*: every byte of the source, including
whitespace and comments, is represented, so the tree round-trips back to the exact
input — the shape a formatter, linter, or editor language-server needs. And a
**semantic abstract syntax tree**: operator precedence resolved, associative
chains flattened, trivia dropped — the shape a compiler or analyzer wants.

It is a faithful port of the parser from [YARA-X](https://github.com/VirusTotal/yara-x),
the Rust rewrite of YARA, and it reproduces that parser byte-for-byte: the same
tokenizer modes, the same error-resilient grammar, the same tree-dump format,
validated against the reference's own golden outputs and across tens of thousands
of real-world rules.

And then it runs them: a byte-oriented matching engine built *on top of* the AST
compiles each pattern — literal, hex, or regexp, with the string modifiers — to a
Thompson NFA, and a condition VM evaluates the rule against data, with the common
`hash`/`math`/`pe`/`elf` modules. What yarrow guarantees at the parser layer is
that the tree it hands you is the tree YARA-X would have built; the scanner is a
faithful MVP that grows toward full parity ([docs/matcher.md](matcher.md)). Both
can be handed input from anywhere — including an adversary — without hanging,
overflowing, or crashing.

*Read next: [executive summary](executive-summary.md) · [architecture](architecture.md) · [user guide](userguide.md)*
