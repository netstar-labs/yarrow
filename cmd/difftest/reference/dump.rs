// Reference dump harness for yarrow's differential testing.
//
// Emits the CST tree / CST event stream / AST tree for a rule file in the exact
// format the YARA-X parser goldens are generated in (see
// src/parser/tests/mod.rs) — same public API, same Debug impls. yarrow's own CLI
// (`app/yarrow -mode ...`) is diffed byte-for-byte against this over a corpus.
//
//   cargo run --release --example dump -- -mode cst       rules.yar
//   cargo run --release --example dump -- -mode cststream rules.yar
//   cargo run --release --example dump -- -mode ast       rules.yar
//   cat rules.yar | cargo run --release --example dump -- -mode ast
//
// Reads bytes (not a UTF-8 string), matching yarrow's []byte entry points, so
// non-UTF-8 corpus files exercise the same error paths on both sides.

use std::io::{Read, Write};

use yara_x_parser::ast::AST;
use yara_x_parser::cst::{CSTStream, CST};
use yara_x_parser::Parser;

fn main() {
    let mut mode = String::from("cst");
    let mut file: Option<String> = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "-mode" | "--mode" => mode = args.next().unwrap_or_default(),
            other => file = Some(other.to_string()),
        }
    }

    let src: Vec<u8> = match file {
        Some(p) => std::fs::read(&p).unwrap_or_else(|e| {
            eprintln!("dump: read {p}: {e}");
            std::process::exit(2);
        }),
        None => {
            let mut b = Vec::new();
            std::io::stdin().read_to_end(&mut b).unwrap();
            b
        }
    };

    let out = std::io::stdout();
    let mut w = std::io::BufWriter::new(out.lock());
    match mode.as_str() {
        "cst" => {
            // CST::try_from can fail only on a tokenizer-level error the tree can't
            // represent; treat that as an empty dump so the diff shows it explicitly
            // rather than aborting the whole corpus run.
            match CST::try_from(Parser::new(&src)) {
                Ok(cst) => write!(w, "{cst:?}").unwrap(),
                Err(e) => {
                    let _ = w.flush();
                    eprintln!("dump: CST error: {e:?}");
                    std::process::exit(3);
                }
            }
        }
        "cststream" => {
            for event in CSTStream::from(Parser::new(&src)) {
                writeln!(w, "{event:?}").unwrap();
            }
        }
        "ast" => {
            let ast = AST::from(src.as_slice());
            write!(w, "{ast:?}").unwrap();
        }
        _ => {
            eprintln!("dump: unknown -mode {mode:?} (want cst|cststream|ast)");
            std::process::exit(2);
        }
    }
    w.flush().unwrap();
}
