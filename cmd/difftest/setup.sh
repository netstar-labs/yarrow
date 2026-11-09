#!/usr/bin/env bash
# Reproducible setup for the differential harness. Clones YARA-X at the pinned
# reference commit, installs the reference dump harness as a cargo example, builds
# it, and reconstructs the rule corpus from the four README-named upstreams. Both
# outputs land in gitignored scratch dirs (_ref/, _corpus/).
#
#   bash cmd/difftest/setup.sh
#   go run ./cmd/difftest -corpus _corpus -ref _ref/yara-x/target/release/examples/dump
#
# Needs: git, and a Rust toolchain new enough for YARA-X (edition 2024, rustc
# >= 1.91 — `rustup update stable`).
set -euo pipefail

# The YARA-X commit yarrow's parser was validated byte-for-byte against.
commit="cb7fb566b5e3a65cf8574e665e3b2ddc57084e7e"

root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"

echo "== YARA-X reference @ ${commit} =="
mkdir -p _ref
if [ ! -d _ref/yara-x/.git ]; then
	git clone --filter=blob:none --quiet https://github.com/VirusTotal/yara-x.git _ref/yara-x
fi
git -C _ref/yara-x checkout --quiet "$commit"
# Install the harness as an example inside the parser crate (guarantees the
# workspace dependency inheritance resolves).
cp cmd/difftest/reference/dump.rs _ref/yara-x/parser/examples/dump.rs
( cd _ref/yara-x/parser && cargo build --release --example dump )
echo "harness: _ref/yara-x/target/release/examples/dump"

echo "== rule corpus (2,532 files across four upstreams) =="
mkdir -p _corpus
clone() { # url dir
	[ -d "_corpus/$2/.git" ] || git clone --depth 1 --quiet "$1" "_corpus/$2"
}
clone https://github.com/Neo23x0/signature-base.git             signature-base
clone https://github.com/Yara-Rules/rules.git                   yara-rules
clone https://github.com/elastic/protections-artifacts.git      protections-artifacts
clone https://github.com/reversinglabs/reversinglabs-yara-rules.git reversinglabs-yara-rules
n=$(find _corpus -type f \( -name '*.yar' -o -name '*.yara' \) | wc -l | tr -d ' ')
echo "corpus: ${n} .yar/.yara files under _corpus/"
