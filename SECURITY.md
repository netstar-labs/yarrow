# Security policy

## Supported versions

yarrow is pre-1.0. Security fixes are made against the latest `v0.x` release only.

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's
[private vulnerability reporting](https://github.com/netstar-labs/yarrow/security/advisories/new)
for this repository. Do not open a public issue for a suspected vulnerability.

Include the affected version or commit, a minimal rule file or input that
reproduces the problem, and the observed impact (panic, hang, excessive memory,
incorrect match result).

## Scope

yarrow parses and scans untrusted input, so the following are in scope:

- Panics, infinite loops, or unbounded CPU or memory use on crafted rule text,
  patterns, or scan targets (the parser is fuel-bounded, the AST builder
  depth-bounded, and pattern compilation instruction-capped; a bypass of those
  limits is a vulnerability).
- Memory-safety or integer-conversion errors in the pattern engine or the
  `pe`, `elf`, `hash`, and `math` modules.
- Incorrect match results that could cause a detection to be silently missed.

Behavioural differences from YARA-X that do not have a security impact are
ordinary bugs; please file them as issues.
