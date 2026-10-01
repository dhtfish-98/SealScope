# Rewrite verification

The baseline is the exact local source commit recorded in ORIGIN.md.

- 134 baseline regression tests passed before the rewrite; all 134 renamed tests pass.
- Original and new file reports were compared on 35 local system files.
- 350 malformed-container inputs, 240 permission-codec inputs and 100 permission-rule
  combinations were compared against the original implementation.
- Retained executable functions are covered by the identifier-aware structural audit
  in the parent workspace; newly organized container modules preserve the original
  reads, checks and errors.
- Source references pass the undefined-name audit. Python 3.9 grammar is checked.
- Wheel/source distributions and an installed consumer are checked separately.

Structural metadata, local tests and parser agreement do not establish CMS
signature validity, certificate trust or OS-granted permissions. Historical
baseline evidence in guides/ is kept separate from this rewrite's current checks.

The 2026-10-01 recheck also compared 2,301 slices with native codesign (zero
mismatches), 947 paired XML/DER permission documents (zero disagreements/errors),
and 481 native permission outputs (zero differences). The 134 tests passed again.
