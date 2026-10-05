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

## 0.2.1 structural bounds revision

The current public 0.2.0 source was used as the revision baseline. Twenty new
synthetic tests cover valid declared extents and malformed fat slices, load commands,
signature references, SuperBlob indexes and children, and CodeDirectory fields,
including hash slots that would otherwise overlap version-header bytes. Positive
fixtures retain valid 0x20500 and 0x20600 CodeDirectory headers.
Nine malformed cases were demonstrated to pass through the baseline parser before
the change. The revised source suite passes all 154 tests on Python 3.11, including
the existing local `/usr/bin/otool` comparison test.

The checks constrain parsing to declared bytes. They do not verify a CMS signature,
certificate chain, page hashes or operating-system-granted entitlements. See the
Apple XNU `CS_SuperBlob` and `CS_CodeDirectory` declarations and validation paths:
https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h
https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/ubc_subr.c

## 0.2.2 source-release synchronization

The 0.2.2 change updates the runtime/package version and the repository's private
vulnerability reporting link. The parser and policy implementation is unchanged
from 0.2.1. On the staged source, 154 tests passed with Python 3.14. The staged
build produced a wheel and source archive under `Build`, and an isolated consumer
installed the wheel, read version 0.2.2 and author `dhtfish98`, and invoked the
CLI help command. These local checks do not replace the GitHub Actions result
for the published commit and tag.
