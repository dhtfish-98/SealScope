> Historical baseline evidence: the runs and commits below belong to the upstream
> project recorded in `../ORIGIN.md`. Paths and current API names have been updated;
> current rewrite checks are recorded in `../VALIDATION.md`.

# Verification

This file maps the claims in [README.md](../README.md) to something a reader can
check, and says which of them were re-run for this revision.

## Environment used for the run below

```
macOS 26.7 (build 25G229), arm64
Python 3.9.6  (pytest not installed — the scripts below need only the standard library)
```

## The two corpus comparisons

Both scripts in [`utilities/`](../utilities/) parse a corpus with sealscope, ask `codesign` for
the same facts, and compare them field by field. They exit non-zero on a mismatch, so
they can gate a change.

```console
$ python3 utilities/compare_native_signing.py
files scanned          : 1434
Mach-O slices parsed   : 2301
  of which unsigned    : 0
slices compared        : 2301
agreed with codesign   : 2301
mismatched             : 0

$ python3 utilities/compare_permissions.py
slices carrying both XML and DER : 947
  DER decode == plist decode     : 947
  contents disagreed             : 0
  decode errors                  : 0
  value shapes seen              : {'bool': 10748, 'str': 755, 'int': 50, 'list': 2900, 'dict': 153}
compared with codesign --xml     : 481
  identical                      : 481
  differed                       : 0
```

Both were re-run on the environment above, at commit
`d03baec`+`83eecf8`, and produced exactly these totals. The first compares identifier,
team identifier, CodeDirectory version, size, flags, slot counts, hash type and every
CDHash per algorithm against `codesign -d -vvv`, for every slice of every Mach-O under
`/usr/bin`, `/usr/lib`, `/usr/libexec`, `/sbin` and `/bin`.

**The totals depend on the corpus, not on the tool.** A different macOS version ships
a different `/usr/bin`, so `files scanned` and the slice counts will differ there. The
number that must stay at zero is `mismatched`; a non-zero count is a bug.

## The unit tests

Current path-containment fixes: **134 passed** on macOS arm64 with Python 3.12.
Eleven added cases cover parent and leaf symlink escapes, executable names,
Info.plist/CodeResources boundaries, nested code and valid in-bundle links.
No test reads a private file. The older 123-case run below is retained as history.

```console
$ python3 -m pip install -e ".[dev]"
$ python3 -m pytest -q
........................................................................ [ 58%]
...................................................                      [100%]
123 passed in 0.68s
```

Earlier run: **123 passed**, on macOS 26.7 arm64 with Python 3.12, after
installing pytest into a throwaway directory — the interpreter in the environment
block above (3.9.6) has no pytest, which is why the two corpus scripts are the ones
that run with nothing installed. The tests that build fixture binaries need Apple's
`clang` and `codesign` on `PATH`; where they are missing, those tests skip themselves
rather than fail, which is what the Linux job in CI exercises.

CI runs the same command on macOS 3.9 and 3.13 and on Linux 3.13, plus both corpus
scripts above; see [`.github/workflows/quality.yml`](../.github/workflows/quality.yml) and the
badge on the README.

## What is not covered by any of this

The README's `## Limitations` section is the authoritative list — no cryptographic
verification, code hashes not recomputed, requirements blobs not evaluated, nested
code checked for presence only, macOS framework bundles not walked. None of the checks
above contradict those; they are deliberate boundaries of the tool, not gaps in the
verification.
