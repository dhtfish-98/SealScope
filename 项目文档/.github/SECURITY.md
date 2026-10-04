# Security policy

sealscope parses files it did not produce — Mach-O binaries, fat archives, code
signature blobs and bundle resource seals — and it is meant to be pointed at files
that may be malformed or deliberately hostile. A parser that crashes, hangs or
over-reads on such input is a bug worth reporting.

## Reporting

Use GitHub's [private vulnerability
reporting](https://github.com/dhtfish-98/SealScope/security/advisories/new) for
anything that could affect someone running the tool against a file they did not
create. Ordinary correctness bugs — a mismatched rule, a wrong finding — are fine as
a normal GitHub issue.

Please include the tool's version or commit, the platform and Python version, and
either the input file or a description precise enough to rebuild it. Do not attach a
file you are not allowed to share.

## In scope

- Crashes, unbounded memory use, hangs and over-reads in `sealscope`'s parsers when
  fed malformed input.
- Resource-seal checking that modifies, writes to, or executes anything it reads.

## Out of scope, by design

- **sealscope does not verify signatures**, and says so in the README. It will
  happily report the claims of a forged signature. "It said this binary is fine and
  it is not" is `codesign -v`'s job, not a vulnerability here.
- Reports about auditing binaries you do not own or are not authorised to inspect.

Reports are handled on a best-effort basis, and I will credit a reporter who wants
credit once a fix is out.
