# SealScope

SealScope inspects Mach-O containers, embedded signing metadata, declared XML/DER
entitlements, load-command hardening and bundle resource seals. It preserves the
baseline report format, finding rules, command options and exit statuses.

## Install and use

Python 3.9 or newer; no runtime dependencies.

```sh
python -m pip install -e ".[dev]"
sealscope /path/to/binary
sealscope --json /path/to/binary
sealscope --fail-on high -r /path/to/tree
sealscope --no-resources Example.app
python -m pytest -q
```

The exit statuses remain 0 for a completed review below the requested threshold,
1 when `--fail-on` is reached, and 2 when nothing can be reviewed.

```python
from sealscope import inspect_file, inspect_bundle

review = inspect_file("/usr/bin/otool")
for observation in review.seal_findings:
    print(observation.seal_severity, observation.seal_title)

bundle = inspect_bundle("Example.app")
print(bundle.export_record())
```

## Source organization

- `sealscope/containers/layout.py`: binary layouts and image records.
- `sealscope/containers/buffer_reader.py`: bounded container/load-command decoding.
- `signing_frames.py`, `permission_codec.py`: signing envelopes and XML/DER codecs.
- `observations.py`, `inspection.py`: classification policies and review orchestration.
- `bundle_seals.py`: bundle layout, resource rules, symlinks and digest comparisons.
- `presentation.py`, `console.py`: stable report formats and command entry point.
- `checks/`: renamed baseline regression tests.
- `utilities/`: comparisons with native `codesign` output.

Parsing metadata does not verify a CMS signature, certificate chain or the
permissions actually granted by the operating system. Those baseline boundaries
remain unchanged. See `guides/VERIFICATION.md` for earlier verification context,
`VALIDATION.md` for this rewrite's checks, and `ORIGIN.md` plus `LICENSE` for lineage.
