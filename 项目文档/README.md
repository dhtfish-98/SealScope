> 目录已整理：文档在「项目文档」，构建、缓存与暂存输入在「Build」。从仓库根目录运行 `python3 构建.py --build`；如需使用本文原有源码命令，先运行 `python3 构建.py --stage --ci`，再进入 `Build/源码`。暂存会恢复原输入路径。现有版本和历史验证记录按各自提交理解。

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
for observation in review.observations:
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


## Current maintenance record

The current package version is **0.2.2** and its maintenance name is **dhtfish98**. This package author entry records the present maintenance period. Earlier package/release metadata and historical source-lineage records may retain `bitfish886`; those records are preserved for their original publication periods.

This release rejects Mach-O slices, embedded signature blobs and CodeDirectory fields that claim bytes outside their declared ranges. The rejection is a structural check on local input; it does not establish signer trust, signature validity or OS-granted permissions. See `VALIDATION.md` for matching synthetic tests and build evidence.

Version 0.2.2 also updates the private vulnerability reporting link to this repository and aligns the source release with the current documentation layout. Parser and policy code is unchanged from 0.2.1; the runtime version string is updated.

Upstream attribution, third-party notices and licenses remain unchanged. The current implementation was revised on the public 0.2.0 baseline; an earlier unpublished package was not reused.

Actual task authorization, any effect of safeguards on that task, and CVP application eligibility remain **OPEN**. Package construction and existing engineering evidence do not establish CVP approval.
