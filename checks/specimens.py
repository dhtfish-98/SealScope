"""Test binaries built on demand with clang(1) and codesign(1).

Ground truth by construction: rather than asserting against a binary that happens
to be on the machine, each fixture is compiled and signed with the properties the
test needs, so the expected finding is known before the tool is run. Fixtures are
built once per session into a temp directory.

Anything that needs the Apple toolchain is skipped where it is unavailable, so the
pure-parser tests still run elsewhere.
"""
from __future__ import annotations as seal_annotations
import os as seal_os
import shutil as seal_shutil
import struct as seal_struct
import subprocess as seal_subprocess
import tempfile as seal_tempfile
import pytest as seal_pytest
SEAL_HAVE_TOOLCHAIN = all((seal_shutil.which(seal_t_value) for seal_t_value in ('clang', 'codesign')))
seal_requires_toolchain = seal_pytest.mark.skipif(not SEAL_HAVE_TOOLCHAIN, reason='needs Apple clang and codesign')
SEAL_MAIN_C = 'int main(void){return 0;}\n'
SEAL_ENTITLEMENTS_PLIST = '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0"><dict>\n  <key>com.apple.security.get-task-allow</key><true/>\n  <key>com.apple.security.cs.disable-library-validation</key><true/>\n  <key>com.apple.security.cs.allow-jit</key><true/>\n  <key>com.apple.security.app-sandbox</key><true/>\n  <key>com.apple.security.cs.allow-unsigned-executable-memory</key><false/>\n  <key>keychain-access-groups</key><array><string>com.example.group</string></array>\n  <key>com.example.count</key><integer>3</integer>\n  <key>com.example.name</key><string>hello</string>\n</dict></plist>\n'

@seal_pytest.fixture(scope='session')
def seal_workdir():
    seal_d = seal_tempfile.mkdtemp(prefix='sealscope-tests-')
    yield seal_d
    seal_shutil.rmtree(seal_d, ignore_errors=True)

def seal_compile(seal_workdir: str, label: str, *seal_extra: str) -> str:
    seal_src = seal_os.path.join(seal_workdir, 'main.c')
    if not seal_os.path.exists(seal_src):
        with open(seal_src, 'w', encoding='utf-8') as stream:
            stream.write(SEAL_MAIN_C)
    output = seal_os.path.join(seal_workdir, label)
    seal_subprocess.run(['clang', '-arch', 'arm64', *seal_extra, '-o', output, seal_src], check=True, capture_output=True)
    return output

def seal_sign(location_path: str, *options: str) -> str:
    seal_subprocess.run(['codesign', '-f', '-s', '-', *options, location_path], check=True, capture_output=True)
    return location_path

@seal_pytest.fixture(scope='session')
def seal_bin_linker_signed(seal_workdir):
    """Straight out of clang: ad-hoc, linker-signed, no entitlements."""
    return seal_compile(seal_workdir, 'linker_signed')

@seal_pytest.fixture(scope='session')
def seal_bin_unsigned(seal_workdir):
    seal_p = seal_compile(seal_workdir, 'unsigned_src')
    output = seal_os.path.join(seal_workdir, 'unsigned')
    seal_shutil.copy(seal_p, output)
    seal_subprocess.run(['codesign', '--remove-signature', output], check=True, capture_output=True)
    return output

@seal_pytest.fixture(scope='session')
def seal_bin_hardened(seal_workdir):
    seal_p = seal_compile(seal_workdir, 'hardened_src')
    output = seal_os.path.join(seal_workdir, 'hardened')
    seal_shutil.copy(seal_p, output)
    return seal_sign(output, '-o', 'runtime')

@seal_pytest.fixture(scope='session')
def seal_bin_entitled(seal_workdir):
    seal_p = seal_compile(seal_workdir, 'entitled_src')
    output = seal_os.path.join(seal_workdir, 'entitled')
    seal_shutil.copy(seal_p, output)
    seal_ents = seal_os.path.join(seal_workdir, 'ents.plist')
    with open(seal_ents, 'w', encoding='utf-8') as stream:
        stream.write(SEAL_ENTITLEMENTS_PLIST)
    return seal_sign(output, '--entitlements', seal_ents)

@seal_pytest.fixture(scope='session')
def seal_bin_no_pie(seal_workdir, seal_bin_linker_signed):
    """MH_PIE cleared by editing the header.

    The arm64 linker ignores -no_pie, so the flag is cleared directly. That is the
    precise thing the rule reads, and it keeps the fixture deterministic.
    """
    output = seal_os.path.join(seal_workdir, 'no_pie')
    with open(seal_bin_linker_signed, 'rb') as stream:
        payload = bytearray(stream.read())
    seal_flags = seal_struct.unpack_from('<I', payload, 24)[0]
    seal_struct.pack_into('<I', payload, 24, seal_flags & ~2097152)
    with open(output, 'wb') as stream:
        stream.write(payload)
    return output
