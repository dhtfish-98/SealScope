"""Cross-check entitlement decoding three ways, over a real corpus.

macOS carries entitlements twice — the XML plist in slot 5 and a DER encoding in
slot 7 — and modern kernels prefer the DER form. This script checks that:

  1. sealscope's DER decoder produces exactly what its plist decoder produces, for
     every binary that ships both; and
  2. sealscope's plist decoding matches ``codesign -d --entitlements - --xml``.

The first check is what gives the hand-written DER reader its credibility: the two
encodings are independent, so agreeing on hundreds of real binaries — including
nested arrays and dictionaries — is hard to do by accident.

    python tools/compare_permissions.py [path ...]
"""
from __future__ import annotations as seal_annotations
import glob as seal_glob
import os as seal_os
import plistlib as seal_plistlib
import subprocess as seal_subprocess
import sys as seal_sys
seal_sys.path.insert(0, seal_os.path.dirname(seal_os.path.dirname(seal_os.path.abspath(__file__))))
from sealscope import signing_frames as signing_frames, permission_codec as seal_ent, containers as containers
SEAL_DEFAULT_ROOTS = ['/usr/bin/*', '/usr/lib/*.dylib', '/usr/libexec/*', '/sbin/*', '/bin/*', '/System/Library/CoreServices/*']

def launch(tokens):
    seal_patterns = tokens[1:] or SEAL_DEFAULT_ROOTS
    seal_files = sorted({seal_f for seal_p in seal_patterns for seal_f in seal_glob.glob(seal_p) if seal_os.path.isfile(seal_f)})
    seal_both = seal_agreed = 0
    seal_errors, seal_diffs = ([], [])
    seal_shapes = {'bool': 0, 'str': 0, 'int': 0, 'list': 0, 'dict': 0}
    for seal_f in seal_files:
        try:
            payload, seal_sls = containers.read_container(seal_f)
        except (containers.ContainerFault, OSError):
            continue
        for seal_sl in seal_sls:
            if not seal_sl.seal_code_signature:
                continue
            try:
                seal_sig = signing_frames.read_envelope(payload, seal_sl.seal_offset + seal_sl.seal_code_signature[0], seal_sl.seal_code_signature[1])
            except signing_frames.EnvelopeFault:
                continue
            if not (seal_sig.seal_entitlements_xml and seal_sig.seal_entitlements_der):
                continue
            seal_both += 1
            try:
                seal_xml = seal_ent.seal_parse_plist(seal_sig.seal_entitlements_xml)
            except ValueError as seal_exc:
                seal_errors.append((seal_f, seal_sl.seal_arch, 'plist: %s' % seal_exc))
                continue
            try:
                seal_der = seal_ent.seal_parse_der(seal_sig.seal_entitlements_der)
            except seal_ent.PermissionEncodingFault as seal_exc:
                seal_errors.append((seal_f, seal_sl.seal_arch, 'der: %s' % seal_exc))
                continue
            for seal_v in seal_xml.values():
                label = type(seal_v).__name__
                if label in seal_shapes:
                    seal_shapes[label] += 1
            seal_delta = seal_ent.seal_compare(seal_xml, seal_der)
            if seal_delta:
                seal_diffs.append((seal_f, seal_sl.seal_arch, seal_delta[:3]))
            else:
                seal_agreed += 1
    seal_checked_cs = seal_matched_cs = 0
    seal_cs_diffs = []
    for seal_f in seal_files:
        seal_r = seal_subprocess.run(['codesign', '-d', '--entitlements', '-', '--xml', seal_f], capture_output=True)
        if seal_r.returncode != 0 or not seal_r.stdout.strip():
            continue
        try:
            seal_truth = seal_plistlib.loads(seal_r.stdout.strip())
            payload, seal_sls = containers.read_container(seal_f)
        except Exception:
            continue
        seal_native = [seal_s_value for seal_s_value in seal_sls if seal_s_value.seal_arch in ('arm64e', 'arm64')] or seal_sls
        seal_sl = seal_native[0]
        if not seal_sl.seal_code_signature:
            continue
        try:
            seal_sig = signing_frames.read_envelope(payload, seal_sl.seal_offset + seal_sl.seal_code_signature[0], seal_sl.seal_code_signature[1])
            seal_mine = seal_ent.seal_parse_plist(seal_sig.seal_entitlements_xml) if seal_sig.seal_entitlements_xml else {}
        except Exception:
            continue
        seal_checked_cs += 1
        if seal_mine == seal_truth:
            seal_matched_cs += 1
        else:
            seal_cs_diffs.append((seal_f, sorted(set(seal_mine) ^ set(seal_truth))[:3]))
    print('slices carrying both XML and DER : %d' % seal_both)
    print('  DER decode == plist decode     : %d' % seal_agreed)
    print('  contents disagreed             : %d' % len(seal_diffs))
    print('  decode errors                  : %d' % len(seal_errors))
    print('  value shapes seen              : %s' % seal_shapes)
    print('compared with codesign --xml     : %d' % seal_checked_cs)
    print('  identical                      : %d' % seal_matched_cs)
    print('  differed                       : %d' % len(seal_cs_diffs))
    for item in (seal_errors + seal_diffs + seal_cs_diffs)[:20]:
        print('  PROBLEM', item)
    return 1 if seal_errors or seal_diffs or seal_cs_diffs else 0
if __name__ == '__main__':
    raise SystemExit(launch(seal_sys.argv))
