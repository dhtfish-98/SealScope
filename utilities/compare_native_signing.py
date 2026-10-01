"""Cross-check every field sealscope parses against codesign(1), over a real corpus.

This is the tool's correctness evidence. It walks a set of system paths, parses each
Mach-O slice with sealscope, asks codesign for the same facts, and compares them
field by field. Every CodeDirectory is matched to the CandidateCDHashFull line for
its own hash algorithm, because a binary can carry several directories and codesign
prints one candidate per algorithm.

    python tools/compare_native_signing.py [path ...]

Exits non-zero if anything mismatches, so it can gate a change.
"""
from __future__ import annotations as seal_annotations
import glob as seal_glob
import os as seal_os
import re as seal_re
import subprocess as seal_subprocess
import sys as seal_sys
seal_sys.path.insert(0, seal_os.path.dirname(seal_os.path.dirname(seal_os.path.abspath(__file__))))
from sealscope import signing_frames as signing_frames, containers as containers
SEAL_DEFAULT_ROOTS = ['/usr/bin/*', '/usr/lib/*.dylib', '/usr/libexec/*', '/sbin/*', '/bin/*']
SEAL_FIELDS = [('ident', '^Identifier=(.*)$'), ('team', '^TeamIdentifier=(.*)$'), ('cdver', 'CodeDirectory v=([0-9a-f]+)'), ('cdsize', 'CodeDirectory v=\\w+ size=(\\d+)'), ('flags', 'CodeDirectory v=\\S+ size=\\d+ flags=(0x[0-9a-f]+)'), ('hashes', 'hashes=(\\d+\\+\\d+)'), ('htype', '^Hash type=(\\S+) size')]

def seal_codesign_facts(location_path: str, seal_arch: str):
    seal_r = seal_subprocess.run(['codesign', '-d', '-vvv', '--arch', seal_arch, location_path], capture_output=True, text=True)
    seal_text = seal_r.stderr + seal_r.stdout
    output = {}
    for seal_key, seal_pat in SEAL_FIELDS:
        seal_m = seal_re.search(seal_pat, seal_text, seal_re.M)
        if seal_m:
            output[seal_key] = seal_m.group(1)
    output['candidates'] = dict(seal_re.findall('CandidateCDHashFull (\\w+)=([0-9a-f]+)', seal_text))
    return output

def launch(tokens):
    seal_patterns = tokens[1:] or SEAL_DEFAULT_ROOTS
    seal_files = sorted({seal_f for seal_p in seal_patterns for seal_f in seal_glob.glob(seal_p) if seal_os.path.isfile(seal_f)})
    seal_slices = seal_compared = seal_agreed = 0
    seal_unsigned = 0
    seal_mismatches = []
    for seal_f in seal_files:
        try:
            payload, seal_sls = containers.read_container(seal_f)
        except containers.ContainerFault:
            continue
        except OSError:
            continue
        for seal_sl in seal_sls:
            seal_slices += 1
            if not seal_sl.seal_code_signature:
                seal_unsigned += 1
                continue
            try:
                seal_sig = signing_frames.read_envelope(payload, seal_sl.seal_offset + seal_sl.seal_code_signature[0], seal_sl.seal_code_signature[1])
            except signing_frames.EnvelopeFault as seal_exc:
                seal_mismatches.append((seal_f, seal_sl.seal_arch, 'parse failed: %s' % seal_exc))
                continue
            seal_truth = seal_codesign_facts(seal_f, seal_sl.seal_arch)
            if not seal_truth.get('candidates'):
                continue
            seal_chosen = max(seal_sig.seal_all_directories, key=lambda seal_c: seal_c.seal_hash_type)
            seal_compared += 1
            seal_bad = []
            for seal_key, seal_want, seal_got in [('ident', seal_truth.get('ident'), seal_chosen.seal_identifier), ('team', seal_truth.get('team', 'not set'), seal_chosen.seal_team_id or 'not set'), ('cdsize', seal_truth.get('cdsize'), str(seal_chosen.seal_raw_length)), ('hashes', seal_truth.get('hashes'), '%d+%d' % (seal_chosen.seal_n_code_slots, seal_chosen.seal_n_special_slots)), ('htype', seal_truth.get('htype'), seal_chosen.seal_hash_name)]:
                if seal_want is not None and seal_want != seal_got:
                    seal_bad.append('%s: codesign=%r sealscope=%r' % (seal_key, seal_want, seal_got))
            if seal_truth.get('cdver') and int(seal_truth['cdver'], 16) != seal_chosen.seal_version:
                seal_bad.append('version: codesign=%s sealscope=%x' % (seal_truth['cdver'], seal_chosen.seal_version))
            if seal_truth.get('flags') and int(seal_truth['flags'], 16) != seal_chosen.seal_flags:
                seal_bad.append('flags: codesign=%s sealscope=0x%x' % (seal_truth['flags'], seal_chosen.seal_flags))
            for seal_cd in seal_sig.seal_all_directories:
                seal_want = seal_truth['candidates'].get(seal_cd.seal_hash_name)
                if seal_want and seal_want != (seal_cd.seal_cdhash or ''):
                    seal_bad.append('cdhash[%s]: codesign=%s sealscope=%s' % (seal_cd.seal_hash_name, seal_want, seal_cd.seal_cdhash))
            if seal_bad:
                seal_mismatches.append((seal_f, seal_sl.seal_arch, '; '.join(seal_bad)))
            else:
                seal_agreed += 1
    print('files scanned          : %d' % len(seal_files))
    print('Mach-O slices parsed   : %d' % seal_slices)
    print('  of which unsigned    : %d' % seal_unsigned)
    print('slices compared        : %d' % seal_compared)
    print('agreed with codesign   : %d' % seal_agreed)
    print('mismatched             : %d' % len(seal_mismatches))
    for seal_f, seal_a, seal_why in seal_mismatches[:20]:
        print('  MISMATCH %s [%s] %s' % (seal_f, seal_a, seal_why))
    return 1 if seal_mismatches else 0
if __name__ == '__main__':
    raise SystemExit(launch(seal_sys.argv))
