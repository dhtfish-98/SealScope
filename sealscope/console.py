"""``sealscope`` command line.

    sealscope <path>...              audit files, directories are walked
    sealscope Foo.app                audit a bundle: its binary and its resource seal
    sealscope --json <path>...       machine-readable output
    sealscope -v <path>...           include the reasoning for each finding
    sealscope --min-severity high    only the findings that matter most

Exit status: 0 when nothing at or above ``--fail-on`` was found, 1 when something
was, 2 when no input could be read at all. That makes it usable as a CI gate
without parsing the output.
"""
from __future__ import annotations as seal_annotations
import argparse as seal_argparse
import os as seal_os
import sys as seal_sys
from typing import List as seal_List
from . import __version__ as __version__, bundle_seals as bundle_seals
from .inspection import FileReview as FileReview, inspect_bundle as inspect_bundle, inspect_file as inspect_file
from .observations import SEAL_SEVERITY_ORDER as SEAL_SEVERITY_ORDER, RiskLevel as RiskLevel
from .presentation import format_json as format_json, format_text as format_text, tally_reports as tally_reports
__all__ = ['launch', 'make_arguments']
SEAL_SEVERITIES = [RiskLevel.SEAL_HIGH, RiskLevel.SEAL_MEDIUM, RiskLevel.SEAL_LOW, RiskLevel.SEAL_INFO]

def seal_looks_macho(location_path: str) -> bool:
    try:
        with open(location_path, 'rb') as stream:
            seal_head = stream.read(4)
    except OSError:
        return False
    return seal_head in (b'\xcf\xfa\xed\xfe', b'\xce\xfa\xed\xfe', b'\xfe\xed\xfa\xcf', b'\xfe\xed\xfa\xce', b'\xca\xfe\xba\xbe', b'\xca\xfe\xba\xbf')

def seal_collect(seal_paths: seal_List[str], seal_recurse: bool) -> seal_List[str]:
    output: seal_List[str] = []
    for seal_p in seal_paths:
        if seal_os.path.isdir(seal_p):
            if not seal_recurse:
                print('sealscope: %s is a directory (use -r to walk it)' % seal_p, file=seal_sys.stderr)
                continue
            for seal_root, seal_dirs, seal_files in seal_os.walk(seal_p):
                for label in sorted(seal_files):
                    seal_f = seal_os.path.join(seal_root, label)
                    if not seal_os.path.islink(seal_f) and seal_looks_macho(seal_f):
                        output.append(seal_f)
        else:
            output.append(seal_p)
    return output

def make_arguments() -> seal_argparse.ArgumentParser:
    seal_p = seal_argparse.ArgumentParser(prog='sealscope', description='Audit Mach-O code signatures, entitlements and load-command hardening. Structural analysis only: it reports what a binary claims, and does not verify the CMS signature — use `codesign -v` for that.')
    seal_p.add_argument('--version', action='version', version='sealscope %s' % __version__)
    seal_p.add_argument('paths', nargs='+', metavar='PATH', help='files to audit; directories need -r')
    seal_p.add_argument('-r', '--recursive', action='store_true', help='walk directories, auditing every Mach-O found')
    seal_p.add_argument('-j', '--json', action='store_true', help='emit JSON instead of the text report')
    seal_p.add_argument('-v', '--verbose', action='store_true', help='show signature details and the reasoning for each finding')
    seal_p.add_argument('--min-severity', choices=SEAL_SEVERITIES, default=RiskLevel.SEAL_INFO, help='hide findings below this severity (default: info)')
    seal_p.add_argument('--fail-on', choices=SEAL_SEVERITIES + ['never'], default='never', help='exit 1 if any finding reaches this severity (default: never)')
    seal_p.add_argument('--summary', action='store_true', help='print only the totals, not the per-file report')
    seal_p.add_argument('--no-resources', action='store_true', help='for a bundle, audit the binary but not the resource seal (hashing every resource is the slow part on a large app)')
    seal_p.add_argument('--no-colour', action='store_true', help='never colourise output')
    return seal_p

def launch(tokens: seal_List[str]=None) -> int:
    options = make_arguments().parse_args(tokens)
    seal_bundles: seal_List[str] = []
    seal_others: seal_List[str] = []
    for location_path in options.paths:
        (seal_bundles if bundle_seals.seal_find_bundle(location_path) else seal_others).append(location_path)
    seal_files = seal_collect(seal_others, options.recursive)
    if not seal_files and (not seal_bundles):
        print('sealscope: nothing to audit', file=seal_sys.stderr)
        return 2
    seal_reports: seal_List[FileReview] = [inspect_bundle(seal_b, seal_check_resources=not options.no_resources) for seal_b in seal_bundles]
    seal_reports += [inspect_file(seal_f) for seal_f in seal_files]
    if all((seal_r.seal_error for seal_r in seal_reports)):
        for seal_r in seal_reports:
            print('sealscope: %s: %s' % (seal_r.location_path, seal_r.seal_error), file=seal_sys.stderr)
        return 2
    if options.json:
        print(format_json(seal_reports))
    elif options.summary:
        seal_s_value = tally_reports(seal_reports)
        print('files audited        : %d' % seal_s_value['files'])
        print('files with findings  : %d' % seal_s_value['files_with_findings'])
        print('unsigned slices      : %d' % seal_s_value['unsigned_slices'])
        for seal_sev in SEAL_SEVERITIES:
            print('%-21s: %d' % (seal_sev, seal_s_value['by_severity'].get(seal_sev, 0)))
        seal_top = list(seal_s_value['by_finding'].items())[:15]
        if seal_top:
            print('\nmost common findings:')
            for seal_fid, seal_n_value in seal_top:
                print('  %5d  %s' % (seal_n_value, seal_fid))
    else:
        seal_text = format_text(seal_reports, seal_min_severity=options.min_severity, seal_verbose=options.verbose, seal_colour=False if options.no_colour else None)
        if seal_text.strip():
            print(seal_text, end='' if seal_text.endswith('\n') else '\n')
        else:
            print('no findings at or above %s' % options.min_severity)
    if options.fail_on != 'never':
        seal_cutoff = SEAL_SEVERITY_ORDER[options.fail_on]
        for seal_r in seal_reports:
            for seal_f in seal_r.observations:
                if SEAL_SEVERITY_ORDER.get(seal_f.seal_severity, 9) <= seal_cutoff:
                    return 1
    return 0
if __name__ == '__main__':
    seal_sys.exit(launch())
