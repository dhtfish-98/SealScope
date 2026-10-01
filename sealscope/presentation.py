"""Rendering: a readable terminal report and a stable JSON document.

The JSON shape is the contract for anything scripting this tool, so it is produced
from the report dataclasses rather than from the text, and the text is never parsed
back. Colour is only emitted when stdout is a terminal.
"""
from __future__ import annotations as seal_annotations
import json as seal_json
import sys as seal_sys
from typing import Any as seal_Any, Dict as seal_Dict, Iterable as seal_Iterable, List as seal_List
from .inspection import FileReview as FileReview
from .observations import SEAL_SEVERITY_ORDER as SEAL_SEVERITY_ORDER, RiskLevel as RiskLevel
__all__ = ['format_text', 'format_json', 'tally_reports']
SEAL__COLOURS = {RiskLevel.SEAL_HIGH: '\x1b[31m', RiskLevel.SEAL_MEDIUM: '\x1b[33m', RiskLevel.SEAL_LOW: '\x1b[36m', RiskLevel.SEAL_INFO: '\x1b[90m'}
SEAL__RESET = '\x1b[0m'
SEAL__BOLD = '\x1b[1m'
SEAL__MARKS = {RiskLevel.SEAL_HIGH: 'HIGH', RiskLevel.SEAL_MEDIUM: 'MED ', RiskLevel.SEAL_LOW: 'LOW ', RiskLevel.SEAL_INFO: 'INFO'}

def seal_use_colour(seal_force: bool=False) -> bool:
    return seal_force or seal_sys.stdout.isatty()

def seal_wrap(seal_text: str, seal_width: int, seal_indent: str) -> seal_List[str]:
    seal_words, seal_lines, seal_cur = (seal_text.split(), [], '')
    for seal_w_value in seal_words:
        if seal_cur and len(seal_cur) + 1 + len(seal_w_value) > seal_width:
            seal_lines.append(seal_indent + seal_cur)
            seal_cur = seal_w_value
        else:
            seal_cur = (seal_cur + ' ' + seal_w_value).strip()
    if seal_cur:
        seal_lines.append(seal_indent + seal_cur)
    return seal_lines

def format_text(seal_reports: seal_Iterable[FileReview], seal_min_severity: str=RiskLevel.SEAL_INFO, seal_verbose: bool=False, seal_colour: bool=None, seal_width: int=78) -> str:
    if seal_colour is None:
        seal_colour = seal_use_colour()
    seal_cutoff = SEAL_SEVERITY_ORDER.get(seal_min_severity, 3)
    output: seal_List[str] = []
    for seal_rep in seal_reports:
        seal_shown = [seal_f for seal_f in seal_rep.observations if SEAL_SEVERITY_ORDER.get(seal_f.seal_severity, 9) <= seal_cutoff]
        if seal_rep.seal_error:
            output.append('%s%s%s' % (SEAL__BOLD if seal_colour else '', seal_rep.location_path, SEAL__RESET if seal_colour else ''))
            output.append('    not audited: %s' % seal_rep.seal_error)
            output.append('')
            continue
        if not seal_shown and (not seal_verbose):
            continue
        seal_head = seal_rep.location_path
        if seal_colour:
            seal_head = SEAL__BOLD + seal_head + SEAL__RESET
        output.append(seal_head)
        if seal_verbose and seal_rep.bundle_seals:
            seal_seal = seal_rep.bundle_seals
            output.extend(seal_wrap('resource seal %s: %d entries, %d hashed, %d nested (requirement not evaluated), %d mismatched, %d missing, %d unsealed file(s)' % (seal_seal.get('seal'), seal_seal.get('sealed'), seal_seal.get('hashed'), seal_seal.get('nested_not_evaluated'), seal_seal.get('mismatched'), seal_seal.get('missing'), seal_seal.get('unsealed_files')), seal_width, '      '))
        for seal_sl in seal_rep.seal_slices:
            seal_bits = [seal_sl.seal_arch, seal_sl.seal_filetype]
            if seal_sl.seal_signed:
                seal_bits.append(seal_sl.seal_hash_type or '?')
                seal_bits.append('adhoc' if 'CS_ADHOC' in seal_sl.seal_cs_flags else seal_sl.seal_team_id or 'no-team')
            else:
                seal_bits.append('unsigned')
            output.append('  [%s]' % '  '.join(seal_bits))
            if seal_verbose and seal_sl.seal_signed:
                output.append('      identifier : %s' % (seal_sl.seal_identifier or '-'))
                output.append('      cdhash     : %s' % (seal_sl.seal_cdhash or '-'))
                if seal_sl.seal_cs_flags:
                    output.append('      cs flags   : %s' % ', '.join(seal_sl.seal_cs_flags))
                if seal_sl.seal_exec_seg_flags:
                    output.append('      exec seg   : %s' % ', '.join(seal_sl.seal_exec_seg_flags))
                if seal_sl.permission_codec:
                    output.append('      entitlements (%s): %d' % (seal_sl.seal_entitlement_source, len(seal_sl.permission_codec)))
            for seal_f in seal_sl.observations:
                if SEAL_SEVERITY_ORDER.get(seal_f.seal_severity, 9) > seal_cutoff:
                    continue
                seal_mark = SEAL__MARKS.get(seal_f.seal_severity, seal_f.seal_severity.upper())
                if seal_colour:
                    seal_mark = SEAL__COLOURS.get(seal_f.seal_severity, '') + seal_mark + SEAL__RESET
                output.append('      %s  %s' % (seal_mark, seal_f.seal_title))
                if seal_verbose:
                    output.extend(seal_wrap(seal_f.seal_detail, seal_width - 14, ' ' * 12))
        seal_extra = [seal_f for seal_f in seal_rep.seal_extra_findings if SEAL_SEVERITY_ORDER.get(seal_f.seal_severity, 9) <= seal_cutoff]
        if seal_extra:
            output.append('  [bundle resources]')
            for seal_f in seal_extra:
                seal_mark = SEAL__MARKS.get(seal_f.seal_severity, seal_f.seal_severity.upper())
                if seal_colour:
                    seal_mark = SEAL__COLOURS.get(seal_f.seal_severity, '') + seal_mark + SEAL__RESET
                output.append('      %s  %s' % (seal_mark, seal_f.seal_title))
                if seal_verbose:
                    output.extend(seal_wrap(seal_f.seal_detail, seal_width - 14, ' ' * 12))
        output.append('')
    return '\n'.join(output)

def tally_reports(seal_reports: seal_List[FileReview]) -> seal_Dict[str, seal_Any]:
    seal_totals = {seal_s_value: 0 for seal_s_value in SEAL_SEVERITY_ORDER}
    seal_by_id: seal_Dict[str, int] = {}
    seal_files_with = 0
    seal_unsigned = 0
    for seal_rep in seal_reports:
        seal_fs = seal_rep.observations
        if seal_fs:
            seal_files_with += 1
        for seal_f in seal_fs:
            seal_totals[seal_f.seal_severity] = seal_totals.get(seal_f.seal_severity, 0) + 1
            seal_by_id[seal_f.seal_id] = seal_by_id.get(seal_f.seal_id, 0) + 1
        seal_unsigned += sum((1 for seal_s_value in seal_rep.seal_slices if not seal_s_value.seal_signed))
    return {'files': len(seal_reports), 'files_with_findings': seal_files_with, 'unsigned_slices': seal_unsigned, 'by_severity': seal_totals, 'by_finding': dict(sorted(seal_by_id.items(), key=lambda seal_kv: -seal_kv[1]))}

def format_json(seal_reports: seal_List[FileReview], seal_indent: int=2) -> str:
    return seal_json.dumps({'summary': tally_reports(seal_reports), 'files': [seal_r.export_record() for seal_r in seal_reports]}, indent=seal_indent, default=str)
