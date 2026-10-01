"""The command line: exit codes, filtering and the JSON contract.

The exit code is the part other programs depend on, so --fail-on has to mean
exactly what it says: 0 when nothing reached the threshold, 1 when something did,
2 only when there was nothing to audit at all. The JSON shape is the other
contract, so its keys are asserted rather than eyeballed.
"""
import json as seal_json
import os as seal_os
import pytest as seal_pytest
from sealscope import console as console
from sealscope.observations import RiskLevel as RiskLevel
from specimens import seal_requires_toolchain as seal_requires_toolchain
SEAL_SYSTEM_BINARY = '/usr/bin/otool'
seal_needs_system = seal_pytest.mark.skipif(not seal_os.path.exists(SEAL_SYSTEM_BINARY), reason='no system binary')

@seal_needs_system
def test_seal_default_run_succeeds(capsys):
    assert console.launch([SEAL_SYSTEM_BINARY, '--no-colour']) == 0

def test_seal_nothing_to_audit_exits_2(capsys):
    assert console.launch(['/nonexistent/sealscope/path']) == 2

def test_seal_a_directory_without_recursive_exits_2(tmp_path, capsys):
    assert console.launch([str(tmp_path)]) == 2
    assert '-r' in capsys.readouterr().err

@seal_requires_toolchain
def test_seal_fail_on_high_exits_1_when_a_high_finding_exists(seal_bin_entitled, capsys):
    assert console.launch([seal_bin_entitled, '--fail-on', 'high', '--no-colour']) == 1

@seal_needs_system
def test_seal_fail_on_high_exits_0_for_a_clean_binary(capsys):
    assert console.launch([SEAL_SYSTEM_BINARY, '--fail-on', 'high', '--no-colour']) == 0

@seal_needs_system
def test_seal_fail_on_never_is_the_default(capsys):
    """Auditing must not fail a build unless the caller asked it to."""
    assert console.launch([SEAL_SYSTEM_BINARY, '--no-colour']) == 0

@seal_requires_toolchain
def test_seal_fail_on_info_catches_everything(seal_bin_linker_signed, capsys):
    assert console.launch([seal_bin_linker_signed, '--fail-on', 'info', '--no-colour']) == 1

@seal_requires_toolchain
def test_seal_json_output_shape(seal_bin_entitled, capsys):
    console.launch([seal_bin_entitled, '--json'])
    seal_doc = seal_json.loads(capsys.readouterr().out)
    assert set(seal_doc) == {'summary', 'files'}
    assert seal_doc['summary']['files'] == 1
    assert seal_doc['summary']['by_severity']['high'] >= 1
    seal_f = seal_doc['files'][0]
    assert seal_f['path'] == seal_bin_entitled
    seal_sl = seal_f['slices'][0]
    for seal_key in ('arch', 'filetype', 'signed', 'identifier', 'cdhash', 'hash_type', 'cs_flags', 'entitlements', 'findings'):
        assert seal_key in seal_sl
    seal_finding = seal_sl['findings'][0]
    assert set(seal_finding) >= {'id', 'severity', 'title', 'detail'}

@seal_requires_toolchain
def test_seal_min_severity_hides_lower_findings(seal_bin_entitled, capsys):
    console.launch([seal_bin_entitled, '--min-severity', 'high', '--no-colour'])
    output = capsys.readouterr().out
    assert 'HIGH' in output
    assert 'LOW ' not in output and 'INFO' not in output

@seal_requires_toolchain
def test_seal_verbose_includes_the_reasoning(seal_bin_entitled, capsys):
    console.launch([seal_bin_entitled, '-v', '--no-colour'])
    output = capsys.readouterr().out
    assert 'identifier :' in output
    assert 'attach' in output
    assert 'hardened' in output

@seal_requires_toolchain
def test_seal_summary_mode_prints_totals_only(seal_bin_entitled, capsys):
    console.launch([seal_bin_entitled, '--summary'])
    output = capsys.readouterr().out
    assert 'files audited' in output
    assert 'most common findings' in output
    assert seal_bin_entitled not in output

@seal_needs_system
def test_seal_no_colour_emits_no_escape_sequences(capsys):
    console.launch([SEAL_SYSTEM_BINARY, '--no-colour', '--min-severity', 'info'])
    assert '\x1b[' not in capsys.readouterr().out

@seal_requires_toolchain
def test_seal_recursive_walk_finds_binaries(seal_workdir, seal_bin_linker_signed, capsys):
    assert console.launch([seal_workdir, '-r', '--json']) == 0
    seal_doc = seal_json.loads(capsys.readouterr().out)
    assert seal_doc['summary']['files'] >= 1
    assert all((seal_f['path'].startswith(seal_workdir) for seal_f in seal_doc['files']))

@seal_requires_toolchain
def test_seal_recursive_walk_skips_non_macho_files(seal_workdir, seal_bin_linker_signed, capsys):
    """main.c and the plist live in the fixture dir and must not be audited."""
    console.launch([seal_workdir, '-r', '--json'])
    seal_doc = seal_json.loads(capsys.readouterr().out)
    assert not any((seal_f['path'].endswith(('.c', '.plist')) for seal_f in seal_doc['files']))

def test_seal_parser_rejects_an_unknown_severity():
    with seal_pytest.raises(SystemExit):
        console.make_arguments().parse_args(['x', '--min-severity', 'catastrophic'])

def test_seal_parser_defaults():
    options = console.make_arguments().parse_args(['x'])
    assert options.min_severity == RiskLevel.SEAL_INFO
    assert options.fail_on == 'never'
    assert not options.recursive and (not options.json) and (not options.verbose)

def test_seal_path_is_required():
    with seal_pytest.raises(SystemExit):
        console.make_arguments().parse_args([])

def test_seal_looks_macho_recognises_the_magics(tmp_path):
    for seal_magic in (b'\xcf\xfa\xed\xfe', b'\xca\xfe\xba\xbe', b'\xca\xfe\xba\xbf'):
        seal_p = tmp_path / ('m' + seal_magic.hex())
        seal_p.write_bytes(seal_magic + b'\x00' * 32)
        assert console.seal_looks_macho(str(seal_p))
    seal_p = tmp_path / 'script'
    seal_p.write_text('#!/bin/sh\n')
    assert not console.seal_looks_macho(str(seal_p))
