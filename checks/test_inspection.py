"""The audit rules, against binaries built to have the property under test.

Each fixture is compiled and signed so the expected finding is known before the
tool runs — an ad-hoc binary really is ad-hoc, an entitled binary really carries
those entitlements. That is what makes a passing assertion mean something.

The rules also have to stay quiet where quiet is correct: a rule that fires on
every Apple binary is a rule nobody reads, so the negative assertions here matter
as much as the positive ones.
"""
import os as seal_os
import pytest as seal_pytest
from sealscope import inspection as inspection
from sealscope.observations import RiskLevel as RiskLevel, seal_entitlement_risk as seal_entitlement_risk
from specimens import seal_requires_toolchain as seal_requires_toolchain

def seal_ids_value(presentation):
    return {seal_f.seal_id for seal_f in presentation.observations}

def seal_severity_of(presentation, seal_finding_id):
    for seal_f in presentation.observations:
        if seal_f.seal_id == seal_finding_id:
            return seal_f.seal_severity
    raise AssertionError('no finding %r in %s' % (seal_finding_id, sorted(seal_ids_value(presentation))))

@seal_requires_toolchain
def test_seal_unsigned_executable_is_high(seal_bin_unsigned):
    seal_rep = inspection.inspect_file(seal_bin_unsigned)
    assert 'unsigned' in seal_ids_value(seal_rep)
    assert seal_severity_of(seal_rep, 'unsigned') == RiskLevel.SEAL_HIGH
    assert all((not seal_s_value.seal_signed for seal_s_value in seal_rep.seal_slices))

@seal_requires_toolchain
def test_seal_linker_signed_binary_is_adhoc(seal_bin_linker_signed):
    seal_rep = inspection.inspect_file(seal_bin_linker_signed)
    assert 'adhoc-signature' in seal_ids_value(seal_rep)
    assert 'linker-signed' in seal_ids_value(seal_rep)
    assert 'unsigned' not in seal_ids_value(seal_rep)
    assert seal_rep.seal_slices[0].seal_signed

@seal_requires_toolchain
def test_seal_hardened_runtime_is_detected_and_not_flagged(seal_bin_hardened):
    seal_rep = inspection.inspect_file(seal_bin_hardened)
    assert 'CS_RUNTIME' in seal_rep.seal_slices[0].seal_cs_flags
    assert 'no-hardened-runtime' not in seal_ids_value(seal_rep)

@seal_requires_toolchain
def test_seal_missing_hardened_runtime_is_flagged_on_a_non_platform_binary(seal_bin_entitled):
    seal_rep = inspection.inspect_file(seal_bin_entitled)
    assert 'no-hardened-runtime' in seal_ids_value(seal_rep)
    assert seal_severity_of(seal_rep, 'no-hardened-runtime') == RiskLevel.SEAL_MEDIUM

@seal_requires_toolchain
def test_seal_risky_entitlements_are_reported(seal_bin_entitled):
    seal_rep = inspection.inspect_file(seal_bin_entitled)
    seal_found = seal_ids_value(seal_rep)
    assert 'entitlement:com.apple.security.get-task-allow' in seal_found
    assert 'entitlement:com.apple.security.cs.disable-library-validation' in seal_found
    assert seal_severity_of(seal_rep, 'entitlement:com.apple.security.get-task-allow') == RiskLevel.SEAL_HIGH

@seal_requires_toolchain
def test_seal_jit_entitlement_is_medium_not_high(seal_bin_entitled):
    seal_rep = inspection.inspect_file(seal_bin_entitled)
    assert seal_severity_of(seal_rep, 'entitlement:com.apple.security.cs.allow-jit') == RiskLevel.SEAL_MEDIUM

@seal_requires_toolchain
def test_seal_an_entitlement_set_to_false_grants_nothing(seal_bin_entitled):
    """The plist sets allow-unsigned-executable-memory to false: not a risk."""
    seal_rep = inspection.inspect_file(seal_bin_entitled)
    seal_key = 'entitlement:com.apple.security.cs.allow-unsigned-executable-memory'
    assert seal_key not in seal_ids_value(seal_rep)
    seal_ents = seal_rep.seal_slices[0].permission_codec
    assert seal_ents['com.apple.security.cs.allow-unsigned-executable-memory'] is False

@seal_requires_toolchain
def test_seal_entitlements_are_read_from_the_der_slot(seal_bin_entitled):
    """The kernel prefers DER, so that is what the report must describe."""
    seal_sl = inspection.inspect_file(seal_bin_entitled).seal_slices[0]
    assert seal_sl.seal_entitlement_source == 'der'
    assert seal_sl.permission_codec['keychain-access-groups'] == ['com.example.group']
    assert seal_sl.permission_codec['com.example.count'] == 3
    assert seal_sl.permission_codec['com.example.name'] == 'hello'

@seal_requires_toolchain
def test_seal_matching_entitlement_slots_raise_no_mismatch(seal_bin_entitled):
    assert 'entitlements-slot-mismatch' not in seal_ids_value(inspection.inspect_file(seal_bin_entitled))

def test_seal_entitlement_risk_table():
    assert seal_entitlement_risk('com.apple.security.get-task-allow', True)[0] == RiskLevel.SEAL_HIGH
    assert seal_entitlement_risk('com.apple.security.cs.allow-jit', True)[0] == RiskLevel.SEAL_MEDIUM
    assert seal_entitlement_risk('com.apple.security.get-task-allow', False) is None
    assert seal_entitlement_risk('com.example.whatever', True) is None

def test_seal_entitlement_risk_falls_back_to_prefix_rules():
    assert seal_entitlement_risk('com.apple.security.cs.some-future-exception', True)[0] == RiskLevel.SEAL_MEDIUM
    assert seal_entitlement_risk('com.apple.private.something', True)[0] == RiskLevel.SEAL_LOW
    assert seal_entitlement_risk('com.apple.security.temporary-exception.x', True)[0] == RiskLevel.SEAL_MEDIUM
    assert seal_entitlement_risk('com.apple.security.network.client', True)[0] == RiskLevel.SEAL_INFO

@seal_requires_toolchain
def test_seal_missing_pie_is_high(seal_bin_no_pie):
    seal_rep = inspection.inspect_file(seal_bin_no_pie)
    assert 'no-pie' in seal_ids_value(seal_rep)
    assert seal_severity_of(seal_rep, 'no-pie') == RiskLevel.SEAL_HIGH

@seal_requires_toolchain
def test_seal_a_normal_binary_is_not_flagged_for_pie(seal_bin_linker_signed):
    assert 'no-pie' not in seal_ids_value(inspection.inspect_file(seal_bin_linker_signed))

@seal_pytest.mark.skipif(not seal_os.path.exists('/usr/bin/otool'), reason='no system binary')
def test_seal_apple_platform_binaries_are_not_flagged_for_hardened_runtime():
    seal_rep = inspection.inspect_file('/usr/bin/otool')
    assert 'no-hardened-runtime' not in seal_ids_value(seal_rep)
    assert 'platform-binary' in seal_ids_value(seal_rep)
    assert seal_severity_of(seal_rep, 'platform-binary') == RiskLevel.SEAL_INFO

@seal_pytest.mark.skipif(not seal_os.path.exists('/usr/bin/otool'), reason='no system binary')
def test_seal_apple_platform_binaries_are_not_flagged_for_a_missing_team_id():
    assert 'no-team-identifier' not in seal_ids_value(inspection.inspect_file('/usr/bin/otool'))

@seal_pytest.mark.skipif(not seal_os.path.exists('/usr/bin/otool'), reason='no system binary')
def test_seal_a_signed_system_binary_has_no_high_findings():
    seal_rep = inspection.inspect_file('/usr/bin/otool')
    assert [seal_f.seal_id for seal_f in seal_rep.observations if seal_f.seal_severity == RiskLevel.SEAL_HIGH] == []

def test_seal_a_non_macho_file_reports_an_error_not_a_crash(tmp_path):
    seal_p = tmp_path / 'script.sh'
    seal_p.write_text('#!/bin/sh\necho hello\n')
    seal_rep = inspection.inspect_file(str(seal_p))
    assert seal_rep.seal_error and (not seal_rep.seal_slices)

def test_seal_a_missing_file_reports_an_error():
    seal_rep = inspection.inspect_file('/nonexistent/sealscope/binary')
    assert seal_rep.seal_error and seal_rep.span == 0

def test_seal_truncated_macho_reports_an_error(tmp_path):
    seal_p = tmp_path / 'truncated'
    seal_p.write_bytes(b'\xcf\xfa\xed\xfe' + b'\x00' * 12)
    assert inspection.inspect_file(str(seal_p)).seal_error

@seal_requires_toolchain
def test_seal_findings_are_sorted_worst_first(seal_bin_entitled):
    seal_rep = inspection.inspect_file(seal_bin_entitled)
    seal_order = [{'high': 0, 'medium': 1, 'low': 2, 'info': 3}[seal_f.seal_severity] for seal_f in seal_rep.observations]
    assert seal_order == sorted(seal_order)
    assert seal_rep.seal_worst == RiskLevel.SEAL_HIGH

@seal_requires_toolchain
def test_seal_report_serialises_to_json_safe_types(seal_bin_entitled):
    import json as seal_json
    seal_d = inspection.inspect_file(seal_bin_entitled).export_record()
    seal_json.dumps(seal_d)
    assert seal_d['counts']['high'] >= 1
    assert seal_d['slices'][0]['entitlement_source'] == 'der'
