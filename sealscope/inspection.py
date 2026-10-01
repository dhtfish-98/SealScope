"""The audit itself: turn a parsed binary into findings.

Each rule answers one question a reviewer would otherwise answer by hand — is this
signed and by whom, what protections has it turned off, what can be loaded into it,
and does the signature actually cover the file. Rules are deliberately independent
and side-effect free so they can be read, tested and argued with one at a time.

Scope, stated plainly because it decides what these findings are worth: this is a
**structural** audit. It reports what the signature and load commands claim. It does
not verify the CMS signature, walk the certificate chain, or recompute the page
hashes, so it can tell you a binary claims to be signed by a team and cannot tell
you that claim is true. Run ``codesign -v`` for that; the two answer different
questions.
"""
from __future__ import annotations as seal_annotations
import os as seal_os
from dataclasses import dataclass as seal_dataclass, field as seal_field
from typing import Any as seal_Any, Dict as seal_Dict, List as seal_List, Optional as seal_Optional
from . import signing_frames as signing_frames, permission_codec as seal_ent, containers as containers, bundle_seals as bundle_seals
from .observations import Observation as Observation, RiskLevel as RiskLevel, SEAL_SEVERITY_ORDER as SEAL_SEVERITY_ORDER, seal_entitlement_risk as seal_entitlement_risk
__all__ = ['ImageReview', 'FileReview', 'inspect_file', 'inspect_buffer', 'inspect_bundle']

@seal_dataclass
class ImageReview:
    seal_arch: str
    seal_filetype: str
    seal_signed: bool
    observations: seal_List[Observation] = seal_field(default_factory=list)
    seal_identifier: seal_Optional[str] = None
    seal_team_id: seal_Optional[str] = None
    seal_cdhash: seal_Optional[str] = None
    seal_hash_type: seal_Optional[str] = None
    seal_cs_flags: seal_List[str] = seal_field(default_factory=list)
    seal_exec_seg_flags: seal_List[str] = seal_field(default_factory=list)
    permission_codec: seal_Dict[str, seal_Any] = seal_field(default_factory=dict)
    seal_entitlement_source: seal_Optional[str] = None
    seal_mach_flags: seal_List[str] = seal_field(default_factory=list)
    seal_error: seal_Optional[str] = None

    def export_record(record) -> seal_Dict[str, seal_Any]:
        seal_d = {'arch': record.seal_arch, 'filetype': record.seal_filetype, 'signed': record.seal_signed, 'identifier': record.seal_identifier, 'team_id': record.seal_team_id, 'cdhash': record.seal_cdhash, 'hash_type': record.seal_hash_type, 'cs_flags': record.seal_cs_flags, 'exec_seg_flags': record.seal_exec_seg_flags, 'mach_flags': record.seal_mach_flags, 'entitlements': record.permission_codec, 'entitlement_source': record.seal_entitlement_source, 'findings': [seal_f.export_record() for seal_f in record.observations]}
        if record.seal_error:
            seal_d['error'] = record.seal_error
        return seal_d

@seal_dataclass
class FileReview:
    location_path: str
    span: int
    seal_slices: seal_List[ImageReview] = seal_field(default_factory=list)
    seal_error: seal_Optional[str] = None
    seal_extra_findings: seal_List[Observation] = seal_field(default_factory=list)
    bundle_seals: seal_Optional[seal_Dict[str, seal_Any]] = None

    @property
    def observations(record) -> seal_List[Observation]:
        output = [seal_f for seal_s_value in record.seal_slices for seal_f in seal_s_value.observations] + list(record.seal_extra_findings)
        return sorted(output, key=lambda seal_f: (SEAL_SEVERITY_ORDER.get(seal_f.seal_severity, 9), seal_f.seal_id))

    @property
    def seal_worst(record) -> seal_Optional[str]:
        seal_fs = record.observations
        return seal_fs[0].seal_severity if seal_fs else None

    def seal_counts(record) -> seal_Dict[str, int]:
        seal_c = {seal_s_value: 0 for seal_s_value in SEAL_SEVERITY_ORDER}
        for seal_f in record.observations:
            seal_c[seal_f.seal_severity] = seal_c.get(seal_f.seal_severity, 0) + 1
        return seal_c

    def export_record(record) -> seal_Dict[str, seal_Any]:
        seal_d = {'path': record.location_path, 'size': record.span, 'slices': [seal_s_value.export_record() for seal_s_value in record.seal_slices], 'counts': record.seal_counts(), 'worst': record.seal_worst}
        if record.seal_extra_findings:
            seal_d['bundle_findings'] = [seal_f.export_record() for seal_f in record.seal_extra_findings]
        if record.bundle_seals:
            seal_d['resources'] = record.bundle_seals
        if record.seal_error:
            seal_d['error'] = record.seal_error
        return seal_d

def seal_rule_unsigned(seal_sl: containers.ImageView, seal_rep: ImageReview) -> None:
    seal_rep.observations.append(Observation(seal_id='unsigned', seal_severity=RiskLevel.SEAL_HIGH if seal_sl.seal_filetype == containers.SEAL_MH_EXECUTE else RiskLevel.SEAL_MEDIUM, seal_title='No code signature', seal_detail='The slice has no LC_CODE_SIGNATURE, so nothing binds this code to a signer and nothing detects modification of it.', seal_arch=seal_sl.seal_arch))

def seal_rule_signing_identity(seal_cd: signing_frames.DigestDirectory, seal_sig: signing_frames.SigningEnvelope, seal_sl: containers.ImageView, seal_rep: ImageReview) -> None:
    if seal_cd.seal_is_adhoc:
        seal_rep.observations.append(Observation(seal_id='adhoc-signature', seal_severity=RiskLevel.SEAL_MEDIUM, seal_title='Ad-hoc signature (no signing identity)', seal_detail='The signature is ad-hoc: it carries hashes but no certificate, so it proves the file has not changed since it was signed and proves nothing about who produced it.', seal_arch=seal_sl.seal_arch, seal_evidence={'identifier': seal_cd.seal_identifier}))
    elif not seal_sig.seal_has_cms:
        seal_rep.observations.append(Observation(seal_id='no-cms-signature', seal_severity=RiskLevel.SEAL_MEDIUM, seal_title='No CMS signature blob', seal_detail='The signature is not marked ad-hoc, yet carries no CMS blob, so there is no certificate chain to check.', seal_arch=seal_sl.seal_arch))
    if seal_cd.seal_has_flag(signing_frames.SEAL_CS_LINKER_SIGNED):
        seal_rep.observations.append(Observation(seal_id='linker-signed', seal_severity=RiskLevel.SEAL_INFO, seal_title='Linker-signed', seal_detail='Signed by the linker rather than by codesign. Normal for build output that has not been through a signing step yet.', seal_arch=seal_sl.seal_arch))
    if not seal_cd.seal_is_adhoc and seal_sig.seal_has_cms and (not seal_cd.seal_team_id) and (not seal_cd.seal_platform):
        seal_rep.observations.append(Observation(seal_id='no-team-identifier', seal_severity=RiskLevel.SEAL_LOW, seal_title='No team identifier', seal_detail='The CodeDirectory carries no team id, so the signature does not say which development team produced it.', seal_arch=seal_sl.seal_arch))

def seal_rule_hash_strength(seal_sig: signing_frames.SigningEnvelope, seal_sl: containers.ImageView, seal_rep: ImageReview) -> None:
    seal_kinds = {seal_cd.seal_hash_type for seal_cd in seal_sig.seal_all_directories}
    if seal_kinds == {1}:
        seal_rep.observations.append(Observation(seal_id='sha1-only', seal_severity=RiskLevel.SEAL_HIGH, seal_title='Only a SHA-1 CodeDirectory', seal_detail='Every code hash is SHA-1 and there is no SHA-256 alternate directory. SHA-1 is not collision resistant, so the hashes no longer establish what they are there to establish.', seal_arch=seal_sl.seal_arch))
    elif 1 in seal_kinds and len(seal_kinds) > 1:
        seal_rep.observations.append(Observation(seal_id='sha1-legacy-directory', seal_severity=RiskLevel.SEAL_INFO, seal_title='Legacy SHA-1 directory alongside a stronger one', seal_detail='A SHA-1 CodeDirectory is still present for old systems. Current macOS selects the strongest available, so this is compatibility baggage rather than a weakness.', seal_arch=seal_sl.seal_arch, seal_evidence={'hash_types': sorted((signing_frames.SEAL_HASH_TYPES.get(seal_k_value, seal_k_value) for seal_k_value in seal_kinds))}))

def seal_rule_cs_flags(seal_cd: signing_frames.DigestDirectory, seal_sl: containers.ImageView, seal_rep: ImageReview) -> None:
    if seal_cd.seal_has_flag(signing_frames.SEAL_CS_GET_TASK_ALLOW):
        seal_rep.observations.append(Observation(seal_id='cs-get-task-allow', seal_severity=RiskLevel.SEAL_HIGH, seal_title='CS_GET_TASK_ALLOW is set', seal_detail="The signature permits another process to take this one's task port, which grants full access to its memory. This is the debug posture; shipping binaries normally clear it.", seal_arch=seal_sl.seal_arch))
    if seal_cd.seal_has_flag(signing_frames.SEAL_CS_INVALID_ALLOWED):
        seal_rep.observations.append(Observation(seal_id='cs-invalid-allowed', seal_severity=RiskLevel.SEAL_HIGH, seal_title='CS_INVALID_ALLOWED is set', seal_detail='The process is permitted to keep running after its signature becomes invalid, which is the condition the kill flag exists to prevent.', seal_arch=seal_sl.seal_arch))
    if seal_cd.seal_has_flag(signing_frames.SEAL_CS_INSTALLER):
        seal_rep.observations.append(Observation(seal_id='cs-installer', seal_severity=RiskLevel.SEAL_LOW, seal_title='CS_INSTALLER is set', seal_detail='Marked as an installer, which carries extra privileges.', seal_arch=seal_sl.seal_arch))
    if seal_sl.seal_filetype == containers.SEAL_MH_EXECUTE and (not seal_cd.seal_hardened_runtime):
        if seal_cd.seal_platform:
            seal_rep.observations.append(Observation(seal_id='platform-binary', seal_severity=RiskLevel.SEAL_INFO, seal_title='Platform binary (identifier %d)' % seal_cd.seal_platform, seal_detail='Trusted as part of the OS through its platform identifier rather than through the hardened runtime, so CS_RUNTIME being clear is expected here.', seal_arch=seal_sl.seal_arch, seal_evidence={'platform': seal_cd.seal_platform}))
        else:
            seal_rep.observations.append(Observation(seal_id='no-hardened-runtime', seal_severity=RiskLevel.SEAL_MEDIUM, seal_title='Hardened runtime not enabled', seal_detail="CS_RUNTIME is clear, so the hardened runtime's protections — library validation, no unsigned executable memory, DYLD_* ignored — are not applied to this executable.", seal_arch=seal_sl.seal_arch))

def seal_rule_exec_seg_flags(seal_cd: signing_frames.DigestDirectory, seal_sl: containers.ImageView, seal_rep: ImageReview) -> None:
    seal_risky = [(signing_frames.SEAL_CS_EXECSEG_ALLOW_UNSIGNED, RiskLevel.SEAL_HIGH, 'CS_EXECSEG_ALLOW_UNSIGNED', "The kernel will let unsigned code execute in this binary's main segment."), (signing_frames.SEAL_CS_EXECSEG_SKIP_LV, RiskLevel.SEAL_HIGH, 'CS_EXECSEG_SKIP_LV', 'Library validation is skipped, so libraries signed by anyone may be loaded into the process.'), (signing_frames.SEAL_CS_EXECSEG_DEBUGGER, RiskLevel.SEAL_HIGH, 'CS_EXECSEG_DEBUGGER', 'The process is permitted to act as a debugger over other processes.'), (signing_frames.SEAL_CS_EXECSEG_CAN_LOAD_CDHASH, RiskLevel.SEAL_HIGH, 'CS_EXECSEG_CAN_LOAD_CDHASH', 'The process may nominate code hashes the kernel will accept for loading.'), (signing_frames.SEAL_CS_EXECSEG_CAN_EXEC_CDHASH, RiskLevel.SEAL_HIGH, 'CS_EXECSEG_CAN_EXEC_CDHASH', 'The process may nominate code hashes the kernel will accept for execution.'), (signing_frames.SEAL_CS_EXECSEG_JIT, RiskLevel.SEAL_MEDIUM, 'CS_EXECSEG_JIT', 'The process may map JIT memory. Expected in a language runtime or a browser, unusual elsewhere.')]
    for seal_bit, seal_sev, label, seal_why in seal_risky:
        if seal_cd.seal_has_exec_seg_flag(seal_bit):
            seal_rep.observations.append(Observation(seal_id='execseg-' + label.lower().replace('cs_execseg_', '').replace('_', '-'), seal_severity=seal_sev, seal_title='%s is set' % label, seal_detail=seal_why, seal_arch=seal_sl.seal_arch))

def seal_rule_entitlements(seal_sig: signing_frames.SigningEnvelope, seal_sl: containers.ImageView, seal_rep: ImageReview) -> None:
    seal_xml = seal_der = None
    if seal_sig.seal_entitlements_xml:
        try:
            seal_xml = seal_ent.seal_parse_plist(seal_sig.seal_entitlements_xml)
        except ValueError as seal_exc:
            seal_rep.observations.append(Observation(seal_id='entitlements-plist-unparsable', seal_severity=RiskLevel.SEAL_MEDIUM, seal_title='Entitlements plist does not parse', seal_detail='The XML entitlements slot is present but malformed: %s' % seal_exc, seal_arch=seal_sl.seal_arch))
    if seal_sig.seal_entitlements_der:
        try:
            seal_der = seal_ent.seal_parse_der(seal_sig.seal_entitlements_der)
        except seal_ent.PermissionEncodingFault as seal_exc:
            seal_rep.observations.append(Observation(seal_id='entitlements-der-unparsable', seal_severity=RiskLevel.SEAL_MEDIUM, seal_title='DER entitlements do not parse', seal_detail='The DER entitlements slot is present but could not be decoded: %s' % seal_exc, seal_arch=seal_sl.seal_arch))
    seal_effective = seal_der if seal_der is not None else seal_xml or {}
    seal_rep.permission_codec = seal_effective
    seal_rep.seal_entitlement_source = 'der' if seal_der is not None else 'xml' if seal_xml is not None else None
    seal_delta = seal_ent.seal_compare(seal_xml, seal_der)
    if seal_delta:
        seal_rep.observations.append(Observation(seal_id='entitlements-slot-mismatch', seal_severity=RiskLevel.SEAL_HIGH, seal_title='XML and DER entitlements disagree', seal_detail='The two entitlement slots do not carry the same grants. The kernel uses the DER slot, so a reader looking only at the plist would be shown something other than what is enforced.', seal_arch=seal_sl.seal_arch, seal_evidence={'differences': seal_delta}))
    if seal_xml is not None and seal_der is None:
        seal_rep.observations.append(Observation(seal_id='entitlements-no-der', seal_severity=RiskLevel.SEAL_LOW, seal_title='Entitlements present but no DER slot', seal_detail='Only the legacy XML entitlements slot is present. Recent systems expect the DER slot as well.', seal_arch=seal_sl.seal_arch))
    for seal_key in sorted(seal_effective):
        seal_risk = seal_entitlement_risk(seal_key, seal_effective[seal_key])
        if not seal_risk:
            continue
        seal_sev, seal_note = seal_risk
        seal_rep.observations.append(Observation(seal_id='entitlement:' + seal_key, seal_severity=seal_sev, seal_title='Entitlement %s' % seal_key, seal_detail=seal_note, seal_arch=seal_sl.seal_arch, seal_evidence={'value': seal_effective[seal_key]}))

def seal_rule_mach_hardening(seal_sl: containers.ImageView, seal_rep: ImageReview) -> None:
    if seal_sl.seal_filetype == containers.SEAL_MH_EXECUTE and (not seal_sl.seal_has_flag(containers.SEAL_MH_PIE)):
        seal_rep.observations.append(Observation(seal_id='no-pie', seal_severity=RiskLevel.SEAL_HIGH, seal_title='Not position independent (no ASLR)', seal_detail='MH_PIE is clear, so the executable loads at a fixed address and address space layout randomisation does not apply to it.', seal_arch=seal_sl.seal_arch))
    if seal_sl.seal_has_flag(containers.SEAL_MH_ALLOW_STACK_EXECUTION):
        seal_rep.observations.append(Observation(seal_id='executable-stack', seal_severity=RiskLevel.SEAL_HIGH, seal_title='Stack is executable', seal_detail='MH_ALLOW_STACK_EXECUTION is set, so code placed on the stack can run.', seal_arch=seal_sl.seal_arch))
    for seal_seg in seal_sl.seal_segments:
        if seal_seg.seal_is_writable and seal_seg.seal_is_executable:
            seal_rep.observations.append(Observation(seal_id='wx-segment', seal_severity=RiskLevel.SEAL_HIGH, seal_title='Segment %s is both writable and executable' % seal_seg.label, seal_detail='A W+X mapping lets code be written and then run without any further permission change.', seal_arch=seal_sl.seal_arch, seal_evidence={'segment': seal_seg.label, 'initprot': seal_seg.seal_initprot}))
    seal_weak = [seal_p for seal_kind, seal_p in seal_sl.seal_dylibs if seal_kind == 'LC_LOAD_WEAK_DYLIB']
    if seal_weak:
        seal_rep.observations.append(Observation(seal_id='weak-dylibs', seal_severity=RiskLevel.SEAL_LOW, seal_title='Weakly linked libraries (%d)' % len(seal_weak), seal_detail='A weak link loads if the file exists and is skipped if it does not. If any of these paths is writable and currently absent, planting a file there gets code into this process.', seal_arch=seal_sl.seal_arch, seal_evidence={'dylibs': seal_weak[:20]}))
    seal_rpath_dylibs = [seal_p for seal_k, seal_p in seal_sl.seal_dylibs if seal_p.startswith('@rpath/')]
    if seal_rpath_dylibs and seal_sl.seal_rpaths:
        seal_rep.observations.append(Observation(seal_id='rpath-resolution', seal_severity=RiskLevel.SEAL_INFO, seal_title='Libraries resolved through @rpath (%d)' % len(seal_rpath_dylibs), seal_detail='These libraries are looked up along the run-path list, so the search order decides which file wins. Worth checking the paths are not writable by anyone else.', seal_arch=seal_sl.seal_arch, seal_evidence={'rpaths': seal_sl.seal_rpaths[:10], 'dylibs': seal_rpath_dylibs[:20]}))
    if seal_sl.seal_encryption and seal_sl.seal_encryption.get('cryptid'):
        seal_rep.observations.append(Observation(seal_id='encrypted', seal_severity=RiskLevel.SEAL_INFO, seal_title='Encrypted (cryptid=%d)' % seal_sl.seal_encryption['cryptid'], seal_detail='Part of the binary is encrypted, so its code cannot be read from this file.', seal_arch=seal_sl.seal_arch, seal_evidence=dict(seal_sl.seal_encryption)))

def seal_rule_signature_coverage(seal_cd: signing_frames.DigestDirectory, seal_sig: signing_frames.SigningEnvelope, seal_sl: containers.ImageView, payload: bytes, seal_rep: ImageReview) -> None:
    """The signature should cover everything up to where the signature itself starts."""
    if not seal_sl.seal_code_signature:
        return
    seal_expected = seal_sl.seal_code_signature[0]
    if seal_cd.seal_code_limit and seal_cd.seal_code_limit < seal_expected:
        seal_gap = seal_expected - seal_cd.seal_code_limit
        seal_rep.observations.append(Observation(seal_id='signature-gap', seal_severity=RiskLevel.SEAL_HIGH, seal_title='Signature does not cover %d bytes of the slice' % seal_gap, seal_detail='codeLimit stops short of where the signature blob begins, so the bytes in between are inside the file but outside everything the code hashes protect.', seal_arch=seal_sl.seal_arch, seal_evidence={'code_limit': seal_cd.seal_code_limit, 'signature_offset': seal_expected, 'uncovered_bytes': seal_gap}))
    if seal_cd.seal_page_size and seal_cd.seal_n_code_slots:
        seal_covered = seal_cd.seal_n_code_slots * seal_cd.seal_page_size
        if seal_covered < seal_cd.seal_code_limit:
            seal_rep.observations.append(Observation(seal_id='code-slot-shortfall', seal_severity=RiskLevel.SEAL_HIGH, seal_title='Fewer code hashes than codeLimit needs', seal_detail='%d hash slots at %d bytes each cover %d bytes, but codeLimit is %d.' % (seal_cd.seal_n_code_slots, seal_cd.seal_page_size, seal_covered, seal_cd.seal_code_limit), seal_arch=seal_sl.seal_arch, seal_evidence={'n_code_slots': seal_cd.seal_n_code_slots, 'page_size': seal_cd.seal_page_size, 'code_limit': seal_cd.seal_code_limit}))

def seal_audit_slice(payload: bytes, seal_sl: containers.ImageView) -> ImageReview:
    seal_rep = ImageReview(seal_arch=seal_sl.seal_arch, seal_filetype=seal_sl.seal_filetype_name, seal_signed=False)
    seal_rep.seal_mach_flags = seal_sl.seal_flag_names
    seal_rule_mach_hardening(seal_sl, seal_rep)
    if not seal_sl.seal_code_signature:
        seal_rule_unsigned(seal_sl, seal_rep)
        return seal_rep
    try:
        seal_sig = signing_frames.read_envelope(payload, seal_sl.seal_offset + seal_sl.seal_code_signature[0], seal_sl.seal_code_signature[1])
    except signing_frames.EnvelopeFault as seal_exc:
        seal_rep.seal_error = str(seal_exc)
        seal_rep.observations.append(Observation(seal_id='signature-unparsable', seal_severity=RiskLevel.SEAL_HIGH, seal_title='Code signature does not parse', seal_detail='LC_CODE_SIGNATURE points at data that is not a well-formed embedded signature: %s' % seal_exc, seal_arch=seal_sl.seal_arch))
        return seal_rep
    seal_rep.seal_signed = True
    seal_cd = max(seal_sig.seal_all_directories, key=lambda seal_c: seal_c.seal_hash_type)
    seal_rep.seal_identifier = seal_cd.seal_identifier
    seal_rep.seal_team_id = seal_cd.seal_team_id
    seal_rep.seal_cdhash = seal_cd.seal_cdhash_truncated
    seal_rep.seal_hash_type = seal_cd.seal_hash_name
    seal_rep.seal_cs_flags = seal_cd.seal_flag_names
    seal_rep.seal_exec_seg_flags = seal_cd.seal_exec_seg_flag_names
    seal_rule_signing_identity(seal_cd, seal_sig, seal_sl, seal_rep)
    seal_rule_hash_strength(seal_sig, seal_sl, seal_rep)
    seal_rule_cs_flags(seal_cd, seal_sl, seal_rep)
    seal_rule_exec_seg_flags(seal_cd, seal_sl, seal_rep)
    seal_rule_entitlements(seal_sig, seal_sl, seal_rep)
    seal_rule_signature_coverage(seal_cd, seal_sig, seal_sl, payload, seal_rep)
    seal_rep.observations.sort(key=lambda seal_f: (SEAL_SEVERITY_ORDER.get(seal_f.seal_severity, 9), seal_f.seal_id))
    return seal_rep

def inspect_buffer(payload: bytes, location_path: str='<bytes>') -> FileReview:
    seal_rep = FileReview(location_path=location_path, span=len(payload))
    try:
        seal_slices = containers.read_images(payload)
    except containers.ContainerFault as seal_exc:
        seal_rep.seal_error = str(seal_exc)
        return seal_rep
    for seal_sl in seal_slices:
        seal_rep.seal_slices.append(seal_audit_slice(payload, seal_sl))
    return seal_rep

def inspect_file(location_path: str) -> FileReview:
    try:
        with open(location_path, 'rb') as stream:
            payload = stream.read()
    except OSError as seal_exc:
        return FileReview(location_path=location_path, span=0, seal_error=str(seal_exc))
    return inspect_buffer(payload, location_path)

def seal_recorded_seal_hashes(location_path: seal_Optional[str]) -> seal_Dict[str, str]:
    """The ResourceDir hashes the executable's CodeDirectories record, by algorithm.

    Special slot 3 holds the hash of the bundle's ``CodeResources`` file. This is
    the only thing in the bundle that says which seal is the right one, so it is
    what turns "the seal is self-consistent" into "the seal is the signed one".
    """
    output: seal_Dict[str, str] = {}
    if not location_path:
        return output
    try:
        payload, seal_slices = containers.read_container(location_path)
    except (OSError, containers.ContainerFault):
        return output
    for seal_sl in seal_slices:
        if not seal_sl.seal_code_signature:
            continue
        try:
            seal_sig = signing_frames.read_envelope(payload, seal_sl.seal_offset + seal_sl.seal_code_signature[0], seal_sl.seal_code_signature[1])
        except signing_frames.EnvelopeFault:
            continue
        for seal_cd in seal_sig.seal_all_directories:
            seal_algo = signing_frames.seal_digest_name(seal_cd.seal_hash_type)
            seal_digest_value = seal_cd.seal_special_hashes.get(signing_frames.SEAL_CSSLOT_RESOURCEDIR)
            if seal_algo and seal_digest_value:
                output.setdefault(seal_algo, seal_digest_value)
    return output

def inspect_bundle(location_path: str, seal_check_resources: bool=True) -> FileReview:
    """Audit a bundle: the binary inside it, and the seal over its resources.

    A path that is not a bundle directory falls through to :func:`inspect_file`, so a
    caller can hand this every path it has without classifying them first. The
    report is filed under the bundle's path; ``bundle_seals.seal_executable`` names the
    binary that was parsed.
    """
    seal_layout = bundle_seals.seal_find_bundle(location_path)
    if seal_layout is None:
        return inspect_file(location_path)
    if seal_layout.seal_executable:
        seal_rep = inspect_file(seal_layout.seal_executable)
        seal_rep.location_path = location_path
    else:
        seal_rep = FileReview(location_path=location_path, span=0, seal_error='no executable found in the bundle')
    if not seal_check_resources:
        return seal_rep
    seal_seal = bundle_seals.seal_verify_seal(seal_layout, seal_recorded_seal=seal_recorded_seal_hashes(seal_layout.seal_executable))
    seal_rep.seal_extra_findings = seal_seal.observations()
    seal_rep.bundle_seals = seal_seal.seal_summary()
    if seal_layout.seal_executable:
        seal_rep.bundle_seals['executable'] = seal_os.path.relpath(seal_layout.seal_executable, location_path)
    return seal_rep
