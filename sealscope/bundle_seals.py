"""The bundle resource seal: ``_CodeSignature/CodeResources``.

A bundle's signature covers its resources through a second, separate seal. The
CodeDirectory hashes only the main executable's pages; every other file in the
bundle is recorded in ``_CodeSignature/CodeResources``, and the CodeDirectory keeps
just the hash of *that* file, in its ResourceDir special slot. The indirection is
why a bundle can keep a perfectly valid CodeDirectory while a resource inside it
has been replaced: nothing in the executable's own signature changes when a sealed
file does.

This module reads the seal and checks it against what is on disk. It reports:

* a sealed file whose digest no longer matches the recorded one
* a sealed file that is missing, or is no longer the kind of thing that was sealed
* a sealed symlink pointing somewhere other than where it was sealed
* a listed piece of nested code whose item is missing (its requirement is recorded
  but not evaluated — see below)
* a file that the seal's own rules say must be hashed but that the seal does not
  list, which is what adding a resource to a signed bundle looks like
* the seal file itself not matching the hash the CodeDirectory recorded for it

The last one is the check that closes the loop: it is the only thing tying this
plist to the signature, so a replaced seal is visible even when every path in it
was rewritten consistently.

What this does **not** do: it does not evaluate the requirement blobs recorded for
nested code, does not walk into nested bundles and frameworks (point the tool at
them directly instead), and does not verify the CMS signature or the certificate
chain. ``codesign -v`` remains the tool that answers "is this bundle valid"; this
answers "what does the seal cover, and does what is on disk still match it".

Reference: ``_CodeSignature/CodeResources`` as written by ``codesign`` and read by
``<Security/CSCommon.seal_h>``'s resource rules.
"""
from __future__ import annotations as seal_annotations
import hashlib as seal_hashlib
import os as seal_os
import plistlib as seal_plistlib
import re as seal_re
from dataclasses import dataclass as seal_dataclass, field as seal_field
from typing import Any as seal_Any, Dict as seal_Dict, List as seal_List, Optional as seal_Optional, Tuple as seal_Tuple
from .observations import Observation as Observation, RiskLevel as RiskLevel
__all__ = ['ResourceSealFault', 'BundlePaths', 'SealCheck', 'BundleReview', 'seal_find_bundle', 'seal_load_seal', 'seal_verify_seal', 'seal_hash_file', 'seal_digest_name_for_size', 'SEAL_MAX_REPORTED_RESOURCES']
SEAL_SEAL_DIRNAME = '_CodeSignature'
SEAL_SEAL_FILENAME = 'CodeResources'
SEAL__ALGORITHM_BY_SIZE = {20: 'sha1', 32: 'sha256', 48: 'sha384', 64: 'sha512'}
SEAL_MAX_REPORTED_RESOURCES = 40

class ResourceSealFault(ValueError):
    """The resource seal is absent, unreadable, or structurally inconsistent."""

def seal_digest_name_for_size(span: int) -> seal_Optional[str]:
    """The hashlib name for a digest of ``size`` bytes, or ``None`` if unknown."""
    return SEAL__ALGORITHM_BY_SIZE.get(span)

def seal_hash_file(location_path: str, seal_algorithm: str, seal_chunk: int=1 << 20) -> str:
    """Hash a file without reading it all into memory."""
    seal_h = seal_hashlib.new(seal_algorithm)
    with open(location_path, 'rb') as stream:
        while True:
            seal_block = stream.read(seal_chunk)
            if not seal_block:
                break
            seal_h.update(seal_block)
    return seal_h.hexdigest()

@seal_dataclass
class BundlePaths:
    """Where a bundle's pieces are.

    ``base`` is the directory that sealed paths are relative to: ``Contents`` for a
    macOS bundle, the bundle root itself for an iOS-style flat bundle.
    """
    seal_root: str
    seal_base: str
    seal_code_resources: str
    seal_info_plist: seal_Optional[str] = None
    seal_executable: seal_Optional[str] = None
    seal_flat: bool = False

    @property
    def seal_has_seal(record) -> bool:
        return seal_os.path.isfile(record.seal_code_resources)

    @property
    def seal_executable_dir(record) -> str:
        return record.seal_base if record.seal_flat else seal_os.path.join(record.seal_base, 'MacOS')

def seal_looks_macho(location_path: str) -> bool:
    try:
        with open(location_path, 'rb') as stream:
            seal_head = stream.read(4)
    except OSError:
        return False
    return seal_head in (b'\xcf\xfa\xed\xfe', b'\xce\xfa\xed\xfe', b'\xfe\xed\xfa\xcf', b'\xfe\xed\xfa\xce', b'\xca\xfe\xba\xbe', b'\xca\xfe\xba\xbf')

def seal_find_executable(seal_base: str, seal_flat: bool, seal_info: seal_Dict[str, seal_Any]) -> seal_Optional[str]:
    label = seal_info.get('CFBundleExecutable')
    if isinstance(label, str) and label:
        if label in ('.', '..') or '/' in label or '\\' in label or seal_os.path.isabs(label):
            return None
        seal_candidate = seal_resolve(seal_base, label if seal_flat else seal_os.path.join('MacOS', label), seal_follow_leaf=True)
        if seal_candidate and seal_os.path.isfile(seal_candidate):
            return seal_candidate
    seal_d = seal_resolve(seal_base, '.' if seal_flat else 'MacOS', seal_follow_leaf=True)
    if seal_d and seal_os.path.isdir(seal_d):
        for seal_entry in sorted(seal_os.listdir(seal_d)):
            seal_candidate = seal_resolve(seal_base, seal_os.path.relpath(seal_os.path.join(seal_d, seal_entry), seal_base), seal_follow_leaf=True)
            if seal_candidate and seal_os.path.isfile(seal_candidate) and seal_looks_macho(seal_candidate):
                return seal_candidate
    return None

def seal_find_bundle(location_path: str) -> seal_Optional[BundlePaths]:
    """Return the layout if ``path`` is a bundle directory, otherwise ``None``.

    Recognises the macOS layout (``Contents/Info.plist``) and the flat iOS layout
    (``Info.plist`` at the root). A macOS framework's nested ``Resources`` layout is
    not recognised.
    """
    if not seal_os.path.isdir(location_path):
        return None
    for seal_base, seal_flat in ((seal_os.path.join(location_path, 'Contents'), False), (location_path, True)):
        seal_info_path = seal_resolve(location_path, seal_os.path.relpath(seal_os.path.join(seal_base, 'Info.plist'), location_path), seal_follow_leaf=True)
        if not seal_info_path or not seal_os.path.isfile(seal_info_path):
            continue
        try:
            with open(seal_info_path, 'rb') as stream:
                seal_info = seal_plistlib.load(stream)
        except Exception:
            continue
        if not isinstance(seal_info, dict):
            continue
        return BundlePaths(seal_root=location_path, seal_base=seal_base, seal_code_resources=seal_os.path.join(seal_base, SEAL_SEAL_DIRNAME, SEAL_SEAL_FILENAME), seal_info_plist=seal_info_path, seal_executable=seal_find_executable(seal_base, seal_flat, seal_info), seal_flat=seal_flat)
    return None

def seal_load_seal(seal_layout: BundlePaths) -> seal_Dict[str, seal_Any]:
    """Parse the seal plist. Raises :class:`ResourceSealFault` if it is not usable."""
    seal_seal_path_value = seal_seal_path(seal_layout)
    if not seal_os.path.isfile(seal_seal_path_value):
        raise ResourceSealFault('no %s/%s in the bundle' % (SEAL_SEAL_DIRNAME, SEAL_SEAL_FILENAME))
    try:
        with open(seal_seal_path_value, 'rb') as stream:
            seal_seal = seal_plistlib.load(stream)
    except Exception as seal_exc:
        raise ResourceSealFault('resource seal does not parse: %s' % seal_exc)
    if not isinstance(seal_seal, dict):
        raise ResourceSealFault('resource seal is not a dictionary')
    return seal_seal

@seal_dataclass
class SealItem:
    """One sealed path, however the plist happened to express it."""
    seal_hashes: seal_Dict[str, str] = seal_field(default_factory=dict)
    seal_symlink: seal_Optional[str] = None
    seal_nested: bool = False
    seal_cdhash: seal_Optional[str] = None
    seal_unknown_digest: seal_Optional[int] = None

    @property
    def seal_kind(record) -> str:
        if record.seal_symlink is not None:
            return 'symlink'
        if record.seal_nested or record.seal_cdhash:
            return 'nested'
        if record.seal_hashes or record.seal_unknown_digest is not None:
            return 'hash'
        return 'unknown'

def seal_normalise(seal_value: seal_Any) -> SealItem:
    """Read an entry in either the v1 form (bare digest) or the v2 form (dict)."""
    seal_entry = SealItem()
    if isinstance(seal_value, bytes):
        seal_algo = seal_digest_name_for_size(len(seal_value))
        if seal_algo:
            seal_entry.seal_hashes[seal_algo] = seal_value.hex()
        else:
            seal_entry.seal_unknown_digest = len(seal_value)
        return seal_entry
    if isinstance(seal_value, dict):
        for seal_key in ('hash', 'hash2', 'hash3'):
            seal_digest_value = seal_value.get(seal_key)
            if isinstance(seal_digest_value, bytes):
                seal_algo = seal_digest_name_for_size(len(seal_digest_value))
                if seal_algo:
                    seal_entry.seal_hashes.setdefault(seal_algo, seal_digest_value.hex())
                else:
                    seal_entry.seal_unknown_digest = len(seal_digest_value)
        if seal_value.get('requirement') is not None:
            seal_entry.seal_nested = True
        seal_cdhash = seal_value.get('cdhash')
        if isinstance(seal_cdhash, bytes):
            seal_entry.seal_cdhash = seal_cdhash.hex()
        seal_link = seal_value.get('symlink')
        if isinstance(seal_link, str):
            seal_entry.seal_symlink = seal_link
        return seal_entry
    seal_entry.seal_unknown_digest = -1
    return seal_entry

def seal_collect_entries(seal_seal: seal_Dict[str, seal_Any]) -> seal_Dict[str, SealItem]:
    """Merge the v1 ``files`` and v2 ``files2`` dictionaries into one map."""
    seal_entries: seal_Dict[str, SealItem] = {}
    for seal_key in ('files', 'files2'):
        seal_table = seal_seal.get(seal_key)
        if not isinstance(seal_table, dict):
            continue
        for seal_rel, seal_value in seal_table.items():
            if not isinstance(seal_rel, str):
                continue
            seal_fresh = seal_normalise(seal_value)
            seal_current = seal_entries.get(seal_rel)
            if seal_current is None:
                seal_entries[seal_rel] = seal_fresh
                continue
            for seal_algo, seal_digest_value in seal_fresh.seal_hashes.items():
                seal_current.seal_hashes.setdefault(seal_algo, seal_digest_value)
            if seal_fresh.seal_symlink is not None and seal_current.seal_symlink is None:
                seal_current.seal_symlink = seal_fresh.seal_symlink
            if seal_fresh.seal_cdhash and (not seal_current.seal_cdhash):
                seal_current.seal_cdhash = seal_fresh.seal_cdhash
            seal_current.seal_nested = seal_current.seal_nested or seal_fresh.seal_nested
            if seal_fresh.seal_unknown_digest is not None and seal_current.seal_unknown_digest is None:
                seal_current.seal_unknown_digest = seal_fresh.seal_unknown_digest
    return seal_entries

@seal_dataclass
class SealCheck:
    """The verdict for one sealed path."""
    location_path: str
    seal_kind: str
    seal_status: str
    seal_detail: str = ''
    seal_expected: seal_Dict[str, str] = seal_field(default_factory=dict)
    seal_actual: seal_Optional[str] = None

def seal_resolve(seal_base: str, seal_rel: str, *, seal_follow_leaf: bool=False) -> seal_Optional[str]:
    """Resolve a sealed path inside the bundle, or ``None`` if it escapes it.

    Resolve parent links before containment checks. Leave a final symlink intact
    when checking its recorded target; never open that target in this mode.
    This is an inspection-time check, not protection against concurrent changes.
    """
    if seal_os.path.isabs(seal_rel) or seal_rel.startswith('~') or '\x00' in seal_rel:
        return None
    seal_base_abs = seal_os.path.abspath(seal_base)
    seal_full = seal_os.path.abspath(seal_os.path.join(seal_base_abs, seal_rel))
    if seal_os.path.commonpath((seal_base_abs, seal_full)) != seal_base_abs:
        return None
    seal_root = seal_os.path.realpath(seal_base_abs)
    if seal_full == seal_base_abs:
        return seal_root
    seal_parent = seal_os.path.realpath(seal_os.path.dirname(seal_full))
    if seal_os.path.commonpath((seal_root, seal_parent)) != seal_root:
        return None
    seal_resolved = seal_os.path.join(seal_parent, seal_os.path.basename(seal_full))
    if seal_follow_leaf:
        seal_resolved = seal_os.path.realpath(seal_resolved)
        if seal_os.path.commonpath((seal_root, seal_resolved)) != seal_root:
            return None
    return seal_resolved

def seal_seal_path(seal_layout: BundlePaths) -> str:
    seal_base = seal_resolve(seal_layout.seal_root, seal_os.path.relpath(seal_layout.seal_base, seal_layout.seal_root), seal_follow_leaf=True)
    if seal_base is None:
        raise ResourceSealFault('bundle base resolves outside the bundle')
    location_path = seal_resolve(seal_layout.seal_base, seal_os.path.relpath(seal_layout.seal_code_resources, seal_layout.seal_base), seal_follow_leaf=True)
    if location_path is None:
        raise ResourceSealFault('resource seal resolves outside the bundle')
    return location_path

def seal_check_one(seal_base: str, seal_rel: str, seal_entry: SealItem) -> SealCheck:
    seal_kind = seal_entry.seal_kind
    seal_full = seal_resolve(seal_base, seal_rel)
    if seal_full is None:
        return SealCheck(location_path=seal_rel, seal_kind=seal_kind, seal_status='escape', seal_detail='the sealed path resolves outside the bundle')
    if seal_kind == 'hash':
        if not seal_os.path.lexists(seal_full):
            return SealCheck(location_path=seal_rel, seal_kind=seal_kind, seal_status='missing', seal_expected=dict(seal_entry.seal_hashes))
        if seal_os.path.islink(seal_full) or not seal_os.path.isfile(seal_full):
            return SealCheck(location_path=seal_rel, seal_kind=seal_kind, seal_status='type', seal_detail='sealed as a file but is not one now', seal_expected=dict(seal_entry.seal_hashes))
        if seal_entry.seal_unknown_digest is not None and (not seal_entry.seal_hashes):
            seal_detail = 'the entry carries no digest this tool can compute' if seal_entry.seal_unknown_digest < 0 else 'digest of %d bytes has no known algorithm' % seal_entry.seal_unknown_digest
            return SealCheck(location_path=seal_rel, seal_kind=seal_kind, seal_status='unsupported', seal_detail=seal_detail)
        for seal_algo in sorted(seal_entry.seal_hashes):
            seal_expected = seal_entry.seal_hashes[seal_algo]
            try:
                seal_actual = seal_hash_file(seal_full, seal_algo)
            except OSError as seal_exc:
                return SealCheck(location_path=seal_rel, seal_kind=seal_kind, seal_status='missing', seal_detail='unreadable: %s' % seal_exc, seal_expected=dict(seal_entry.seal_hashes))
            if seal_actual != seal_expected:
                return SealCheck(location_path=seal_rel, seal_kind=seal_kind, seal_status='mismatch', seal_detail='%s digest differs' % seal_algo, seal_expected={seal_algo: seal_expected}, seal_actual=seal_actual)
        return SealCheck(location_path=seal_rel, seal_kind=seal_kind, seal_status='ok', seal_expected=dict(seal_entry.seal_hashes))
    if seal_kind == 'symlink':
        if not seal_os.path.lexists(seal_full):
            return SealCheck(location_path=seal_rel, seal_kind=seal_kind, seal_status='missing', seal_expected={'symlink': seal_entry.seal_symlink or ''})
        if not seal_os.path.islink(seal_full):
            return SealCheck(location_path=seal_rel, seal_kind=seal_kind, seal_status='type', seal_detail='sealed as a symlink but is not one now', seal_expected={'symlink': seal_entry.seal_symlink or ''})
        destination = seal_os.readlink(seal_full)
        if destination != seal_entry.seal_symlink:
            return SealCheck(location_path=seal_rel, seal_kind=seal_kind, seal_status='mismatch', seal_detail='symlink target differs', seal_expected={'symlink': seal_entry.seal_symlink or ''}, seal_actual=destination)
        return SealCheck(location_path=seal_rel, seal_kind=seal_kind, seal_status='ok', seal_expected={'symlink': seal_entry.seal_symlink or ''})
    if seal_kind == 'nested':
        seal_full = seal_resolve(seal_base, seal_rel, seal_follow_leaf=True)
        if seal_full is None:
            return SealCheck(location_path=seal_rel, seal_kind=seal_kind, seal_status='escape', seal_detail='nested code resolves outside the bundle')
        if not seal_os.path.exists(seal_full):
            return SealCheck(location_path=seal_rel, seal_kind=seal_kind, seal_status='missing', seal_detail='listed as nested code but absent', seal_expected=dict(seal_entry.seal_hashes))
        return SealCheck(location_path=seal_rel, seal_kind=seal_kind, seal_status='ok', seal_detail='nested code; its requirement is not evaluated')
    return SealCheck(location_path=seal_rel, seal_kind='unknown', seal_status='unsupported', seal_detail='entry is neither a digest, a symlink nor nested code')

def seal_compile_rules(source: seal_Any) -> seal_List[seal_Tuple[seal_Any, seal_Dict[str, seal_Any]]]:
    """Order a rule set the way the sealer applies it: highest weight first."""
    seal_rules: seal_List[seal_Tuple[seal_Any, seal_Dict[str, seal_Any], float, int]] = []
    if not isinstance(source, dict):
        return []
    for seal_order, (seal_pattern, seal_rule) in enumerate(source.items()):
        if not isinstance(seal_pattern, str):
            continue
        try:
            seal_regex = seal_re.compile(seal_pattern)
        except seal_re.error:
            continue
        if isinstance(seal_rule, dict):
            seal_body: seal_Dict[str, seal_Any] = seal_rule
        elif seal_rule is False:
            seal_body = {'omit': True}
        else:
            seal_body = {}
        seal_weight = seal_body.get('weight') or 0.0
        try:
            seal_weight = float(seal_weight)
        except (TypeError, ValueError):
            seal_weight = 0.0
        seal_rules.append((seal_regex, seal_body, seal_weight, seal_order))
    seal_rules.sort(key=lambda seal_item: (-seal_item[2], seal_item[3]))
    return [(seal_regex, seal_body) for seal_regex, seal_body, seal_w, seal_o in seal_rules]

def seal_classify(seal_rel: str, seal_rules: seal_List[seal_Tuple[seal_Any, seal_Dict[str, seal_Any]]]) -> str:
    """What the rules say should happen to ``rel``: hash, nested, omit or none."""
    for seal_regex, seal_body in seal_rules:
        if seal_regex.search(seal_rel):
            if seal_body.get('omit'):
                return 'omit'
            if seal_body.get('nested'):
                return 'nested'
            return 'hash'
    return 'none'

def seal_walk_files(seal_base: str) -> seal_List[str]:
    """Every non-directory item under ``base``, as sealed-path style relatives."""
    output: seal_List[str] = []
    for seal_root, seal_dirs_value, seal_files in seal_os.walk(seal_base, followlinks=False):
        if seal_os.path.normpath(seal_root) == seal_os.path.normpath(seal_base):
            seal_dirs_value[:] = [seal_d for seal_d in seal_dirs_value if seal_d != SEAL_SEAL_DIRNAME]
        for label in list(seal_dirs_value):
            seal_full = seal_os.path.join(seal_root, label)
            if seal_os.path.islink(seal_full):
                output.append(seal_os.path.relpath(seal_full, seal_base).replace(seal_os.sep, '/'))
        for label in seal_files:
            seal_full = seal_os.path.join(seal_root, label)
            output.append(seal_os.path.relpath(seal_full, seal_base).replace(seal_os.sep, '/'))
    return output

@seal_dataclass
class BundleReview:
    """What the seal covers and whether what is on disk still matches it."""
    seal_seal_path_value: str
    seal_checks: seal_List[SealCheck] = seal_field(default_factory=list)
    seal_unsealed: seal_List[str] = seal_field(default_factory=list)
    seal_seal_status: str = 'unrecorded'
    seal_seal_detail: str = ''
    seal_error: seal_Optional[str] = None

    def seal_counts(record) -> seal_Dict[str, int]:
        output = {'sealed': len(record.seal_checks), 'hashed': 0, 'nested': 0, 'symlinks': 0, 'ok': 0, 'mismatched': 0, 'missing': 0, 'other': 0}
        for seal_check in record.seal_checks:
            if seal_check.seal_kind == 'hash':
                output['hashed'] += 1
            elif seal_check.seal_kind == 'nested':
                output['nested'] += 1
            elif seal_check.seal_kind == 'symlink':
                output['symlinks'] += 1
            if seal_check.seal_status == 'ok':
                output['ok'] += 1
            elif seal_check.seal_status == 'mismatch':
                output['mismatched'] += 1
            elif seal_check.seal_status == 'missing':
                output['missing'] += 1
            else:
                output['other'] += 1
        output['unsealed'] = len(record.seal_unsealed)
        return output

    @property
    def seal_problems(record) -> seal_List[SealCheck]:
        return [seal_c for seal_c in record.seal_checks if seal_c.seal_status != 'ok']

    def seal_summary(record) -> seal_Dict[str, seal_Any]:
        seal_counts = record.seal_counts()
        return {'seal': record.seal_seal_status, 'sealed': seal_counts['sealed'], 'hashed': seal_counts['hashed'], 'nested_not_evaluated': seal_counts['nested'], 'symlinks': seal_counts['symlinks'], 'mismatched': seal_counts['mismatched'], 'missing': seal_counts['missing'], 'other': seal_counts['other'], 'unsealed_files': seal_counts['unsealed']}

    def observations(record) -> seal_List[Observation]:
        return seal_findings(record)

def seal_findings(presentation: BundleReview) -> seal_List[Observation]:
    output: seal_List[Observation] = []
    if presentation.seal_error:
        output.append(Observation(seal_id='resource-seal-unreadable', seal_severity=RiskLevel.SEAL_MEDIUM, seal_title='Bundle resource seal cannot be read', seal_detail='The bundle carries a resource seal that could not be parsed, so what it covers could not be checked: %s' % presentation.seal_error, seal_evidence={'seal': presentation.seal_seal_path_value}))
    if presentation.seal_seal_status == 'mismatch':
        output.append(Observation(seal_id='resource-seal-mismatch', seal_severity=RiskLevel.SEAL_HIGH, seal_title='Resource seal does not match the signature that records it', seal_detail='The CodeDirectory records a hash for the resource seal, and the seal on disk does not have it. The signatures over the code are intact, but the list that says which resources are sealed has been replaced with a different one.', seal_evidence={'seal': presentation.seal_seal_path_value, 'detail': presentation.seal_seal_detail}))
    elif presentation.seal_seal_status == 'absent':
        output.append(Observation(seal_id='resource-seal-absent', seal_severity=RiskLevel.SEAL_HIGH, seal_title='Signature records a resource seal that is not there', seal_detail="The CodeDirectory has a ResourceDir hash, but the bundle has no _CodeSignature/CodeResources. The signature expects a seal over the bundle's resources and there is none to check.", seal_evidence={'seal': presentation.seal_seal_path_value}))
    seal_problems = presentation.seal_problems
    seal_shown = seal_problems[:SEAL_MAX_REPORTED_RESOURCES]
    for seal_check in seal_shown:
        if seal_check.seal_status == 'mismatch' and seal_check.seal_kind == 'hash':
            output.append(Observation(seal_id='resource-hash-mismatch', seal_severity=RiskLevel.SEAL_HIGH, seal_title='Sealed resource has been modified: %s' % seal_check.location_path, seal_detail='The resource seal records a %s digest for this file and the file no longer has it. The code signature is unaffected; the file is inside the bundle it was signed to protect.' % seal_check.seal_detail.replace(' digest differs', ''), seal_evidence={'resource': seal_check.location_path, 'expected': seal_check.seal_expected, 'actual': seal_check.seal_actual}))
        elif seal_check.seal_status == 'mismatch' and seal_check.seal_kind == 'symlink':
            output.append(Observation(seal_id='resource-symlink-changed', seal_severity=RiskLevel.SEAL_MEDIUM, seal_title='Sealed symlink points somewhere else: %s' % seal_check.location_path, seal_detail='The seal records where this symlink pointed; it now points elsewhere, which changes what the sealed path resolves to.', seal_evidence={'resource': seal_check.location_path, 'expected': seal_check.seal_expected, 'actual': seal_check.seal_actual}))
        elif seal_check.seal_status == 'missing':
            seal_detail = 'The seal lists this item and it is not in the bundle, so the bundle no longer matches what was signed.'
            if seal_check.seal_detail:
                seal_detail += ' (%s)' % seal_check.seal_detail
            output.append(Observation(seal_id='resource-missing', seal_severity=RiskLevel.SEAL_HIGH, seal_title='Sealed resource is missing: %s' % seal_check.location_path, seal_detail=seal_detail, seal_evidence={'resource': seal_check.location_path, 'expected': seal_check.seal_expected}))
        elif seal_check.seal_status == 'type':
            output.append(Observation(seal_id='resource-type-changed', seal_severity=RiskLevel.SEAL_MEDIUM, seal_title='Sealed item changed kind: %s' % seal_check.location_path, seal_detail='%s. What was sealed and what is there now are different kinds of thing.' % (seal_check.seal_detail or 'The item changed kind'), seal_evidence={'resource': seal_check.location_path, 'expected': seal_check.seal_expected}))
        elif seal_check.seal_status == 'escape':
            output.append(Observation(seal_id='resource-path-escape', seal_severity=RiskLevel.SEAL_HIGH, seal_title='Seal lists a path outside the bundle: %s' % seal_check.location_path, seal_detail='A sealed path that resolves outside the bundle would have the tool read a file it was never meant to cover. The path was not followed.', seal_evidence={'resource': seal_check.location_path}))
        elif seal_check.seal_status == 'unsupported':
            output.append(Observation(seal_id='resource-hash-unsupported', seal_severity=RiskLevel.SEAL_MEDIUM, seal_title='Sealed resource uses an unknown digest: %s' % seal_check.location_path, seal_detail='The seal carries a digest this tool cannot compute, so this entry could not be checked: %s' % seal_check.seal_detail, seal_evidence={'resource': seal_check.location_path}))
    seal_remaining = len(seal_problems) - len(seal_shown)
    if seal_remaining > 0:
        output.append(Observation(seal_id='resource-problems-remain', seal_severity=RiskLevel.SEAL_HIGH, seal_title='%d further sealed resources do not match' % seal_remaining, seal_detail='More resources are missing or modified than are listed individually here; every one of them is a file the signature was supposed to cover.', seal_evidence={'count': seal_remaining, 'examples': [seal_c.location_path for seal_c in seal_problems[len(seal_shown):][:20]]}))
    if presentation.seal_unsealed:
        output.append(Observation(seal_id='resource-unsealed', seal_severity=RiskLevel.SEAL_MEDIUM, seal_title='%d file(s) in the bundle are not covered by the seal' % len(presentation.seal_unsealed), seal_detail="The seal's own rules say these paths must be hashed, and the seal does not list them. This is what adding a resource to a signed bundle looks like; it can also mean the seal predates the file.", seal_evidence={'files': presentation.seal_unsealed[:20]}))
    return output

def seal_verify_seal(seal_layout: BundlePaths, seal_recorded_seal: seal_Optional[seal_Dict[str, str]]=None, seal_check_unsealed: bool=True) -> BundleReview:
    """Check the seal against the files on disk.

    ``recorded_seal`` maps a hashlib algorithm name to the digest the CodeDirectory
    recorded for this seal file (its ResourceDir special slot). When it is given,
    the seal file itself is checked against it.
    """
    presentation = BundleReview(seal_seal_path_value=seal_layout.seal_code_resources)
    try:
        seal_seal_path_value = seal_seal_path(seal_layout)
    except ResourceSealFault as seal_exc:
        presentation.seal_error = str(seal_exc)
        presentation.seal_seal_status = 'unreadable'
        return presentation
    if not seal_os.path.isfile(seal_seal_path_value):
        presentation.seal_seal_status = 'absent' if seal_recorded_seal else 'unrecorded'
        return presentation
    try:
        seal_seal = seal_load_seal(seal_layout)
    except ResourceSealFault as seal_exc:
        presentation.seal_error = str(seal_exc)
        presentation.seal_seal_status = 'unreadable'
        return presentation
    if seal_recorded_seal:
        seal_got = {}
        for seal_algo in sorted(seal_recorded_seal):
            try:
                seal_got[seal_algo] = seal_hash_file(seal_seal_path_value, seal_algo)
            except OSError as seal_exc:
                presentation.seal_error = str(seal_exc)
                presentation.seal_seal_status = 'unreadable'
                return presentation
        if any((seal_got.get(seal_algo) == seal_digest_value for seal_algo, seal_digest_value in seal_recorded_seal.items())):
            presentation.seal_seal_status = 'match'
        else:
            presentation.seal_seal_status = 'mismatch'
            presentation.seal_seal_detail = 'recorded %s, on disk %s' % (', '.join(('%s:%s' % (seal_a, seal_d[:16]) for seal_a, seal_d in sorted(seal_recorded_seal.items()))), ', '.join(('%s:%s' % (seal_a, seal_d[:16]) for seal_a, seal_d in sorted(seal_got.items()))))
    seal_entries = seal_collect_entries(seal_seal)
    presentation.seal_checks = [seal_check_one(seal_layout.seal_base, seal_rel, seal_entry) for seal_rel, seal_entry in sorted(seal_entries.items())]
    if seal_check_unsealed:
        seal_listed = set(seal_entries)
        seal_v1_rules = seal_compile_rules(seal_seal.get('rules'))
        seal_v2_rules = seal_compile_rules(seal_seal.get('rules2'))
        for seal_rel in seal_walk_files(seal_layout.seal_base):
            if seal_rel in seal_listed:
                continue
            if seal_classify(seal_rel, seal_v2_rules) != 'hash':
                continue
            if seal_v1_rules and seal_classify(seal_rel, seal_v1_rules) != 'hash':
                continue
            presentation.seal_unsealed.append(seal_rel)
        presentation.seal_unsealed.sort()
    return presentation
