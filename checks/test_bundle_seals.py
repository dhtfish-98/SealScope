"""The bundle resource seal, tested against seals built by hand and by codesign.

Two layers, deliberately. The first builds ``CodeResources`` plists directly, so the
expected verdict for each kind of tampering is known before the tool runs and the
tests work anywhere Python does. The second builds a real bundle, signs it with
``codesign``, and tampers with it — the ground truth there is Apple's own signer and
validator, not this file's idea of what a seal looks like.
"""
from __future__ import annotations as seal_annotations
import hashlib as seal_hashlib
import os as seal_os
import plistlib as seal_plistlib
import shutil as seal_shutil
import subprocess as seal_subprocess
import pytest as seal_pytest
from specimens import seal_compile as seal_compile, seal_requires_toolchain as seal_requires_toolchain
from sealscope import inspect_bundle as inspect_bundle, bundle_seals as bundle_seals
SEAL_RULES2 = {'^Resources/': {'weight': 20.0}, '^.*': {'omit': True}}

def seal_digest(content: bytes) -> dict:
    return {'hash': seal_hashlib.sha1(content).digest(), 'hash2': seal_hashlib.sha256(content).digest()}

def seal_make_bundle(seal_root: str, seal_resources_files: dict, seal_entries: dict, seal_rules2: dict=None, seal_seal: bytes=None) -> str:
    """Write a bundle whose seal says whatever the test needs it to say."""
    seal_base = seal_os.path.join(seal_root, 'Contents')
    seal_os.makedirs(seal_os.path.join(seal_base, 'MacOS'), exist_ok=True)
    seal_os.makedirs(seal_os.path.join(seal_base, 'Resources'), exist_ok=True)
    with open(seal_os.path.join(seal_base, 'Info.plist'), 'wb') as stream:
        seal_plistlib.dump({'CFBundleExecutable': 'demo', 'CFBundleIdentifier': 'com.example.demo'}, stream)
    with open(seal_os.path.join(seal_base, 'MacOS', 'demo'), 'wb') as stream:
        stream.write(b'\xcf\xfa\xed\xfe' + b'\x00' * 60)
    for seal_rel, content in seal_resources_files.items():
        seal_full = seal_os.path.join(seal_base, seal_rel)
        seal_os.makedirs(seal_os.path.dirname(seal_full), exist_ok=True)
        if isinstance(content, tuple):
            seal_os.symlink(content[1], seal_full)
        else:
            with open(seal_full, 'wb') as stream:
                stream.write(content)
    seal_os.makedirs(seal_os.path.join(seal_base, '_CodeSignature'), exist_ok=True)
    seal_seal_path_value = seal_os.path.join(seal_base, '_CodeSignature', 'CodeResources')
    if seal_seal is None:
        seal_body = {'files2': seal_entries, 'rules2': SEAL_RULES2 if seal_rules2 is None else seal_rules2}
        with open(seal_seal_path_value, 'wb') as stream:
            seal_plistlib.dump(seal_body, stream)
    else:
        with open(seal_seal_path_value, 'wb') as stream:
            stream.write(seal_seal)
    return seal_root

def seal_verify(seal_root: str, seal_recorded_seal: dict=None) -> bundle_seals.BundleReview:
    seal_layout = bundle_seals.seal_find_bundle(seal_root)
    assert seal_layout is not None, 'the test built something that is not a bundle'
    return bundle_seals.seal_verify_seal(seal_layout, seal_recorded_seal=seal_recorded_seal)

def seal_ids(presentation: bundle_seals.BundleReview) -> list:
    return [seal_f.seal_id for seal_f in presentation.observations()]

def test_seal_find_bundle_macos_layout(tmp_path):
    seal_root = seal_make_bundle(str(tmp_path / 'Demo.app'), {'Resources/a.txt': b'a'}, {})
    seal_layout = bundle_seals.seal_find_bundle(seal_root)
    assert seal_layout is not None
    assert seal_layout.seal_base.endswith('Contents')
    assert seal_layout.seal_executable.endswith(seal_os.path.join('MacOS', 'demo'))
    assert not seal_layout.seal_flat

def test_seal_find_bundle_flat_layout(tmp_path):
    seal_root = str(tmp_path / 'Flat.app')
    seal_os.makedirs(seal_root)
    with open(seal_os.path.join(seal_root, 'Info.plist'), 'wb') as stream:
        seal_plistlib.dump({'CFBundleExecutable': 'flat'}, stream)
    with open(seal_os.path.join(seal_root, 'flat'), 'wb') as stream:
        stream.write(b'\xcf\xfa\xed\xfe' + b'\x00' * 60)
    seal_layout = bundle_seals.seal_find_bundle(seal_root)
    assert seal_layout is not None and seal_layout.seal_flat
    assert seal_layout.seal_executable == seal_os.path.join(seal_root, 'flat')

def test_seal_find_bundle_rejects_plain_directory(tmp_path):
    seal_plain = tmp_path / 'not-a-bundle'
    seal_plain.mkdir()
    assert bundle_seals.seal_find_bundle(str(seal_plain)) is None
    assert bundle_seals.seal_find_bundle(str(tmp_path / 'missing')) is None

def test_seal_clean_bundle_has_no_findings(tmp_path):
    content = b'hello\n'
    seal_root = seal_make_bundle(str(tmp_path / 'Demo.app'), {'Resources/a.txt': content}, {'Resources/a.txt': seal_digest(content)})
    presentation = seal_verify(seal_root)
    assert presentation.seal_problems == []
    assert presentation.seal_unsealed == []
    assert seal_ids(presentation) == []
    assert presentation.seal_counts()['hashed'] == 1

def test_seal_modified_resource_is_a_mismatch(tmp_path):
    seal_root = seal_make_bundle(str(tmp_path / 'Demo.app'), {'Resources/a.txt': b'hello\n'}, {'Resources/a.txt': seal_digest(b'hello\n')})
    with open(seal_os.path.join(seal_root, 'Contents', 'Resources', 'a.txt'), 'wb') as stream:
        stream.write(b'goodbye\n')
    presentation = seal_verify(seal_root)
    assert seal_ids(presentation) == ['resource-hash-mismatch']
    seal_finding = presentation.observations()[0]
    assert seal_finding.seal_severity == 'high'
    assert seal_finding.seal_evidence['resource'] == 'Resources/a.txt'
    assert seal_finding.seal_evidence['expected'] == {'sha1': seal_hashlib.sha1(b'hello\n').hexdigest()}
    assert seal_finding.seal_evidence['actual'] == seal_hashlib.sha1(b'goodbye\n').hexdigest()

def test_seal_deleted_resource_is_missing(tmp_path):
    seal_root = seal_make_bundle(str(tmp_path / 'Demo.app'), {}, {'Resources/a.txt': seal_digest(b'hello\n')})
    presentation = seal_verify(seal_root)
    assert seal_ids(presentation) == ['resource-missing']

def test_seal_added_resource_is_reported_as_unsealed(tmp_path):
    seal_root = seal_make_bundle(str(tmp_path / 'Demo.app'), {'Resources/a.txt': b'a'}, {'Resources/a.txt': seal_digest(b'a')})
    with open(seal_os.path.join(seal_root, 'Contents', 'Resources', 'extra.txt'), 'wb') as stream:
        stream.write(b'smuggled\n')
    presentation = seal_verify(seal_root)
    assert presentation.seal_unsealed == ['Resources/extra.txt']
    assert seal_ids(presentation) == ['resource-unsealed']

def test_seal_file_omitted_by_the_rules_is_not_reported(tmp_path):
    seal_root = seal_make_bundle(str(tmp_path / 'Demo.app'), {'Resources/a.txt': b'a'}, {'Resources/a.txt': seal_digest(b'a')})
    with open(seal_os.path.join(seal_root, 'Contents', '.DS_Store'), 'wb') as stream:
        stream.write(b'junk')
    presentation = seal_verify(seal_root)
    assert presentation.seal_unsealed == []

def test_seal_highest_weight_rule_wins(tmp_path):
    """``^.*`` omits everything; a heavier ``^Resources/`` must still seal."""
    seal_rules2 = {'^.*': {'omit': True}, '^Resources/': {'weight': 20.0}}
    seal_root = seal_make_bundle(str(tmp_path / 'Demo.app'), {'Resources/a.txt': b'a'}, {'Resources/a.txt': seal_digest(b'a')}, seal_rules2=seal_rules2)
    assert seal_verify(seal_root).seal_unsealed == []

def test_seal_equal_weight_rules_keep_document_order():
    """With no weight to separate them, the earlier rule is the one that applies."""
    seal_rules = bundle_seals.seal_compile_rules({'^Resources/': {}, '^.*': {'omit': True}})
    assert bundle_seals.seal_classify('Resources/a.txt', seal_rules) == 'hash'
    assert bundle_seals.seal_classify('Info.plist', seal_rules) == 'omit'

def test_seal_symlink_target_change_is_reported(tmp_path):
    seal_root = seal_make_bundle(str(tmp_path / 'Demo.app'), {'Resources/current': ('symlink', 'v1')}, {'Resources/current': {'symlink': 'v1'}})
    seal_os.remove(seal_os.path.join(seal_root, 'Contents', 'Resources', 'current'))
    seal_os.symlink('v2', seal_os.path.join(seal_root, 'Contents', 'Resources', 'current'))
    presentation = seal_verify(seal_root)
    assert seal_ids(presentation) == ['resource-symlink-changed']
    assert presentation.observations()[0].seal_evidence['actual'] == 'v2'

def test_seal_sealed_symlink_that_became_a_file_is_a_type_change(tmp_path):
    seal_root = seal_make_bundle(str(tmp_path / 'Demo.app'), {'Resources/current': b'v1'}, {'Resources/current': {'symlink': 'v1'}})
    presentation = seal_verify(seal_root)
    assert seal_ids(presentation) == ['resource-type-changed']

def test_seal_nested_code_that_is_absent_is_missing(tmp_path):
    seal_root = seal_make_bundle(str(tmp_path / 'Demo.app'), {}, {'Frameworks/Gone.framework': {'cdhash': b'\x01' * 20, 'requirement': b'designated => true'}})
    presentation = seal_verify(seal_root)
    assert seal_ids(presentation) == ['resource-missing']
    assert 'nested code' in presentation.seal_problems[0].seal_detail

def test_seal_nested_code_that_is_present_is_not_hash_checked(tmp_path):
    seal_root = seal_make_bundle(str(tmp_path / 'Demo.app'), {}, {})
    seal_os.makedirs(seal_os.path.join(seal_root, 'Contents', 'Frameworks'))
    with open(seal_os.path.join(seal_root, 'Contents', 'Frameworks', 'Present.framework'), 'wb') as stream:
        stream.write(b'not really a framework')
    seal_layout = bundle_seals.seal_find_bundle(seal_root)
    seal_seal = bundle_seals.seal_load_seal(seal_layout)
    seal_seal['files2']['Frameworks/Present.framework'] = {'cdhash': b'\x02' * 20, 'requirement': b'designated => true'}
    with open(seal_layout.seal_code_resources, 'wb') as stream:
        seal_plistlib.dump(seal_seal, stream)
    presentation = seal_verify(seal_root)
    assert seal_ids(presentation) == []
    assert presentation.seal_counts()['nested'] == 1

def test_seal_a_path_that_escapes_the_bundle_is_not_followed(tmp_path):
    seal_outside = tmp_path / 'outside.txt'
    seal_outside.write_bytes(b'not yours')
    seal_root = seal_make_bundle(str(tmp_path / 'Demo.app'), {}, {})
    seal_layout = bundle_seals.seal_find_bundle(seal_root)
    seal_seal = bundle_seals.seal_load_seal(seal_layout)
    seal_seal['files2']['../../outside.txt'] = seal_digest(b'not yours')
    with open(seal_layout.seal_code_resources, 'wb') as stream:
        seal_plistlib.dump(seal_seal, stream)
    presentation = seal_verify(seal_root)
    assert seal_ids(presentation) == ['resource-path-escape']

def test_seal_parent_symlink_cannot_escape_for_hashing(tmp_path, monkeypatch):
    seal_outside = tmp_path / 'outside'
    seal_outside.mkdir()
    (seal_outside / 'canary').write_bytes(b'fixture')
    seal_root = seal_make_bundle(str(tmp_path / 'Demo.app'), {}, {'linked/canary': seal_digest(b'fixture')})
    seal_os.symlink(seal_outside, seal_os.path.join(seal_root, 'Contents', 'linked'))

    def seal_unexpected_read(*options):
        raise AssertionError('escaped file was opened for hashing')
    monkeypatch.setattr(bundle_seals, 'seal_hash_file', seal_unexpected_read)
    assert seal_ids(seal_verify(seal_root)) == ['resource-path-escape']

def test_seal_parent_symlink_inside_bundle_still_hashes(tmp_path):
    seal_root = seal_make_bundle(str(tmp_path / 'Demo.app'), {'Resources/a': b'a'}, {'linked/a': seal_digest(b'a')}, seal_rules2={})
    seal_os.symlink('Resources', seal_os.path.join(seal_root, 'Contents', 'linked'))
    assert seal_verify(seal_root).seal_problems == []

def test_seal_sealed_leaf_symlink_is_compared_without_following_target(tmp_path, monkeypatch):
    seal_root = seal_make_bundle(str(tmp_path / 'Demo.app'), {'Resources/link': ('symlink', '../../../outside')}, {'Resources/link': {'symlink': '../../../outside'}})
    monkeypatch.setattr(bundle_seals, 'seal_hash_file', lambda *options: seal_pytest.fail('followed a sealed symlink'))
    assert seal_verify(seal_root).seal_problems == []

@seal_pytest.mark.parametrize('label', ['/tmp/outside', '../../outside', '../MacOS/demo'])
def test_seal_executable_name_must_be_a_filename(tmp_path, label):
    seal_root = seal_make_bundle(str(tmp_path / 'Demo.app'), {}, {})
    with open(seal_os.path.join(seal_root, 'Contents', 'Info.plist'), 'wb') as stream:
        seal_plistlib.dump({'CFBundleExecutable': label}, stream)
    assert bundle_seals.seal_find_bundle(seal_root).seal_executable is None

def test_seal_executable_symlink_cannot_leave_bundle(tmp_path):
    seal_root = seal_make_bundle(str(tmp_path / 'Demo.app'), {}, {})
    seal_outside = tmp_path / 'outside'
    seal_outside.write_bytes(b'\xcf\xfa\xed\xfe' + b'\x00' * 60)
    seal_exe = seal_os.path.join(seal_root, 'Contents', 'MacOS', 'demo')
    seal_os.remove(seal_exe)
    seal_os.symlink(seal_outside, seal_exe)
    assert bundle_seals.seal_find_bundle(seal_root).seal_executable is None

def test_seal_info_plist_symlink_cannot_leave_bundle(tmp_path):
    seal_root = seal_make_bundle(str(tmp_path / 'Demo.app'), {}, {})
    seal_info = seal_os.path.join(seal_root, 'Contents', 'Info.plist')
    seal_outside = tmp_path / 'outside.plist'
    seal_os.rename(seal_info, seal_outside)
    seal_os.symlink(seal_outside, seal_info)
    assert bundle_seals.seal_find_bundle(seal_root) is None

@seal_pytest.mark.parametrize('seal_link_directory', [False, True])
def test_seal_resource_seal_symlink_cannot_leave_bundle(tmp_path, seal_link_directory):
    seal_root = seal_make_bundle(str(tmp_path / 'Demo.app'), {}, {})
    seal_signature = seal_os.path.join(seal_root, 'Contents', '_CodeSignature')
    seal_original = seal_signature if seal_link_directory else seal_os.path.join(seal_signature, 'CodeResources')
    seal_outside = tmp_path / 'outside'
    seal_os.rename(seal_original, seal_outside)
    seal_os.symlink(seal_outside, seal_original)
    presentation = seal_verify(seal_root)
    assert presentation.seal_seal_status == 'unreadable'
    assert 'outside' in presentation.seal_error

def test_seal_nested_code_symlink_cannot_leave_bundle(tmp_path):
    seal_outside = tmp_path / 'outside'
    seal_outside.mkdir()
    seal_root = seal_make_bundle(str(tmp_path / 'Demo.app'), {}, {'Nested': {'requirement': 'true'}})
    seal_os.symlink(seal_outside, seal_os.path.join(seal_root, 'Contents', 'Nested'))
    assert seal_ids(seal_verify(seal_root)) == ['resource-path-escape']

def test_seal_unknown_digest_size_is_reported_not_guessed(tmp_path):
    seal_root = seal_make_bundle(str(tmp_path / 'Demo.app'), {'Resources/a.txt': b'a'}, {'Resources/a.txt': b'\x00' * 24})
    presentation = seal_verify(seal_root)
    assert seal_ids(presentation) == ['resource-hash-unsupported']

def test_seal_seal_that_does_not_parse_is_reported(tmp_path):
    seal_root = seal_make_bundle(str(tmp_path / 'Demo.app'), {'Resources/a.txt': b'a'}, {}, seal_seal=b'this is not a plist')
    presentation = seal_verify(seal_root)
    assert presentation.seal_error is not None
    assert seal_ids(presentation) == ['resource-seal-unreadable']

def test_seal_seal_hash_mismatch_is_reported(tmp_path):
    content = b'hello\n'
    seal_root = seal_make_bundle(str(tmp_path / 'Demo.app'), {'Resources/a.txt': content}, {'Resources/a.txt': seal_digest(content)})
    seal_recorded = {'sha256': seal_hashlib.sha256(b'a different seal').hexdigest()}
    presentation = seal_verify(seal_root, seal_recorded_seal=seal_recorded)
    assert presentation.seal_seal_status == 'mismatch'
    assert 'resource-seal-mismatch' in seal_ids(presentation)

def test_seal_seal_hash_match_is_recorded(tmp_path):
    content = b'hello\n'
    seal_root = seal_make_bundle(str(tmp_path / 'Demo.app'), {'Resources/a.txt': content}, {'Resources/a.txt': seal_digest(content)})
    seal_seal_bytes = open(seal_os.path.join(seal_root, 'Contents', '_CodeSignature', 'CodeResources'), 'rb').read()
    seal_recorded = {'sha256': seal_hashlib.sha256(seal_seal_bytes).hexdigest()}
    presentation = seal_verify(seal_root, seal_recorded_seal=seal_recorded)
    assert presentation.seal_seal_status == 'match'
    assert seal_ids(presentation) == []

def test_seal_recorded_seal_that_is_absent_is_reported(tmp_path):
    seal_root = seal_make_bundle(str(tmp_path / 'Demo.app'), {'Resources/a.txt': b'a'}, {'Resources/a.txt': seal_digest(b'a')})
    seal_os.remove(seal_os.path.join(seal_root, 'Contents', '_CodeSignature', 'CodeResources'))
    presentation = seal_verify(seal_root, seal_recorded_seal={'sha256': '00' * 32})
    assert presentation.seal_seal_status == 'absent'
    assert seal_ids(presentation) == ['resource-seal-absent']

def test_seal_many_problems_are_capped_and_counted(tmp_path):
    seal_entries = {'Resources/f%02d.txt' % seal_i: seal_digest(b'x') for seal_i in range(60)}
    seal_root = seal_make_bundle(str(tmp_path / 'Demo.app'), {}, seal_entries)
    presentation = seal_verify(seal_root)
    seal_ids_value = seal_ids(presentation)
    assert seal_ids_value.count('resource-missing') == bundle_seals.SEAL_MAX_REPORTED_RESOURCES
    assert seal_ids_value[-1] == 'resource-problems-remain'
    assert presentation.seal_counts()['missing'] == 60

def seal_make_signed_bundle(seal_workdir: str) -> str:
    """A real bundle, signed by codesign, in its own directory under ``seal_workdir``."""
    import tempfile as seal_tempfile
    seal_root = seal_os.path.join(seal_tempfile.mkdtemp(prefix='signed-', dir=seal_workdir), 'Signed.app')
    seal_macos = seal_os.path.join(seal_root, 'Contents', 'MacOS')
    seal_res = seal_os.path.join(seal_root, 'Contents', 'Resources')
    seal_os.makedirs(seal_macos)
    seal_os.makedirs(seal_res)
    seal_exe = seal_compile(seal_workdir, 'signed_bundle_exe')
    seal_shutil.copy(seal_exe, seal_os.path.join(seal_macos, 'signed'))
    with open(seal_os.path.join(seal_root, 'Contents', 'Info.plist'), 'wb') as stream:
        seal_plistlib.dump({'CFBundleExecutable': 'signed', 'CFBundleIdentifier': 'com.example.signed'}, stream)
    with open(seal_os.path.join(seal_res, 'data.txt'), 'wb') as stream:
        stream.write(b'original resource\n')
    seal_subprocess.run(['codesign', '-f', '-s', '-', seal_root], check=True, capture_output=True)
    return seal_root

def seal_codesign_verdict(location_path: str) -> bool:
    """True when codesign considers the bundle valid."""
    seal_proc = seal_subprocess.run(['codesign', '-v', location_path], capture_output=True, text=True)
    return seal_proc.returncode == 0

@seal_requires_toolchain
def test_seal_codesign_signed_bundle_is_clean(tmp_path, seal_workdir):
    seal_root = seal_make_signed_bundle(seal_workdir)
    seal_rep = inspect_bundle(seal_root)
    assert seal_rep.bundle_seals['seal'] == 'match', seal_rep.bundle_seals
    assert seal_rep.bundle_seals['hashed'] >= 1
    assert seal_rep.seal_extra_findings == []
    assert [seal_f.seal_id for seal_f in seal_rep.observations if seal_f.seal_id.startswith('resource-')] == []
    assert seal_codesign_verdict(seal_root), 'the fixture bundle is not valid to codesign'

@seal_requires_toolchain
def test_seal_modified_resource_agrees_with_codesign(tmp_path, seal_workdir):
    seal_root = seal_os.path.join(str(tmp_path), 'Tampered.app')
    seal_shutil.copytree(seal_make_signed_bundle(seal_workdir), seal_root, symlinks=True)
    with open(seal_os.path.join(seal_root, 'Contents', 'Resources', 'data.txt'), 'wb') as stream:
        stream.write(b'tampered\n')
    presentation = seal_verify(seal_root)
    assert seal_ids(presentation) == ['resource-hash-mismatch']
    assert not seal_codesign_verdict(seal_root), 'codesign accepted what the seal rejects'

@seal_requires_toolchain
def test_seal_added_resource_agrees_with_codesign(tmp_path, seal_workdir):
    seal_root = seal_os.path.join(str(tmp_path), 'Added.app')
    seal_shutil.copytree(seal_make_signed_bundle(seal_workdir), seal_root, symlinks=True)
    with open(seal_os.path.join(seal_root, 'Contents', 'Resources', 'added.txt'), 'wb') as stream:
        stream.write(b'added later\n')
    presentation = seal_verify(seal_root)
    assert presentation.seal_unsealed == ['Resources/added.txt']
    assert not seal_codesign_verdict(seal_root), 'codesign accepted a file the seal does not list'

@seal_requires_toolchain
def test_seal_removed_resource_agrees_with_codesign(tmp_path, seal_workdir):
    seal_root = seal_os.path.join(str(tmp_path), 'Removed.app')
    seal_shutil.copytree(seal_make_signed_bundle(seal_workdir), seal_root, symlinks=True)
    seal_os.remove(seal_os.path.join(seal_root, 'Contents', 'Resources', 'data.txt'))
    presentation = seal_verify(seal_root)
    assert seal_ids(presentation) == ['resource-missing']
    assert not seal_codesign_verdict(seal_root), 'codesign accepted a bundle missing a sealed file'

@seal_requires_toolchain
def test_seal_audit_bundle_files_the_report_under_the_bundle(tmp_path, seal_workdir):
    seal_root = seal_os.path.join(str(tmp_path), 'Reported.app')
    seal_shutil.copytree(seal_make_signed_bundle(seal_workdir), seal_root, symlinks=True)
    seal_rep = inspect_bundle(seal_root)
    assert seal_rep.location_path == seal_root
    assert seal_rep.bundle_seals and seal_rep.bundle_seals['executable'] == seal_os.path.join('Contents', 'MacOS', 'signed')
    assert seal_rep.seal_extra_findings == []
    assert seal_rep.seal_slices, 'the binary inside the bundle should have been audited'
    assert seal_rep.seal_slices[0].seal_signed
    assert 'resources' in seal_rep.export_record()

@seal_requires_toolchain
def test_seal_tampered_bundle_fails_the_cli_gate(tmp_path, seal_workdir):
    from sealscope.console import launch as launch
    seal_root = seal_os.path.join(str(tmp_path), 'Gate.app')
    seal_shutil.copytree(seal_make_signed_bundle(seal_workdir), seal_root, symlinks=True)
    with open(seal_os.path.join(seal_root, 'Contents', 'Resources', 'data.txt'), 'wb') as stream:
        stream.write(b'tampered\n')
    assert launch(['--fail-on', 'high', seal_root]) == 1
