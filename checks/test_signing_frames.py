"""CodeDirectory and SuperBlob parsing.

The CodeDirectory grows by version, so the version gating is the delicate part: a
v20100 directory has no team id, and reading one anyway returns whatever bytes
follow. These tests build directories at each version and check that the fields
that should not exist are not invented.

The CDHash assertions use a real system binary, because a digest that matches
codesign(1) is the strongest evidence the field offsets are right.
"""
import hashlib as seal_hashlib
import os as seal_os
import struct as seal_struct
import subprocess as seal_subprocess
import pytest as seal_pytest
from sealscope import signing_frames as signing_frames, containers as containers

def seal_build_cd(seal_version=132096, seal_flags=0, seal_ident='com.example.app', seal_team=None, seal_hash_type=2, seal_hash_size=32, seal_page_shift=12, seal_code_limit=4096, seal_n_code=1, seal_n_special=2, seal_platform=0, seal_exec_seg_flags=0):
    """A CodeDirectory whose tail is exactly what ``version`` declares.

    The fixed header is 44 bytes; everything after it is version-gated tail, then
    the hash slots, then the string table. Offsets are relative to the start of the
    blob, and the special-slot hashes sit *before* hashOffset.
    """
    seal_tail = b''
    seal_team_field_pos = None
    if seal_version >= 131328:
        seal_tail += seal_struct.pack('>I', 0)
    if seal_version >= 131584:
        seal_team_field_pos = 44 + len(seal_tail)
        seal_tail += seal_struct.pack('>I', 0)
    if seal_version >= 131840:
        seal_tail += seal_struct.pack('>IQ', 0, 0)
    if seal_version >= 132096:
        seal_tail += seal_struct.pack('>QQQ', 0, 4096, seal_exec_seg_flags)
    seal_header_len = 44 + len(seal_tail)
    seal_hashes = b'\x11' * (seal_hash_size * seal_n_special) + b'"' * (seal_hash_size * seal_n_code)
    seal_hash_off = seal_header_len + seal_hash_size * seal_n_special
    seal_ident_off = seal_header_len + len(seal_hashes)
    seal_strings = seal_ident.encode() + b'\x00'
    seal_team_off = 0
    if seal_team is not None:
        seal_team_off = seal_ident_off + len(seal_strings)
        seal_strings += seal_team.encode() + b'\x00'
    seal_body = seal_tail + seal_hashes + seal_strings
    seal_total = 44 + len(seal_body)
    seal_cd = bytearray(seal_struct.pack('>IIIIIIIIIBBBBI', signing_frames.SEAL_CSMAGIC_CODEDIRECTORY, seal_total, seal_version, seal_flags, seal_hash_off, seal_ident_off, seal_n_special, seal_n_code, seal_code_limit, seal_hash_size, seal_hash_type, seal_platform, seal_page_shift, 0) + seal_body)
    if seal_team is not None and seal_team_field_pos is not None:
        seal_struct.pack_into('>I', seal_cd, seal_team_field_pos, seal_team_off)
    return bytes(seal_cd)

def seal_build_superblob(*seal_blob_pairs):
    """(slot, bytes) pairs -> an embedded signature SuperBlob."""
    seal_index = b''
    seal_body = b''
    seal_base = 12 + 8 * len(seal_blob_pairs)
    for seal_slot, content in seal_blob_pairs:
        seal_index += seal_struct.pack('>II', seal_slot, seal_base + len(seal_body))
        seal_body += content
    seal_total = 12 + len(seal_index) + len(seal_body)
    return seal_struct.pack('>III', signing_frames.SEAL_CSMAGIC_EMBEDDED_SIGNATURE, seal_total, len(seal_blob_pairs)) + seal_index + seal_body

def test_seal_v20400_reads_the_exec_segment_fields():
    seal_sb = seal_build_superblob((0, seal_build_cd(seal_version=132096, seal_exec_seg_flags=signing_frames.SEAL_CS_EXECSEG_JIT)))
    seal_cd = signing_frames.read_envelope(seal_sb, 0, len(seal_sb)).seal_code_directory
    assert seal_cd.seal_version == 132096
    assert seal_cd.seal_has_exec_seg_flag(signing_frames.SEAL_CS_EXECSEG_JIT)
    assert 'CS_EXECSEG_JIT' in seal_cd.seal_exec_seg_flag_names

def test_seal_v20100_has_no_team_id_and_none_is_invented():
    seal_sb = seal_build_superblob((0, seal_build_cd(seal_version=131328)))
    seal_cd = signing_frames.read_envelope(seal_sb, 0, len(seal_sb)).seal_code_directory
    assert seal_cd.seal_team_id is None
    assert seal_cd.seal_exec_seg_flags == 0

def test_seal_v20200_reads_a_team_id():
    seal_sb = seal_build_superblob((0, seal_build_cd(seal_version=131584, seal_team='ABCDE12345')))
    seal_cd = signing_frames.read_envelope(seal_sb, 0, len(seal_sb)).seal_code_directory
    assert seal_cd.seal_team_id == 'ABCDE12345'

def test_seal_identifier_is_read():
    seal_sb = seal_build_superblob((0, seal_build_cd(seal_ident='com.example.tool')))
    assert signing_frames.read_envelope(seal_sb, 0, len(seal_sb)).seal_code_directory.seal_identifier == 'com.example.tool'

def test_seal_flag_decoding():
    seal_sb = seal_build_superblob((0, seal_build_cd(seal_flags=signing_frames.SEAL_CS_ADHOC | signing_frames.SEAL_CS_RUNTIME)))
    seal_cd = signing_frames.read_envelope(seal_sb, 0, len(seal_sb)).seal_code_directory
    assert seal_cd.seal_is_adhoc and seal_cd.seal_hardened_runtime
    assert set(seal_cd.seal_flag_names) == {'CS_ADHOC', 'CS_RUNTIME'}

def test_seal_cdhash_is_the_digest_of_the_whole_directory():
    seal_cd_bytes = seal_build_cd(seal_hash_type=2)
    seal_sb = seal_build_superblob((0, seal_cd_bytes))
    seal_cd = signing_frames.read_envelope(seal_sb, 0, len(seal_sb)).seal_code_directory
    assert seal_cd.seal_cdhash == seal_hashlib.sha256(seal_cd_bytes).hexdigest()
    assert seal_cd.seal_cdhash_truncated == seal_cd.seal_cdhash[:40]

def test_seal_page_size_is_decoded_from_the_shift():
    seal_sb = seal_build_superblob((0, seal_build_cd(seal_page_shift=14)))
    assert signing_frames.read_envelope(seal_sb, 0, len(seal_sb)).seal_code_directory.seal_page_size == 16384

def test_seal_best_hash_type_prefers_the_strongest_directory():
    seal_sb = seal_build_superblob((0, seal_build_cd(seal_hash_type=1, seal_hash_size=20)), (signing_frames.SEAL_CSSLOT_ALTERNATE_CODEDIRECTORIES, seal_build_cd(seal_hash_type=2, seal_hash_size=32)))
    seal_sig = signing_frames.read_envelope(seal_sb, 0, len(seal_sb))
    assert seal_sig.seal_code_directory.seal_hash_type == 1
    assert len(seal_sig.seal_alternates) == 1
    assert seal_sig.seal_best_hash_type == 2

def test_seal_entitlement_slots_are_extracted():
    seal_xml = b'<plist/>'
    seal_der = b'p\x03\x02\x01\x01'
    seal_sb = seal_build_superblob((0, seal_build_cd()), (signing_frames.SEAL_CSSLOT_ENTITLEMENTS, seal_struct.pack('>II', signing_frames.SEAL_CSMAGIC_EMBEDDED_ENTITLEMENTS, 8 + len(seal_xml)) + seal_xml), (signing_frames.SEAL_CSSLOT_DER_ENTITLEMENTS, seal_struct.pack('>II', signing_frames.SEAL_CSMAGIC_EMBEDDED_DER_ENTITLEMENTS, 8 + len(seal_der)) + seal_der))
    seal_sig = signing_frames.read_envelope(seal_sb, 0, len(seal_sb))
    assert seal_sig.seal_entitlements_xml == seal_xml
    assert seal_sig.seal_entitlements_der == seal_der

def test_seal_cms_blob_is_recognised():
    seal_cms = b'0\x82fake'
    seal_sb = seal_build_superblob((0, seal_build_cd()), (signing_frames.SEAL_CSSLOT_SIGNATURESLOT, seal_struct.pack('>II', signing_frames.SEAL_CSMAGIC_BLOBWRAPPER, 8 + len(seal_cms)) + seal_cms))
    seal_sig = signing_frames.read_envelope(seal_sb, 0, len(seal_sb))
    assert seal_sig.seal_has_cms and seal_sig.seal_cms_length == len(seal_cms)

def test_seal_adhoc_signature_has_no_cms():
    seal_sb = seal_build_superblob((0, seal_build_cd(seal_flags=signing_frames.SEAL_CS_ADHOC)))
    assert not signing_frames.read_envelope(seal_sb, 0, len(seal_sb)).seal_has_cms

def test_seal_wrong_superblob_magic_is_refused():
    with seal_pytest.raises(signing_frames.EnvelopeFault):
        signing_frames.read_envelope(seal_struct.pack('>III', 3735928559, 12, 0), 0, 12)

def test_seal_signature_without_a_code_directory_is_refused():
    seal_sb = seal_build_superblob((signing_frames.SEAL_CSSLOT_REQUIREMENTS, seal_struct.pack('>II', signing_frames.SEAL_CSMAGIC_REQUIREMENTS, 8)))
    with seal_pytest.raises(signing_frames.EnvelopeFault) as seal_exc:
        signing_frames.read_envelope(seal_sb, 0, len(seal_sb))
    assert 'CodeDirectory' in str(seal_exc.value)

def test_seal_implausible_blob_count_is_refused():
    with seal_pytest.raises(signing_frames.EnvelopeFault):
        signing_frames.read_envelope(seal_struct.pack('>III', signing_frames.SEAL_CSMAGIC_EMBEDDED_SIGNATURE, 12, 500), 0, 12)

def test_seal_blob_offset_past_the_buffer_is_refused():
    payload = seal_struct.pack('>III', signing_frames.SEAL_CSMAGIC_EMBEDDED_SIGNATURE, 20, 1) + seal_struct.pack('>II', 0, 65536)
    with seal_pytest.raises(signing_frames.EnvelopeFault):
        signing_frames.read_envelope(payload, 0, len(payload))

def test_seal_blob_with_an_impossible_length_is_refused():
    payload = seal_struct.pack('>III', signing_frames.SEAL_CSMAGIC_EMBEDDED_SIGNATURE, 28, 1) + seal_struct.pack('>II', 0, 20) + seal_struct.pack('>II', signing_frames.SEAL_CSMAGIC_CODEDIRECTORY, 2)
    with seal_pytest.raises(signing_frames.EnvelopeFault):
        signing_frames.read_envelope(payload, 0, len(payload))

def test_seal_truncated_superblob_is_refused():
    seal_sb = seal_build_superblob((0, seal_build_cd()))
    with seal_pytest.raises(signing_frames.EnvelopeFault):
        signing_frames.read_envelope(seal_sb[:20], 0, 20)

@seal_pytest.mark.skipif(not seal_os.path.exists('/usr/bin/otool'), reason='no system binary')
def test_seal_cdhash_matches_codesign_on_a_real_binary():
    payload, seal_slices = containers.read_container('/usr/bin/otool')
    for seal_sl in seal_slices:
        seal_sig = signing_frames.read_envelope(payload, seal_sl.seal_offset + seal_sl.seal_code_signature[0], seal_sl.seal_code_signature[1])
        seal_r = seal_subprocess.run(['codesign', '-d', '-vvv', '--arch', seal_sl.seal_arch, '/usr/bin/otool'], capture_output=True, text=True)
        seal_text = seal_r.stderr + seal_r.stdout
        for seal_cd in seal_sig.seal_all_directories:
            seal_needle = 'CandidateCDHashFull %s=%s' % (seal_cd.seal_hash_name, seal_cd.seal_cdhash)
            assert seal_needle in seal_text, 'codesign does not report %s' % seal_needle
