"""Declared Mach-O and embedded-signature ranges are hard parser boundaries."""
import struct

import pytest

from sealscope import containers, signing_frames


def thin_header(*, ncmds=0, sizeofcmds=0):
    return struct.pack('<IiiIIIII', 0xFEEDFACF, 0x0100000C, 0, 2, ncmds, sizeofcmds, 0, 0)


def fat_slice(data, declared_size):
    table = struct.pack('>IIiiIII', 0xCAFEBABE, 1, 0x0100000C, 0, 28, declared_size, 0)
    return table + data


def code_directory():
    identifier = b'com.example.bounds\0'
    blob_length = 44 + 32 + len(identifier)
    header = struct.pack(
        '>IIIIIIIIIBBBBI', signing_frames.SEAL_CSMAGIC_CODEDIRECTORY,
        blob_length, 0x20000, 0, 44, 76, 0, 1, 4096, 32, 2, 0, 12, 0,
    )
    return header + b'\x11' * 32 + identifier


def later_code_directory(version):
    tail = b'\0' * {0x20500: 52, 0x20600: 64}[version]
    identifier = b'com.example.later\0'
    hash_offset = 44 + len(tail)
    identifier_offset = hash_offset + 32
    header = struct.pack(
        '>IIIIIIIIIBBBBI', signing_frames.SEAL_CSMAGIC_CODEDIRECTORY,
        identifier_offset + len(identifier), version, 0, hash_offset,
        identifier_offset, 0, 1, 4096, 32, 2, 0, 12, 0,
    )
    return header + tail + b'\x22' * 32 + identifier


def code_directory_with_team():
    identifier = b'com.example.team\0'
    team = b'ABCDE12345\0'
    hash_offset = 52
    identifier_offset = hash_offset + 32
    team_offset = identifier_offset + len(identifier)
    header = struct.pack(
        '>IIIIIIIIIBBBBI', signing_frames.SEAL_CSMAGIC_CODEDIRECTORY,
        team_offset + len(team), 0x20200, 0, hash_offset,
        identifier_offset, 0, 1, 4096, 32, 2, 0, 12, 0,
    )
    return header + struct.pack('>II', 0, team_offset) + b'\x22' * 32 + identifier + team


def superblob(blob):
    return (struct.pack('>III', signing_frames.SEAL_CSMAGIC_EMBEDDED_SIGNATURE, 20 + len(blob), 1)
            + struct.pack('>II', 0, 20) + blob)


def test_valid_synthetic_bounds_baseline():
    assert len(containers.read_images(fat_slice(thin_header(), 32))) == 1
    blob = superblob(code_directory())
    assert signing_frames.read_envelope(blob, 0, len(blob)).seal_code_directory.seal_identifier == 'com.example.bounds'
    team_blob = superblob(code_directory_with_team())
    assert signing_frames.read_envelope(team_blob, 0, len(team_blob)).seal_code_directory.seal_team_id == 'ABCDE12345'


def test_fat_slice_declared_past_file_is_refused():
    with pytest.raises(containers.ContainerFault):
        containers.read_images(fat_slice(thin_header(), 33))


def test_load_commands_cannot_escape_fat_slice():
    command = struct.pack('<II', containers.SEAL_LC_MAIN, 8)
    payload = fat_slice(thin_header(ncmds=1, sizeofcmds=8) + command, 32)
    with pytest.raises(containers.ContainerFault):
        containers.read_images(payload)


def test_signature_reference_cannot_escape_fat_slice():
    signature = superblob(code_directory())
    command = struct.pack('<IIII', containers.SEAL_LC_CODE_SIGNATURE, 16, 48, len(signature))
    payload = fat_slice(thin_header(ncmds=1, sizeofcmds=16) + command + signature, 48)
    with pytest.raises(containers.ContainerFault):
        containers.read_images(payload)


def test_short_signature_command_is_malformed_not_unsigned():
    payload = thin_header(ncmds=1, sizeofcmds=8) + struct.pack('<II', containers.SEAL_LC_CODE_SIGNATURE, 8)
    with pytest.raises(containers.ContainerFault):
        containers.read_images(payload)


def test_superblob_cannot_exceed_supplied_signature_span():
    payload = superblob(code_directory()) + b'\0'
    with pytest.raises(signing_frames.EnvelopeFault):
        signing_frames.read_envelope(payload, 0, len(payload) - 2)


def test_index_must_fit_inside_declared_superblob():
    payload = (struct.pack('>III', signing_frames.SEAL_CSMAGIC_EMBEDDED_SIGNATURE, 12, 1)
               + struct.pack('>II', 0, 20) + code_directory())
    with pytest.raises(signing_frames.EnvelopeFault):
        signing_frames.read_envelope(payload, 0, len(payload))


def test_child_blob_must_fit_inside_declared_superblob():
    payload = (struct.pack('>III', signing_frames.SEAL_CSMAGIC_EMBEDDED_SIGNATURE, 20, 1)
               + struct.pack('>II', 0, 20) + code_directory())
    with pytest.raises(signing_frames.EnvelopeFault):
        signing_frames.read_envelope(payload, 0, len(payload))


def test_code_directory_header_must_fit_its_own_length():
    child = bytearray(code_directory())
    struct.pack_into('>I', child, 4, 8)
    payload = superblob(bytes(child))
    with pytest.raises(signing_frames.EnvelopeFault):
        signing_frames.read_envelope(payload, 0, len(payload))


def test_code_directory_version_tail_must_fit():
    child = bytearray(code_directory()[:87])
    struct.pack_into('>I', child, 4, len(child))
    struct.pack_into('>I', child, 8, 0x20400)
    payload = superblob(bytes(child))
    with pytest.raises(signing_frames.EnvelopeFault):
        signing_frames.read_envelope(payload, 0, len(payload))


@pytest.mark.parametrize('version', [0x20500, 0x20600])
def test_later_code_directory_version_tails_must_fit(version):
    child = bytearray(code_directory())
    struct.pack_into('>I', child, 8, version)
    payload = superblob(bytes(child))
    with pytest.raises(signing_frames.EnvelopeFault):
        signing_frames.read_envelope(payload, 0, len(payload))


@pytest.mark.parametrize('version', [0x20500, 0x20600])
def test_later_code_directory_complete_headers_are_accepted(version):
    payload = superblob(later_code_directory(version))
    directory = signing_frames.read_envelope(payload, 0, len(payload)).seal_code_directory
    assert directory.seal_version == version
    assert directory.seal_identifier == 'com.example.later'


def test_code_hash_table_must_fit_inside_directory():
    child = bytearray(code_directory())
    struct.pack_into('>I', child, 16, 0x1000)
    payload = superblob(bytes(child))
    with pytest.raises(signing_frames.EnvelopeFault):
        signing_frames.read_envelope(payload, 0, len(payload))


@pytest.mark.parametrize('hash_offset, special_slots', [(12, 0), (44, 1)])
def test_hash_slots_cannot_overlap_code_directory_header(hash_offset, special_slots):
    child = bytearray(code_directory())
    struct.pack_into('>I', child, 16, hash_offset)
    struct.pack_into('>I', child, 24, special_slots)
    payload = superblob(bytes(child))
    with pytest.raises(signing_frames.EnvelopeFault):
        signing_frames.read_envelope(payload, 0, len(payload))


def test_identifier_must_be_terminated_inside_directory():
    child = bytearray(code_directory())
    child[-1] = 0x41
    payload = superblob(bytes(child))
    with pytest.raises(signing_frames.EnvelopeFault):
        signing_frames.read_envelope(payload, 0, len(payload))


def test_identifier_cannot_point_into_code_directory_header():
    child = bytearray(code_directory())
    struct.pack_into('>I', child, 20, 12)
    payload = superblob(bytes(child))
    with pytest.raises(signing_frames.EnvelopeFault):
        signing_frames.read_envelope(payload, 0, len(payload))


def test_team_identifier_cannot_point_into_version_header():
    child = bytearray(code_directory_with_team())
    struct.pack_into('>I', child, 48, 12)
    payload = superblob(bytes(child))
    with pytest.raises(signing_frames.EnvelopeFault):
        signing_frames.read_envelope(payload, 0, len(payload))
