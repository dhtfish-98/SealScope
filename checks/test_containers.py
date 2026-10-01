"""Container parsing, and what happens when the container lies.

This parser is pointed at files that may be malformed or hostile, so the important
half of these tests is the refusal half: a truncated header, an implausible command
count or an offset that runs past the end must raise MachOError, never read out of
bounds and never loop.
"""
import struct as seal_struct
import pytest as seal_pytest
from sealscope import containers as containers
SEAL_MH_MAGIC_64 = 4277009103

def seal_build_header(seal_ncmds=0, seal_sizeofcmds=0, seal_flags=2097152, seal_filetype=2, seal_cputype=16777228, seal_cpusubtype=0):
    return seal_struct.pack('<IiiIIIII', SEAL_MH_MAGIC_64, seal_cputype, seal_cpusubtype, seal_filetype, seal_ncmds, seal_sizeofcmds, seal_flags, 0)

def test_seal_parses_a_minimal_thin_header():
    seal_sl = containers.read_images(seal_build_header())[0]
    assert seal_sl.seal_is64 and seal_sl.seal_endian == '<'
    assert seal_sl.seal_arch == 'arm64'
    assert seal_sl.seal_filetype_name == 'execute'
    assert seal_sl.seal_has_flag(containers.SEAL_MH_PIE)

def test_seal_arch_names_match_lipo_conventions():
    assert containers.read_images(seal_build_header(seal_cputype=16777228, seal_cpusubtype=2))[0].seal_arch == 'arm64e'
    assert containers.read_images(seal_build_header(seal_cputype=16777228, seal_cpusubtype=0))[0].seal_arch == 'arm64'
    assert containers.read_images(seal_build_header(seal_cputype=16777223, seal_cpusubtype=3))[0].seal_arch == 'x86_64'
    assert containers.read_images(seal_build_header(seal_cputype=16777223, seal_cpusubtype=8))[0].seal_arch == 'x86_64h'

def test_seal_x86_64_and_x86_64h_are_not_collapsed():
    """A fat file routinely holds both, with different signatures in each."""
    seal_a = containers.read_images(seal_build_header(seal_cputype=16777223, seal_cpusubtype=3))[0]
    seal_b = containers.read_images(seal_build_header(seal_cputype=16777223, seal_cpusubtype=8))[0]
    assert seal_a.seal_arch != seal_b.seal_arch

def test_seal_flag_names_are_reported():
    seal_sl = containers.read_images(seal_build_header(seal_flags=containers.SEAL_MH_PIE | containers.SEAL_MH_ALLOW_STACK_EXECUTION))[0]
    assert 'MH_PIE' in seal_sl.seal_flag_names
    assert 'MH_ALLOW_STACK_EXECUTION' in seal_sl.seal_flag_names

def test_seal_segment_protection_helpers():
    seal_seg = containers.RegionRecord('__TEXT', 0, 4096, 0, 4096, 7, 5, 1)
    assert seal_seg.seal_is_executable and (not seal_seg.seal_is_writable)
    seal_wx = containers.RegionRecord('__DATA', 0, 4096, 0, 4096, 7, 7, 1)
    assert seal_wx.seal_is_executable and seal_wx.seal_is_writable

def test_seal_empty_and_tiny_input_is_refused():
    for payload in (b'', b'\xcf\xfa', b'\xcf\xfa\xed'):
        with seal_pytest.raises(containers.ContainerFault):
            containers.read_images(payload)

def test_seal_wrong_magic_is_refused():
    with seal_pytest.raises(containers.ContainerFault):
        containers.read_images(b'#!/bin/sh\necho hi\n' + b'\x00' * 64)

def test_seal_truncated_header_is_refused():
    with seal_pytest.raises(containers.ContainerFault):
        containers.read_images(seal_build_header()[:20])

def test_seal_implausible_command_count_is_refused():
    with seal_pytest.raises(containers.ContainerFault) as seal_exc:
        containers.read_images(seal_build_header(seal_ncmds=999999, seal_sizeofcmds=16))
    assert 'ncmds' in str(seal_exc.value)

def test_seal_load_commands_past_end_of_file_are_refused():
    with seal_pytest.raises(containers.ContainerFault):
        containers.read_images(seal_build_header(seal_ncmds=1, seal_sizeofcmds=4096))

def test_seal_zero_length_command_is_refused_rather_than_looping():
    payload = seal_build_header(seal_ncmds=2, seal_sizeofcmds=16) + seal_struct.pack('<II', 25, 0) + b'\x00' * 8
    with seal_pytest.raises(containers.ContainerFault) as seal_exc:
        containers.read_images(payload)
    assert 'cmdsize' in str(seal_exc.value)

def test_seal_command_overrunning_sizeofcmds_is_refused():
    payload = seal_build_header(seal_ncmds=1, seal_sizeofcmds=16) + seal_struct.pack('<II', 25, 4096) + b'\x00' * 8
    with seal_pytest.raises(containers.ContainerFault):
        containers.read_images(payload)

def test_seal_implausible_fat_arch_count_is_refused():
    with seal_pytest.raises(containers.ContainerFault) as seal_exc:
        containers.read_images(seal_struct.pack('>II', 3405691582, 9999))
    assert 'nfat_arch' in str(seal_exc.value)

def test_seal_fat_slice_offset_past_end_is_refused():
    payload = seal_struct.pack('>II', 3405691582, 1) + seal_struct.pack('>iiIII', 16777228, 0, 1048576, 4096, 14)
    with seal_pytest.raises(containers.ContainerFault):
        containers.read_images(payload)

def test_seal_reads_a_real_fat_binary():
    import os as seal_os
    if not seal_os.path.exists('/usr/bin/otool'):
        seal_pytest.skip('no system binary to read')
    seal_buf, seal_slices = containers.read_container('/usr/bin/otool')
    assert len(seal_slices) >= 1
    assert all((seal_s_value.seal_code_signature for seal_s_value in seal_slices))
    assert all((seal_s_value.seal_segment('__TEXT') for seal_s_value in seal_slices))
