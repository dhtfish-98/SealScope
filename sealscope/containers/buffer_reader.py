from __future__ import annotations as seal_annotations
import struct as seal_struct
from dataclasses import dataclass as seal_dataclass, field as seal_field
from typing import Dict as seal_Dict, Iterator as seal_Iterator, List as seal_List, Optional as seal_Optional, Tuple as seal_Tuple
from .layout import *

def seal_need(payload: bytes, cursor: int, span: int, seal_what: str) -> None:
    if cursor < 0 or span < 0 or cursor + span > len(payload):
        raise ContainerFault('%s needs bytes [0x%x, 0x%x) but the file is 0x%x long' % (seal_what, cursor, cursor + span, len(payload)))

def seal_parse_slice(payload: bytes, cursor: int, span: int) -> ImageView:
    seal_need(payload, cursor, span, 'Mach-O slice')
    if span < 28:
        raise ContainerFault('Mach-O slice is smaller than its header')
    seal_need(payload, cursor, 28, 'Mach-O header')
    seal_magic = seal_struct.unpack_from('<I', payload, cursor)[0]
    if seal_magic not in (SEAL_MH_MAGIC, SEAL_MH_MAGIC_64, SEAL_MH_CIGAM, SEAL_MH_CIGAM_64):
        raise ContainerFault('bad Mach-O magic 0x%08x at 0x%x' % (seal_magic, cursor))
    seal_endian = '>' if seal_magic in (SEAL_MH_CIGAM, SEAL_MH_CIGAM_64) else '<'
    seal_is64 = seal_magic in (SEAL_MH_MAGIC_64, SEAL_MH_CIGAM_64)
    seal_hdr_size = 32 if seal_is64 else 28
    if span < seal_hdr_size:
        raise ContainerFault('Mach-O slice is smaller than its header')
    seal_need(payload, cursor, seal_hdr_size, 'Mach-O header')
    seal_cputype, seal_cpusubtype, seal_filetype, seal_ncmds, seal_sizeofcmds, seal_flags = seal_struct.unpack_from(seal_endian + 'iiIIII', payload, cursor + 4)
    seal_sl = ImageView(seal_offset=cursor, span=span, seal_cputype=seal_cputype, seal_cpusubtype=seal_cpusubtype, seal_filetype=seal_filetype, seal_ncmds=seal_ncmds, seal_flags=seal_flags, seal_is64=seal_is64, seal_endian=seal_endian)
    if seal_ncmds > 10000:
        raise ContainerFault('implausible ncmds=%d' % seal_ncmds)
    if seal_sizeofcmds > span - seal_hdr_size:
        raise ContainerFault('load commands run past the declared Mach-O slice')
    seal_need(payload, cursor + seal_hdr_size, seal_sizeofcmds, 'load commands')
    seal_p = cursor + seal_hdr_size
    seal_limit = cursor + seal_hdr_size + seal_sizeofcmds
    for _ in range(seal_ncmds):
        if seal_p + 8 > seal_limit:
            raise ContainerFault('load commands run past sizeofcmds')
        seal_cmd, seal_cmdsize = seal_struct.unpack_from(seal_endian + 'II', payload, seal_p)
        if seal_cmdsize < 8 or seal_p + seal_cmdsize > seal_limit:
            raise ContainerFault('bad cmdsize %d at 0x%x' % (seal_cmdsize, seal_p))
        seal_sl.seal_commands.append(CommandRecord(seal_cmd, seal_cmdsize, seal_p, SEAL_LC_NAMES.get(seal_cmd, 'LC_0x%x' % seal_cmd)))
        seal_read_command(payload, seal_sl, seal_cmd, seal_cmdsize, seal_p, seal_endian)
        seal_p += seal_cmdsize
    return seal_sl

def seal_cstr(payload: bytes, seal_start: int, seal_limit: int) -> str:
    seal_end = payload.find(b'\x00', seal_start, seal_limit)
    if seal_end < 0:
        seal_end = seal_limit
    return payload[seal_start:seal_end].decode('utf-8', 'replace')

def seal_read_command(payload: bytes, seal_sl: ImageView, seal_cmd: int, seal_cmdsize: int, seal_p: int, seal_e_value: str) -> None:
    if seal_cmd in (SEAL_LC_SEGMENT, SEAL_LC_SEGMENT_64):
        seal_wide = seal_cmd == SEAL_LC_SEGMENT_64
        seal_need_value = 72 if seal_wide else 56
        if seal_cmdsize < seal_need_value:
            raise ContainerFault('segment command too small')
        label = payload[seal_p + 8:seal_p + 24].split(b'\x00')[0].decode('utf-8', 'replace')
        if seal_wide:
            seal_vmaddr, seal_vmsize, seal_fileoff, seal_filesize = seal_struct.unpack_from(seal_e_value + 'QQQQ', payload, seal_p + 24)
            seal_maxprot, seal_initprot, seal_nsects, seal_fl = seal_struct.unpack_from(seal_e_value + 'iiII', payload, seal_p + 56)
        else:
            seal_vmaddr, seal_vmsize, seal_fileoff, seal_filesize = seal_struct.unpack_from(seal_e_value + 'IIII', payload, seal_p + 24)
            seal_maxprot, seal_initprot, seal_nsects, seal_fl = seal_struct.unpack_from(seal_e_value + 'iiII', payload, seal_p + 40)
        seal_sl.seal_segments.append(RegionRecord(label, seal_vmaddr, seal_vmsize, seal_fileoff, seal_filesize, seal_maxprot, seal_initprot, seal_nsects))
    elif seal_cmd in (SEAL_LC_LOAD_DYLIB, SEAL_LC_LOAD_WEAK_DYLIB, SEAL_LC_REEXPORT_DYLIB, SEAL_LC_ID_DYLIB):
        if seal_cmdsize >= 24:
            seal_noff = seal_struct.unpack_from(seal_e_value + 'I', payload, seal_p + 8)[0]
            if 0 < seal_noff < seal_cmdsize:
                seal_sl.seal_dylibs.append((SEAL_LC_NAMES.get(seal_cmd, 'LC_0x%x' % seal_cmd), seal_cstr(payload, seal_p + seal_noff, seal_p + seal_cmdsize)))
    elif seal_cmd == SEAL_LC_RPATH:
        if seal_cmdsize >= 12:
            seal_noff = seal_struct.unpack_from(seal_e_value + 'I', payload, seal_p + 8)[0]
            if 0 < seal_noff < seal_cmdsize:
                seal_sl.seal_rpaths.append(seal_cstr(payload, seal_p + seal_noff, seal_p + seal_cmdsize))
    elif seal_cmd == SEAL_LC_CODE_SIGNATURE:
        if seal_cmdsize < 16:
            raise ContainerFault('code signature command is too small')
        seal_dataoff, seal_datasize = seal_struct.unpack_from(seal_e_value + 'II', payload, seal_p + 8)
        if seal_dataoff > seal_sl.span or seal_datasize > seal_sl.span - seal_dataoff:
            raise ContainerFault('code signature data exceeds the declared Mach-O slice')
        seal_sl.seal_code_signature = (seal_dataoff, seal_datasize)
    elif seal_cmd in (SEAL_LC_ENCRYPTION_INFO, SEAL_LC_ENCRYPTION_INFO_64):
        if seal_cmdsize >= 20:
            seal_cryptoff, seal_cryptsize, seal_cryptid = seal_struct.unpack_from(seal_e_value + 'III', payload, seal_p + 8)
            seal_sl.seal_encryption = {'cryptoff': seal_cryptoff, 'cryptsize': seal_cryptsize, 'cryptid': seal_cryptid}
    elif seal_cmd == SEAL_LC_BUILD_VERSION:
        if seal_cmdsize >= 24:
            seal_platform, seal_minos, seal_sdk, seal_n = seal_struct.unpack_from(seal_e_value + 'IIII', payload, seal_p + 8)
            seal_sl.seal_build = {'platform': seal_platform, 'minos': seal_ver(seal_minos), 'sdk': seal_ver(seal_sdk)}

def seal_ver(seal_v: int) -> str:
    return '%d.%d.%d' % (seal_v >> 16 & 65535, seal_v >> 8 & 255, seal_v & 255)

def read_images(payload: bytes) -> seal_List[ImageView]:
    """Parse a Mach-O or fat buffer into one Slice per architecture."""
    if len(payload) < 8:
        raise ContainerFault('file is too small to be a Mach-O (%d bytes)' % len(payload))
    seal_magic_be = seal_struct.unpack_from('>I', payload, 0)[0]
    if seal_magic_be in (SEAL_FAT_MAGIC, SEAL_FAT_MAGIC_64):
        seal_wide = seal_magic_be == SEAL_FAT_MAGIC_64
        seal_nfat = seal_struct.unpack_from('>I', payload, 4)[0]
        if seal_nfat > 64:
            raise ContainerFault('implausible nfat_arch=%d' % seal_nfat)
        seal_step = 32 if seal_wide else 20
        seal_need(payload, 8, seal_nfat * seal_step, 'fat arch table')
        output: seal_List[ImageView] = []
        for seal_i in range(seal_nfat):
            seal_o_value = 8 + seal_i * seal_step
            if seal_wide:
                seal_ct, seal_cs, seal_soff, seal_ssize, seal_al = seal_struct.unpack_from('>iiQQQ', payload, seal_o_value)
            else:
                seal_ct, seal_cs, seal_soff, seal_ssize, seal_al = seal_struct.unpack_from('>iiIII', payload, seal_o_value)
            seal_need(payload, seal_soff, seal_ssize, 'fat slice %d' % seal_i)
            output.append(seal_parse_slice(payload, seal_soff, seal_ssize))
        if not output:
            raise ContainerFault('fat file declares no architectures')
        return output
    return [seal_parse_slice(payload, 0, len(payload))]

def read_container(location_path: str) -> seal_Tuple[bytes, seal_List[ImageView]]:
    """Read ``path`` and parse it; returns the buffer alongside the slices."""
    with open(location_path, 'rb') as stream:
        payload = stream.read()
    return (payload, read_images(payload))
