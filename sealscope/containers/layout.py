from __future__ import annotations as seal_annotations
import struct as seal_struct
from dataclasses import dataclass as seal_dataclass, field as seal_field
from typing import Dict as seal_Dict, Iterator as seal_Iterator, List as seal_List, Optional as seal_Optional, Tuple as seal_Tuple
'Mach-O container parsing: fat archives, headers, load commands.\n\nStructure only — no code is disassembled and nothing is executed. Every read is\nbounds-checked against the buffer, because this parser is pointed at files that may\nbe malformed or hostile; a truncated or lying offset raises :class:`MachOError`\nrather than reading out of bounds or hanging.\n\nReferences: ``<mach-o/loader.h>`` and ``<mach-o/fat.h>``.\n'
SEAL_FAT_MAGIC, SEAL_FAT_MAGIC_64 = (3405691582, 3405691583)
SEAL_MH_MAGIC_64, SEAL_MH_CIGAM_64 = (4277009103, 3489328638)
SEAL_MH_MAGIC, SEAL_MH_CIGAM = (4277009102, 3472551422)
SEAL_LC_REQ_DYLD = 2147483648
SEAL_LC_SEGMENT = 1
SEAL_LC_SEGMENT_64 = 25
SEAL_LC_LOAD_DYLIB = 12
SEAL_LC_LOAD_WEAK_DYLIB = 24 | SEAL_LC_REQ_DYLD
SEAL_LC_REEXPORT_DYLIB = 31 | SEAL_LC_REQ_DYLD
SEAL_LC_ID_DYLIB = 13
SEAL_LC_RPATH = 28 | SEAL_LC_REQ_DYLD
SEAL_LC_CODE_SIGNATURE = 29
SEAL_LC_ENCRYPTION_INFO = 33
SEAL_LC_ENCRYPTION_INFO_64 = 44
SEAL_LC_BUILD_VERSION = 50
SEAL_LC_VERSION_MIN_MACOSX = 36
SEAL_LC_VERSION_MIN_IPHONEOS = 37
SEAL_LC_MAIN = 40 | SEAL_LC_REQ_DYLD
SEAL_LC_NAMES = {SEAL_LC_SEGMENT: 'LC_SEGMENT', SEAL_LC_SEGMENT_64: 'LC_SEGMENT_64', SEAL_LC_LOAD_DYLIB: 'LC_LOAD_DYLIB', SEAL_LC_LOAD_WEAK_DYLIB: 'LC_LOAD_WEAK_DYLIB', SEAL_LC_REEXPORT_DYLIB: 'LC_REEXPORT_DYLIB', SEAL_LC_ID_DYLIB: 'LC_ID_DYLIB', SEAL_LC_RPATH: 'LC_RPATH', SEAL_LC_CODE_SIGNATURE: 'LC_CODE_SIGNATURE', SEAL_LC_ENCRYPTION_INFO: 'LC_ENCRYPTION_INFO', SEAL_LC_ENCRYPTION_INFO_64: 'LC_ENCRYPTION_INFO_64', SEAL_LC_BUILD_VERSION: 'LC_BUILD_VERSION', SEAL_LC_MAIN: 'LC_MAIN', SEAL_LC_VERSION_MIN_MACOSX: 'LC_VERSION_MIN_MACOSX', SEAL_LC_VERSION_MIN_IPHONEOS: 'LC_VERSION_MIN_IPHONEOS'}
SEAL_CPU_TYPE_X86_64 = 16777223
SEAL_CPU_TYPE_ARM64 = 16777228
SEAL_CPU_TYPE_ARM = 12
SEAL_CPU_TYPE_X86 = 7
SEAL_CPU_NAMES = {SEAL_CPU_TYPE_X86: 'i386', SEAL_CPU_TYPE_X86_64: 'x86_64', SEAL_CPU_TYPE_ARM: 'arm', SEAL_CPU_TYPE_ARM64: 'arm64'}
SEAL_CPU_SUBTYPE_MASK = 16777215
SEAL_ARM64_SUBTYPES = {0: 'arm64', 1: 'arm64v8', 2: 'arm64e'}
SEAL_X86_64_SUBTYPES = {3: 'x86_64', 8: 'x86_64h'}
SEAL_MH_EXECUTE, SEAL_MH_DYLIB, SEAL_MH_BUNDLE = (2, 6, 8)
SEAL_FILETYPE_NAMES = {1: 'object', SEAL_MH_EXECUTE: 'execute', 3: 'fvmlib', 4: 'core', 5: 'preload', SEAL_MH_DYLIB: 'dylib', 7: 'dylinker', SEAL_MH_BUNDLE: 'bundle', 9: 'dylib_stub', 10: 'dsym', 11: 'kext_bundle', 12: 'fileset'}
SEAL_MH_PIE = 2097152
SEAL_MH_ALLOW_STACK_EXECUTION = 131072
SEAL_MH_NO_HEAP_EXECUTION = 16777216
SEAL_MH_ROOT_SAFE = 262144
SEAL_MH_SETUID_SAFE = 524288
SEAL_MH_FLAGS = {1: 'MH_NOUNDEFS', 4: 'MH_DYLDLINK', 8: 'MH_BINDATLOAD', 128: 'MH_TWOLEVEL', SEAL_MH_ALLOW_STACK_EXECUTION: 'MH_ALLOW_STACK_EXECUTION', SEAL_MH_ROOT_SAFE: 'MH_ROOT_SAFE', SEAL_MH_SETUID_SAFE: 'MH_SETUID_SAFE', 1048576: 'MH_WEAK_DEFINES', SEAL_MH_PIE: 'MH_PIE', SEAL_MH_NO_HEAP_EXECUTION: 'MH_NO_HEAP_EXECUTION', 8388608: 'MH_HAS_TLV_DESCRIPTORS', 33554432: 'MH_APP_EXTENSION_SAFE'}

class ContainerFault(ValueError):
    """The file is not a Mach-O we can parse, or its structures are inconsistent."""

@seal_dataclass
class CommandRecord:
    seal_cmd: int
    seal_cmdsize: int
    seal_offset: int
    label: str

    @property
    def seal_is_known(record) -> bool:
        return record.seal_cmd in SEAL_LC_NAMES

@seal_dataclass
class RegionRecord:
    label: str
    seal_vmaddr: int
    seal_vmsize: int
    seal_fileoff: int
    seal_filesize: int
    seal_maxprot: int
    seal_initprot: int
    seal_nsects: int

    @property
    def seal_is_executable(record) -> bool:
        return bool(record.seal_initprot & 4)

    @property
    def seal_is_writable(record) -> bool:
        return bool(record.seal_initprot & 2)

@seal_dataclass
class ImageView:
    """One Mach-O image: a whole thin file, or one architecture of a fat file."""
    seal_offset: int
    span: int
    seal_cputype: int
    seal_cpusubtype: int
    seal_filetype: int
    seal_ncmds: int
    seal_flags: int
    seal_is64: bool
    seal_endian: str
    seal_commands: seal_List[CommandRecord] = seal_field(default_factory=list)
    seal_segments: seal_List[RegionRecord] = seal_field(default_factory=list)
    seal_dylibs: seal_List[seal_Tuple[str, str]] = seal_field(default_factory=list)
    seal_rpaths: seal_List[str] = seal_field(default_factory=list)
    seal_code_signature: seal_Optional[seal_Tuple[int, int]] = None
    seal_encryption: seal_Optional[seal_Dict[str, int]] = None
    seal_build: seal_Optional[seal_Dict[str, object]] = None

    @property
    def seal_arch(record) -> str:
        seal_base = SEAL_CPU_NAMES.get(record.seal_cputype, 'cputype-%d' % record.seal_cputype)
        seal_sub = record.seal_cpusubtype & SEAL_CPU_SUBTYPE_MASK
        if record.seal_cputype == SEAL_CPU_TYPE_ARM64:
            return SEAL_ARM64_SUBTYPES.get(seal_sub, seal_base)
        if record.seal_cputype == SEAL_CPU_TYPE_X86_64:
            return SEAL_X86_64_SUBTYPES.get(seal_sub, seal_base)
        return seal_base

    @property
    def seal_filetype_name(record) -> str:
        return SEAL_FILETYPE_NAMES.get(record.seal_filetype, 'filetype-%d' % record.seal_filetype)

    @property
    def seal_flag_names(record) -> seal_List[str]:
        return [seal_n_value for seal_bit, seal_n_value in sorted(SEAL_MH_FLAGS.items()) if record.seal_flags & seal_bit]

    def seal_has_flag(record, seal_bit: int) -> bool:
        return bool(record.seal_flags & seal_bit)

    def seal_segment(record, label: str) -> seal_Optional[RegionRecord]:
        for seal_s_value in record.seal_segments:
            if seal_s_value.label == label:
                return seal_s_value
        return None
__all__ = ['SEAL_LC_REQ_DYLD', 'SEAL_LC_SEGMENT', 'SEAL_LC_SEGMENT_64', 'SEAL_LC_LOAD_DYLIB', 'SEAL_LC_LOAD_WEAK_DYLIB', 'SEAL_LC_REEXPORT_DYLIB', 'SEAL_LC_ID_DYLIB', 'SEAL_LC_RPATH', 'SEAL_LC_CODE_SIGNATURE', 'SEAL_LC_ENCRYPTION_INFO', 'SEAL_LC_ENCRYPTION_INFO_64', 'SEAL_LC_BUILD_VERSION', 'SEAL_LC_VERSION_MIN_MACOSX', 'SEAL_LC_VERSION_MIN_IPHONEOS', 'SEAL_LC_MAIN', 'SEAL_LC_NAMES', 'SEAL_CPU_TYPE_X86_64', 'SEAL_CPU_TYPE_ARM64', 'SEAL_CPU_TYPE_ARM', 'SEAL_CPU_TYPE_X86', 'SEAL_CPU_NAMES', 'SEAL_CPU_SUBTYPE_MASK', 'SEAL_ARM64_SUBTYPES', 'SEAL_X86_64_SUBTYPES', 'SEAL_FILETYPE_NAMES', 'SEAL_MH_PIE', 'SEAL_MH_ALLOW_STACK_EXECUTION', 'SEAL_MH_NO_HEAP_EXECUTION', 'SEAL_MH_ROOT_SAFE', 'SEAL_MH_SETUID_SAFE', 'SEAL_MH_FLAGS', 'ContainerFault', 'CommandRecord', 'RegionRecord', 'ImageView']

__all__ = [export_name for export_name in globals() if export_name.startswith('SEAL_') or export_name in ('ImageView', 'RegionRecord', 'CommandRecord', 'ContainerFault')]
