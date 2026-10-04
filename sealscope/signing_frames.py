"""Embedded code-signature blobs: the SuperBlob, the CodeDirectory and its slots.

Everything here is big-endian, unlike the Mach-O structures around it. The
CodeDirectory grows by version, so each field is read only when the version
declares it — a v20100 directory has no team id, and reading one would be reading
whatever follows.

What this module does **not** do: it does not verify the CMS signature, walk the
certificate chain, or check that the code hashes match the pages they cover. It
reports what the signature *claims*. Use ``codesign -v`` for cryptographic
verification; see the README for why both are useful.

Reference: ``<Security/CSCommon.seal_h>`` and the ``codesign`` sources.
"""
from __future__ import annotations as seal_annotations
import hashlib as seal_hashlib
import struct as seal_struct
from dataclasses import dataclass as seal_dataclass, field as seal_field
from typing import Dict as seal_Dict, List as seal_List, Optional as seal_Optional
__all__ = ['EnvelopeFault', 'EnvelopeRecord', 'DigestDirectory', 'SigningEnvelope', 'read_envelope', 'SEAL_CS_FLAGS', 'SEAL_EXECSEG_FLAGS', 'SEAL_HASH_TYPES', 'SEAL_SLOT_NAMES', 'seal_digest_name']
SEAL_CSMAGIC_EMBEDDED_SIGNATURE = 4208856256
SEAL_CSMAGIC_EMBEDDED_SIGNATURE_OLD = 4208855810
SEAL_CSMAGIC_CODEDIRECTORY = 4208856066
SEAL_CSMAGIC_REQUIREMENTS = 4208856065
SEAL_CSMAGIC_REQUIREMENT = 4208856064
SEAL_CSMAGIC_EMBEDDED_ENTITLEMENTS = 4208882033
SEAL_CSMAGIC_EMBEDDED_DER_ENTITLEMENTS = 4208882034
SEAL_CSMAGIC_BLOBWRAPPER = 4208855809
SEAL_BLOB_NAMES = {SEAL_CSMAGIC_EMBEDDED_SIGNATURE: 'EmbeddedSignature', SEAL_CSMAGIC_EMBEDDED_SIGNATURE_OLD: 'EmbeddedSignatureOld', SEAL_CSMAGIC_CODEDIRECTORY: 'CodeDirectory', SEAL_CSMAGIC_REQUIREMENTS: 'Requirements', SEAL_CSMAGIC_REQUIREMENT: 'Requirement', SEAL_CSMAGIC_EMBEDDED_ENTITLEMENTS: 'Entitlements', SEAL_CSMAGIC_EMBEDDED_DER_ENTITLEMENTS: 'DEREntitlements', SEAL_CSMAGIC_BLOBWRAPPER: 'BlobWrapper'}
SEAL_CSSLOT_CODEDIRECTORY = 0
SEAL_CSSLOT_INFOSLOT = 1
SEAL_CSSLOT_REQUIREMENTS = 2
SEAL_CSSLOT_RESOURCEDIR = 3
SEAL_CSSLOT_APPLICATION = 4
SEAL_CSSLOT_ENTITLEMENTS = 5
SEAL_CSSLOT_DER_ENTITLEMENTS = 7
SEAL_CSSLOT_ALTERNATE_CODEDIRECTORIES = 4096
SEAL_CSSLOT_SIGNATURESLOT = 65536
SEAL_SLOT_NAMES = {SEAL_CSSLOT_CODEDIRECTORY: 'CodeDirectory', SEAL_CSSLOT_INFOSLOT: 'Info.plist', SEAL_CSSLOT_REQUIREMENTS: 'Requirements', SEAL_CSSLOT_RESOURCEDIR: 'ResourceDir', SEAL_CSSLOT_APPLICATION: 'Application', SEAL_CSSLOT_ENTITLEMENTS: 'Entitlements', 6: 'Reserved6', SEAL_CSSLOT_DER_ENTITLEMENTS: 'DEREntitlements', 8: 'LaunchConstraintSelf', 9: 'LaunchConstraintParent', 10: 'LaunchConstraintResponsible', 11: 'LibraryConstraint', SEAL_CSSLOT_SIGNATURESLOT: 'CMSSignature', 65537: 'Identification', 65538: 'Ticket'}
SEAL_CS_VALID = 1
SEAL_CS_ADHOC = 2
SEAL_CS_GET_TASK_ALLOW = 4
SEAL_CS_INSTALLER = 8
SEAL_CS_FORCED_LV = 16
SEAL_CS_INVALID_ALLOWED = 32
SEAL_CS_HARD = 256
SEAL_CS_KILL = 512
SEAL_CS_CHECK_EXPIRATION = 1024
SEAL_CS_RESTRICT = 2048
SEAL_CS_ENFORCEMENT = 4096
SEAL_CS_REQUIRE_LV = 8192
SEAL_CS_ENTITLEMENTS_VALIDATED = 16384
SEAL_CS_NVRAM_UNRESTRICTED = 32768
SEAL_CS_RUNTIME = 65536
SEAL_CS_LINKER_SIGNED = 131072
SEAL_CS_FLAGS = {SEAL_CS_VALID: 'CS_VALID', SEAL_CS_ADHOC: 'CS_ADHOC', SEAL_CS_GET_TASK_ALLOW: 'CS_GET_TASK_ALLOW', SEAL_CS_INSTALLER: 'CS_INSTALLER', SEAL_CS_FORCED_LV: 'CS_FORCED_LV', SEAL_CS_INVALID_ALLOWED: 'CS_INVALID_ALLOWED', SEAL_CS_HARD: 'CS_HARD', SEAL_CS_KILL: 'CS_KILL', SEAL_CS_CHECK_EXPIRATION: 'CS_CHECK_EXPIRATION', SEAL_CS_RESTRICT: 'CS_RESTRICT', SEAL_CS_ENFORCEMENT: 'CS_ENFORCEMENT', SEAL_CS_REQUIRE_LV: 'CS_REQUIRE_LV', SEAL_CS_ENTITLEMENTS_VALIDATED: 'CS_ENTITLEMENTS_VALIDATED', SEAL_CS_NVRAM_UNRESTRICTED: 'CS_NVRAM_UNRESTRICTED', SEAL_CS_RUNTIME: 'CS_RUNTIME', SEAL_CS_LINKER_SIGNED: 'CS_LINKER_SIGNED'}
SEAL_CS_EXECSEG_MAIN_BINARY = 1
SEAL_CS_EXECSEG_ALLOW_UNSIGNED = 16
SEAL_CS_EXECSEG_DEBUGGER = 32
SEAL_CS_EXECSEG_JIT = 64
SEAL_CS_EXECSEG_SKIP_LV = 128
SEAL_CS_EXECSEG_CAN_LOAD_CDHASH = 256
SEAL_CS_EXECSEG_CAN_EXEC_CDHASH = 512
SEAL_EXECSEG_FLAGS = {SEAL_CS_EXECSEG_MAIN_BINARY: 'CS_EXECSEG_MAIN_BINARY', SEAL_CS_EXECSEG_ALLOW_UNSIGNED: 'CS_EXECSEG_ALLOW_UNSIGNED', SEAL_CS_EXECSEG_DEBUGGER: 'CS_EXECSEG_DEBUGGER', SEAL_CS_EXECSEG_JIT: 'CS_EXECSEG_JIT', SEAL_CS_EXECSEG_SKIP_LV: 'CS_EXECSEG_SKIP_LV', SEAL_CS_EXECSEG_CAN_LOAD_CDHASH: 'CS_EXECSEG_CAN_LOAD_CDHASH', SEAL_CS_EXECSEG_CAN_EXEC_CDHASH: 'CS_EXECSEG_CAN_EXEC_CDHASH'}
SEAL_HASH_TYPES = {0: 'none', 1: 'sha1', 2: 'sha256', 3: 'sha256-truncated', 4: 'sha384', 5: 'sha512'}
SEAL__HASHLIB = {1: 'sha1', 2: 'sha256', 3: 'sha256', 4: 'sha384', 5: 'sha512'}

def seal_digest_name(seal_hash_type: int) -> seal_Optional[str]:
    """The hashlib name for a CodeDirectory hash type, or ``None`` if unmapped.

    Hash type 3 is a truncated SHA-256, so it hashes as SHA-256 and only the
    printed digest is short.
    """
    return SEAL__HASHLIB.get(seal_hash_type)

class EnvelopeFault(ValueError):
    """The code signature is absent, truncated or structurally inconsistent."""

def seal_need(payload: bytes, cursor: int, span: int, seal_what: str) -> None:
    if cursor < 0 or span < 0 or cursor + span > len(payload):
        raise EnvelopeFault('%s needs bytes [0x%x, 0x%x) but the buffer is 0x%x long' % (seal_what, cursor, cursor + span, len(payload)))

@seal_dataclass
class EnvelopeRecord:
    seal_slot: int
    seal_slot_name: str
    seal_offset: int
    seal_magic: int
    seal_length: int
    content: bytes

    @property
    def seal_magic_name(record) -> str:
        return SEAL_BLOB_NAMES.get(record.seal_magic, '0x%08x' % record.seal_magic)

@seal_dataclass
class DigestDirectory:
    seal_version: int
    seal_flags: int
    seal_identifier: str
    seal_team_id: seal_Optional[str]
    seal_hash_type: int
    seal_hash_size: int
    seal_page_size: int
    seal_code_limit: int
    seal_n_code_slots: int
    seal_n_special_slots: int
    seal_platform: int
    seal_exec_seg_base: int = 0
    seal_exec_seg_limit: int = 0
    seal_exec_seg_flags: int = 0
    seal_cdhash: seal_Optional[str] = None
    seal_special_hashes: seal_Dict[int, str] = seal_field(default_factory=dict)
    seal_raw_length: int = 0

    @property
    def seal_hash_name(record) -> str:
        return SEAL_HASH_TYPES.get(record.seal_hash_type, 'hashtype-%d' % record.seal_hash_type)

    @property
    def seal_cdhash_truncated(record) -> seal_Optional[str]:
        """The 20-byte form the kernel and ``codesign`` print as the CDHash."""
        return record.seal_cdhash[:40] if record.seal_cdhash else None

    @property
    def seal_flag_names(record) -> seal_List[str]:
        return [seal_n_value for seal_bit, seal_n_value in sorted(SEAL_CS_FLAGS.items()) if record.seal_flags & seal_bit]

    @property
    def seal_exec_seg_flag_names(record) -> seal_List[str]:
        return [seal_n_value for seal_bit, seal_n_value in sorted(SEAL_EXECSEG_FLAGS.items()) if record.seal_exec_seg_flags & seal_bit]

    def seal_has_flag(record, seal_bit: int) -> bool:
        return bool(record.seal_flags & seal_bit)

    def seal_has_exec_seg_flag(record, seal_bit: int) -> bool:
        return bool(record.seal_exec_seg_flags & seal_bit)

    @property
    def seal_is_adhoc(record) -> bool:
        return record.seal_has_flag(SEAL_CS_ADHOC)

    @property
    def seal_hardened_runtime(record) -> bool:
        return record.seal_has_flag(SEAL_CS_RUNTIME)

@seal_dataclass
class SigningEnvelope:
    seal_offset: int
    seal_length: int
    signing_frames: seal_List[EnvelopeRecord] = seal_field(default_factory=list)
    seal_code_directory: seal_Optional[DigestDirectory] = None
    seal_alternates: seal_List[DigestDirectory] = seal_field(default_factory=list)
    seal_entitlements_xml: seal_Optional[bytes] = None
    seal_entitlements_der: seal_Optional[bytes] = None
    seal_cms_length: int = 0

    def seal_blob(record, seal_slot: int) -> seal_Optional[EnvelopeRecord]:
        for seal_b in record.signing_frames:
            if seal_b.seal_slot == seal_slot:
                return seal_b
        return None

    @property
    def seal_has_cms(record) -> bool:
        return record.seal_cms_length > 0

    @property
    def seal_best_hash_type(record) -> int:
        """The strongest hash across the primary and alternate directories.

        macOS picks the strongest it supports, so a SHA-1 primary is harmless when a
        SHA-256 alternate is present — and dangerous when it is the only one.
        """
        seal_types = [seal_cd.seal_hash_type for seal_cd in record.seal_all_directories]
        return max(seal_types) if seal_types else 0

    @property
    def seal_all_directories(record) -> seal_List[DigestDirectory]:
        seal_cds = [record.seal_code_directory] if record.seal_code_directory else []
        return seal_cds + list(record.seal_alternates)

def seal_parse_code_directory(payload: bytes, cursor: int, seal_length: int) -> DigestDirectory:
    if seal_length < 44:
        raise EnvelopeFault('CodeDirectory is shorter than its fixed header')
    seal_need(payload, cursor, seal_length, 'CodeDirectory')
    seal_need(payload, cursor, 44, 'CodeDirectory fixed header')
    seal_version, seal_flags, seal_hash_off, seal_ident_off, seal_n_special, seal_n_code, seal_code_limit, seal_hash_size, seal_hash_type, seal_platform, seal_page_shift, seal_spare2 = seal_struct.unpack_from('>IIIIIIIBBBBI', payload, cursor + 8)
    seal_end = cursor + seal_length
    seal_tail_size = ((4 if seal_version >= 0x20100 else 0)
                      + (4 if seal_version >= 0x20200 else 0)
                      + (12 if seal_version >= 0x20300 else 0)
                      + (24 if seal_version >= 0x20400 else 0)
                      + (8 if seal_version >= 0x20500 else 0)
                      + (12 if seal_version >= 0x20600 else 0))
    seal_header_end = 44 + seal_tail_size
    if seal_length < seal_header_end:
        raise EnvelopeFault('CodeDirectory is shorter than its declared version header')
    if seal_hash_off > seal_length:
        raise EnvelopeFault('CodeDirectory hash offset is outside its declared length')
    if seal_n_special or seal_n_code:
        if not seal_hash_size or not seal_hash_off:
            raise EnvelopeFault('CodeDirectory declares hash slots without a hash table')
        if seal_n_special > seal_hash_off // seal_hash_size or seal_n_code > (seal_length - seal_hash_off) // seal_hash_size:
            raise EnvelopeFault('CodeDirectory hash slots exceed its declared length')
        if seal_hash_off - seal_n_special * seal_hash_size < seal_header_end:
            raise EnvelopeFault('CodeDirectory hash slots overlap its version header')
    seal_ident = ''
    if seal_ident_off:
        if seal_ident_off < seal_header_end or seal_ident_off >= seal_length:
            raise EnvelopeFault('CodeDirectory identifier offset is outside its data area')
        seal_z = payload.find(b'\x00', cursor + seal_ident_off, seal_end)
        if seal_z < 0:
            raise EnvelopeFault('CodeDirectory identifier is not terminated inside its declared length')
        seal_ident = payload[cursor + seal_ident_off:seal_z].decode('utf-8', 'replace')
    seal_cd = DigestDirectory(seal_version=seal_version, seal_flags=seal_flags, seal_identifier=seal_ident, seal_team_id=None, seal_hash_type=seal_hash_type, seal_hash_size=seal_hash_size, seal_page_size=1 << seal_page_shift if seal_page_shift else 0, seal_code_limit=seal_code_limit, seal_n_code_slots=seal_n_code, seal_n_special_slots=seal_n_special, seal_platform=seal_platform, seal_raw_length=seal_length)
    seal_p = cursor + 44
    if seal_version >= 131328 and seal_p + 4 <= seal_end:
        seal_p += 4
    if seal_version >= 131584 and seal_p + 4 <= seal_end:
        seal_team_off = seal_struct.unpack_from('>I', payload, seal_p)[0]
        seal_p += 4
        if seal_team_off:
            if seal_team_off < seal_header_end or seal_team_off >= seal_length:
                raise EnvelopeFault('CodeDirectory team offset is outside its data area')
            seal_z = payload.find(b'\x00', cursor + seal_team_off, seal_end)
            if seal_z < 0:
                raise EnvelopeFault('CodeDirectory team identifier is not terminated inside its declared length')
            seal_cd.seal_team_id = payload[cursor + seal_team_off:seal_z].decode('utf-8', 'replace')
    if seal_version >= 131840 and seal_p + 12 <= seal_end:
        seal_p += 4
        seal_cd.seal_code_limit = seal_struct.unpack_from('>Q', payload, seal_p)[0] or seal_cd.seal_code_limit
        seal_p += 8
    if seal_version >= 132096 and seal_p + 24 <= seal_end:
        seal_cd.seal_exec_seg_base, seal_cd.seal_exec_seg_limit, seal_cd.seal_exec_seg_flags = seal_struct.unpack_from('>QQQ', payload, seal_p)
        seal_p += 24
    seal_algo = SEAL__HASHLIB.get(seal_hash_type)
    if seal_algo:
        seal_digest_value = seal_hashlib.new(seal_algo, payload[cursor:cursor + seal_length]).hexdigest()
        seal_cd.seal_cdhash = seal_digest_value[:40] if seal_hash_type == 3 else seal_digest_value
    if seal_algo and 0 < seal_hash_size <= 64 and seal_hash_off:
        for seal_i in range(1, seal_n_special + 1):
            seal_h = cursor + seal_hash_off - seal_i * seal_hash_size
            if seal_h >= cursor and seal_h + seal_hash_size <= seal_end:
                seal_blk = payload[seal_h:seal_h + seal_hash_size]
                if any(seal_blk):
                    seal_cd.seal_special_hashes[seal_i] = seal_blk.hex()
    return seal_cd

def read_envelope(payload: bytes, cursor: int, span: int) -> SigningEnvelope:
    """Parse the embedded signature SuperBlob at ``off`` (absolute file offset)."""
    seal_need(payload, cursor, span, 'signature extent')
    if span < 12:
        raise EnvelopeFault('signature extent is shorter than a SuperBlob header')
    seal_need(payload, cursor, 12, 'signature SuperBlob header')
    seal_magic, seal_length, seal_count = seal_struct.unpack_from('>III', payload, cursor)
    if seal_magic not in (SEAL_CSMAGIC_EMBEDDED_SIGNATURE, SEAL_CSMAGIC_EMBEDDED_SIGNATURE_OLD):
        raise EnvelopeFault('not an embedded signature (magic 0x%08x)' % seal_magic)
    if seal_count > 64:
        raise EnvelopeFault('implausible blob count %d' % seal_count)
    if seal_length < 12 or seal_length > span:
        raise EnvelopeFault('signature SuperBlob length exceeds its declared extent')
    seal_index_end = 12 + seal_count * 8
    if seal_index_end > seal_length:
        raise EnvelopeFault('signature blob index exceeds the SuperBlob length')
    seal_sig = SigningEnvelope(seal_offset=cursor, seal_length=seal_length)
    for seal_i in range(seal_count):
        seal_ix = cursor + 12 + seal_i * 8
        seal_slot, seal_rel = seal_struct.unpack_from('>II', payload, seal_ix)
        seal_bo = cursor + seal_rel
        if seal_rel < seal_index_end or seal_rel > seal_length - 8:
            raise EnvelopeFault('blob %d header is outside the SuperBlob length' % seal_i)
        seal_bmagic, seal_blen = seal_struct.unpack_from('>II', payload, seal_bo)
        if seal_blen < 8:
            raise EnvelopeFault('blob %d declares length %d' % (seal_i, seal_blen))
        if seal_blen > seal_length - seal_rel:
            raise EnvelopeFault('blob %d body exceeds the SuperBlob length' % seal_i)
        seal_sig.signing_frames.append(EnvelopeRecord(seal_slot=seal_slot, seal_slot_name=SEAL_SLOT_NAMES.get(seal_slot, 'slot-0x%x' % seal_slot), seal_offset=seal_rel, seal_magic=seal_bmagic, seal_length=seal_blen, content=payload[seal_bo + 8:seal_bo + seal_blen]))
        if seal_bmagic == SEAL_CSMAGIC_CODEDIRECTORY:
            seal_cd = seal_parse_code_directory(payload, seal_bo, seal_blen)
            if seal_slot == SEAL_CSSLOT_CODEDIRECTORY:
                seal_sig.seal_code_directory = seal_cd
            else:
                seal_sig.seal_alternates.append(seal_cd)
        elif seal_bmagic == SEAL_CSMAGIC_EMBEDDED_ENTITLEMENTS:
            seal_sig.seal_entitlements_xml = payload[seal_bo + 8:seal_bo + seal_blen]
        elif seal_bmagic == SEAL_CSMAGIC_EMBEDDED_DER_ENTITLEMENTS:
            seal_sig.seal_entitlements_der = payload[seal_bo + 8:seal_bo + seal_blen]
        elif seal_bmagic == SEAL_CSMAGIC_BLOBWRAPPER and seal_slot == SEAL_CSSLOT_SIGNATURESLOT:
            seal_sig.seal_cms_length = seal_blen - 8
    if seal_sig.seal_code_directory is None:
        raise EnvelopeFault('signature has no CodeDirectory in slot 0')
    return seal_sig
