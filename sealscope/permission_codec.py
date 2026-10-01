"""Entitlement decoding, from both the XML plist slot and the DER slot.

macOS binaries carry entitlements twice: slot 5 holds the classic XML plist and
slot 7 holds a DER encoding of the same thing. Modern kernels prefer the DER form,
so a tool that only reads the XML can be shown one set of entitlements while the
system enforces another. This module decodes both and
:func:`seal_compare` reports any disagreement — which is itself a finding.

The DER decoder here is a minimal, bounds-checked reader for the shape Apple emits
(``SEQUENCE { INTEGER version, SET OF SEQUENCE { UTF8String key, value } }``). It
is not a general ASN.1 implementation and refuses what it does not recognise
instead of guessing.
"""
from __future__ import annotations as seal_annotations
import plistlib as seal_plistlib
from typing import Any as seal_Any, Dict as seal_Dict, List as seal_List, Optional as seal_Optional, Tuple as seal_Tuple
__all__ = ['PermissionEncodingFault', 'seal_parse_plist', 'seal_parse_der', 'seal_compare', 'seal_flatten_keys']

class PermissionEncodingFault(ValueError):
    """The DER entitlements blob is truncated or uses a construct we do not model."""
SEAL_TAG_BOOLEAN = 1
SEAL_TAG_INTEGER = 2
SEAL_TAG_UTF8STRING = 12
SEAL_TAG_SEQUENCE = 48
SEAL_TAG_SET = 49
SEAL_TAG_APPLICATION_16 = 112
SEAL_TAG_CONTEXT_16 = 176
SEAL_OUTER_TAGS = (SEAL_TAG_APPLICATION_16, SEAL_TAG_SEQUENCE)
SEAL_DICT_TAGS = (SEAL_TAG_CONTEXT_16,)
SEAL_ARRAY_TAGS = (SEAL_TAG_SEQUENCE, SEAL_TAG_SET)

def seal_parse_plist(content: bytes) -> seal_Dict[str, seal_Any]:
    """Decode the XML plist entitlements blob (slot 5)."""
    if not content:
        return {}
    seal_body = content.split(b'\x00', 1)[0] if content.endswith(b'\x00') else content
    try:
        output = seal_plistlib.loads(seal_body.strip())
    except Exception as seal_exc:
        raise ValueError('entitlements plist did not parse: %s' % seal_exc) from seal_exc
    if not isinstance(output, dict):
        raise ValueError('entitlements plist is a %s, expected a dict' % type(output).__name__)
    return output

def seal_read_tlv(payload: bytes, seal_p: int, seal_end: int) -> seal_Tuple[int, int, int, int]:
    """Read one tag-length-value header. Returns (tag, body_start, body_end, next)."""
    if seal_p + 2 > seal_end:
        raise PermissionEncodingFault('truncated DER header at %d' % seal_p)
    seal_tag = payload[seal_p]
    seal_n_value = payload[seal_p + 1]
    seal_p += 2
    if seal_n_value & 128:
        seal_count = seal_n_value & 127
        if seal_count == 0 or seal_count > 4:
            raise PermissionEncodingFault('unsupported DER length form 0x%02x at %d' % (seal_n_value, seal_p - 1))
        if seal_p + seal_count > seal_end:
            raise PermissionEncodingFault('truncated DER length at %d' % seal_p)
        seal_length = int.from_bytes(payload[seal_p:seal_p + seal_count], 'big')
        seal_p += seal_count
    else:
        seal_length = seal_n_value
    if seal_p + seal_length > seal_end:
        raise PermissionEncodingFault('DER value at %d runs past the blob' % seal_p)
    return (seal_tag, seal_p, seal_p + seal_length, seal_p + seal_length)

def seal_read_value(payload: bytes, seal_p: int, seal_end: int, seal_depth: int=0) -> seal_Any:
    if seal_depth > 16:
        raise PermissionEncodingFault('DER nesting deeper than 16 levels')
    seal_tag, seal_bs, seal_be, seal_nx = seal_read_tlv(payload, seal_p, seal_end)
    if seal_tag == SEAL_TAG_BOOLEAN:
        if seal_be - seal_bs != 1:
            raise PermissionEncodingFault('BOOLEAN with %d body bytes' % (seal_be - seal_bs))
        return payload[seal_bs] != 0
    if seal_tag == SEAL_TAG_INTEGER:
        return int.from_bytes(payload[seal_bs:seal_be], 'big', signed=True)
    if seal_tag == SEAL_TAG_UTF8STRING:
        return payload[seal_bs:seal_be].decode('utf-8', 'replace')
    if seal_tag in SEAL_ARRAY_TAGS:
        seal_items: seal_List[seal_Any] = []
        seal_q = seal_bs
        while seal_q < seal_be:
            seal_items.append(seal_read_value(payload, seal_q, seal_be, seal_depth + 1))
            seal_t, seal_s, seal_e, seal_q = seal_read_tlv(payload, seal_q, seal_be)
        return seal_items
    if seal_tag in SEAL_DICT_TAGS:
        return seal_read_dict(payload, seal_bs, seal_be, seal_depth + 1)
    raise PermissionEncodingFault('unsupported DER tag 0x%02x at %d' % (seal_tag, seal_p))

def seal_read_dict(payload: bytes, seal_start: int, seal_end: int, seal_depth: int=0) -> seal_Dict[str, seal_Any]:
    """Read a dictionary body: a run of ``SEQUENCE { UTF8String key, value }``."""
    if seal_depth > 16:
        raise PermissionEncodingFault('DER nesting deeper than 16 levels')
    output: seal_Dict[str, seal_Any] = {}
    seal_q = seal_start
    while seal_q < seal_end:
        seal_key, seal_value, seal_q = seal_read_element(payload, seal_q, seal_end, seal_depth)
        output[seal_key] = seal_value
    return output

def seal_read_element(payload: bytes, seal_p: int, seal_end: int, seal_depth: int=0) -> seal_Tuple[str, seal_Any, int]:
    """Read one ``SEQUENCE { UTF8String key, value }``; returns (key, value, next)."""
    seal_tag, seal_bs, seal_be, seal_nx_value = seal_read_tlv(payload, seal_p, seal_end)
    if seal_tag != SEAL_TAG_SEQUENCE:
        raise PermissionEncodingFault('expected a key/value SEQUENCE, got tag 0x%02x at %d' % (seal_tag, seal_p))
    seal_ktag, seal_kbs, seal_kbe, seal_kn = seal_read_tlv(payload, seal_bs, seal_be)
    if seal_ktag != SEAL_TAG_UTF8STRING:
        raise PermissionEncodingFault('entitlement key is tag 0x%02x, expected UTF8String' % seal_ktag)
    seal_key = payload[seal_kbs:seal_kbe].decode('utf-8', 'replace')
    seal_value = seal_read_value(payload, seal_kn, seal_be, seal_depth + 1) if seal_kn < seal_be else None
    return (seal_key, seal_value, seal_nx_value)

def seal_parse_der(content: bytes) -> seal_Dict[str, seal_Any]:
    """Decode the DER entitlements blob (slot 7)."""
    if not content:
        return {}
    seal_end = len(content)
    seal_tag, seal_bs, seal_be, seal_nx = seal_read_tlv(content, 0, seal_end)
    if seal_tag not in SEAL_OUTER_TAGS:
        raise PermissionEncodingFault('DER entitlements start with tag 0x%02x, expected one of %s' % (seal_tag, ', '.join(('0x%02x' % seal_t_value for seal_t_value in SEAL_OUTER_TAGS))))
    seal_p = seal_bs
    seal_vtag, seal_vbs, seal_vbe, seal_p = seal_read_tlv(content, seal_p, seal_be)
    if seal_vtag != SEAL_TAG_INTEGER:
        raise PermissionEncodingFault('DER entitlements have no version INTEGER')
    seal_version = int.from_bytes(content[seal_vbs:seal_vbe], 'big')
    if seal_version != 1:
        raise PermissionEncodingFault('unsupported DER entitlements version %d' % seal_version)
    seal_stag, seal_sbs, seal_sbe, _ = seal_read_tlv(content, seal_p, seal_be)
    if seal_stag not in SEAL_DICT_TAGS:
        raise PermissionEncodingFault('DER entitlements container is tag 0x%02x, expected one of %s' % (seal_stag, ', '.join(('0x%02x' % seal_t_value for seal_t_value in SEAL_DICT_TAGS))))
    return seal_read_dict(content, seal_sbs, seal_sbe)

def seal_compare(seal_xml: seal_Optional[seal_Dict[str, seal_Any]], seal_der: seal_Optional[seal_Dict[str, seal_Any]]) -> seal_List[str]:
    """Describe how the XML and DER entitlement sets disagree; empty when they match.

    A disagreement matters: the kernel prefers the DER form, so anything present
    only in the XML is something a plist-only reader would show you but the system
    would not grant — and anything only in the DER is a grant the plist hides.
    """
    if seal_xml is None or seal_der is None:
        return []
    seal_diffs: seal_List[str] = []
    for seal_k_value in sorted(set(seal_xml) - set(seal_der)):
        seal_diffs.append('only in the XML slot: %s' % seal_k_value)
    for seal_k_value in sorted(set(seal_der) - set(seal_xml)):
        seal_diffs.append('only in the DER slot: %s' % seal_k_value)
    for seal_k_value in sorted(set(seal_xml) & set(seal_der)):
        if seal_xml[seal_k_value] != seal_der[seal_k_value]:
            seal_diffs.append('value differs for %s: XML=%r DER=%r' % (seal_k_value, seal_xml[seal_k_value], seal_der[seal_k_value]))
    return seal_diffs

def seal_flatten_keys(seal_ents: seal_Dict[str, seal_Any]) -> seal_List[str]:
    """Entitlement keys in sorted order, for stable reporting."""
    return sorted(seal_ents)
