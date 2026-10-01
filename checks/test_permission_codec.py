"""The DER entitlement decoder, including everything it must refuse.

Apple's DER encoding carries the collection kind in the constructed tag:
CONTEXT [16] (0xb0) is a dictionary of key/value SEQUENCEs, and a SEQUENCE (0x30)
in value position is an array. Getting those two the wrong way round still parses
many real binaries, so the nesting cases here are the ones that matter.
"""
import pytest as seal_pytest
from sealscope import permission_codec as seal_ent

def seal_tlv(seal_tag: int, seal_body: bytes) -> bytes:
    if len(seal_body) < 128:
        return bytes([seal_tag, len(seal_body)]) + seal_body
    seal_n_value = (len(seal_body).bit_length() + 7) // 8
    return bytes([seal_tag, 128 | seal_n_value]) + len(seal_body).to_bytes(seal_n_value, 'big') + seal_body

def seal_utf8(seal_s_value: str) -> bytes:
    return seal_tlv(12, seal_s_value.encode('utf-8'))

def seal_boolean(seal_v: bool) -> bytes:
    return seal_tlv(1, b'\xff' if seal_v else b'\x00')

def seal_integer(seal_v: int) -> bytes:
    seal_n_value = max(1, (seal_v.bit_length() + 8) // 8)
    return seal_tlv(2, seal_v.to_bytes(seal_n_value, 'big', signed=True))

def seal_element(seal_key: str, seal_value: bytes) -> bytes:
    return seal_tlv(48, seal_utf8(seal_key) + seal_value)

def seal_array(*seal_values: bytes) -> bytes:
    return seal_tlv(48, b''.join(seal_values))

def seal_dictionary(*seal_elements: bytes) -> bytes:
    return seal_tlv(176, b''.join(seal_elements))

def seal_blob(*seal_elements: bytes) -> bytes:
    return seal_tlv(112, seal_integer(1) + seal_dictionary(*seal_elements))

def test_seal_boolean_values():
    output = seal_ent.seal_parse_der(seal_blob(seal_element('a', seal_boolean(True)), seal_element('b', seal_boolean(False))))
    assert output == {'a': True, 'b': False}

def test_seal_string_and_integer_values():
    output = seal_ent.seal_parse_der(seal_blob(seal_element('name', seal_utf8('hello')), seal_element('count', seal_integer(3))))
    assert output == {'name': 'hello', 'count': 3}

def test_seal_array_value():
    output = seal_ent.seal_parse_der(seal_blob(seal_element('groups', seal_array(seal_utf8('one'), seal_utf8('two')))))
    assert output == {'groups': ['one', 'two']}

def test_seal_empty_array_value():
    assert seal_ent.seal_parse_der(seal_blob(seal_element('groups', seal_array()))) == {'groups': []}

def test_seal_dictionary_value():
    seal_inner = seal_dictionary(seal_element('identifier', seal_utf8('expansion-slot-support')))
    output = seal_ent.seal_parse_der(seal_blob(seal_element('cfg', seal_inner)))
    assert output == {'cfg': {'identifier': 'expansion-slot-support'}}

def test_seal_array_of_dictionaries():
    """The shape /System/Library/CoreServices binaries actually use."""
    seal_item = seal_dictionary(seal_element('identifier', seal_utf8('x')))
    output = seal_ent.seal_parse_der(seal_blob(seal_element('k', seal_array(seal_item))))
    assert output == {'k': [{'identifier': 'x'}]}

def test_seal_long_form_length_is_handled():
    seal_long_value = 'a' * 300
    output = seal_ent.seal_parse_der(seal_blob(seal_element('k', seal_utf8(seal_long_value))))
    assert output == {'k': seal_long_value}

def test_seal_empty_blob_is_an_empty_mapping():
    assert seal_ent.seal_parse_der(b'') == {}

def test_seal_wrong_outer_tag_is_refused():
    with seal_pytest.raises(seal_ent.PermissionEncodingFault):
        seal_ent.seal_parse_der(seal_tlv(49, seal_integer(1)))

def test_seal_missing_version_is_refused():
    with seal_pytest.raises(seal_ent.PermissionEncodingFault):
        seal_ent.seal_parse_der(seal_tlv(112, seal_dictionary()))

def test_seal_unsupported_version_is_refused():
    with seal_pytest.raises(seal_ent.PermissionEncodingFault) as seal_exc:
        seal_ent.seal_parse_der(seal_tlv(112, seal_integer(2) + seal_dictionary()))
    assert 'version' in str(seal_exc.value)

def test_seal_truncated_blob_is_refused():
    seal_good = seal_blob(seal_element('a', seal_boolean(True)))
    with seal_pytest.raises(seal_ent.PermissionEncodingFault):
        seal_ent.seal_parse_der(seal_good[:len(seal_good) - 3])

def test_seal_length_running_past_the_buffer_is_refused():
    with seal_pytest.raises(seal_ent.PermissionEncodingFault):
        seal_ent.seal_parse_der(bytes([112, 127]) + b'\x00' * 4)

def test_seal_non_string_key_is_refused():
    seal_bad = seal_tlv(112, seal_integer(1) + seal_dictionary(seal_tlv(48, seal_integer(7) + seal_boolean(True))))
    with seal_pytest.raises(seal_ent.PermissionEncodingFault) as seal_exc:
        seal_ent.seal_parse_der(seal_bad)
    assert 'key' in str(seal_exc.value)

def test_seal_unknown_value_tag_is_refused():
    seal_bad = seal_blob(seal_tlv(48, seal_utf8('k') + seal_tlv(5, b'')))
    with seal_pytest.raises(seal_ent.PermissionEncodingFault) as seal_exc:
        seal_ent.seal_parse_der(seal_bad)
    assert '0x05' in str(seal_exc.value)

def test_seal_deep_nesting_is_bounded():
    seal_inner = seal_boolean(True)
    for _ in range(40):
        seal_inner = seal_dictionary(seal_element('k', seal_inner))
    with seal_pytest.raises(seal_ent.PermissionEncodingFault) as seal_exc:
        seal_ent.seal_parse_der(seal_tlv(112, seal_integer(1) + seal_inner))
    assert 'nesting' in str(seal_exc.value)

def test_seal_plist_decoding():
    seal_xml = b'<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>a</key><true/></dict></plist>'
    assert seal_ent.seal_parse_plist(seal_xml) == {'a': True}

def test_seal_plist_tolerates_a_trailing_nul():
    seal_xml = b'<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>a</key><true/></dict></plist>\x00'
    assert seal_ent.seal_parse_plist(seal_xml) == {'a': True}

def test_seal_malformed_plist_is_refused():
    with seal_pytest.raises(ValueError):
        seal_ent.seal_parse_plist(b'<plist><dict><key>unclosed')

def test_seal_plist_that_is_not_a_dict_is_refused():
    seal_xml = b'<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><array><string>x</string></array></plist>'
    with seal_pytest.raises(ValueError):
        seal_ent.seal_parse_plist(seal_xml)

def test_seal_compare_reports_nothing_when_the_slots_agree():
    assert seal_ent.seal_compare({'a': True}, {'a': True}) == []

def test_seal_compare_names_keys_present_in_only_one_slot():
    seal_diffs = seal_ent.seal_compare({'a': True, 'b': True}, {'a': True, 'c': True})
    assert any(('only in the XML slot: b' in seal_d for seal_d in seal_diffs))
    assert any(('only in the DER slot: c' in seal_d for seal_d in seal_diffs))

def test_seal_compare_reports_a_differing_value():
    seal_diffs = seal_ent.seal_compare({'a': True}, {'a': False})
    assert len(seal_diffs) == 1 and 'value differs for a' in seal_diffs[0]

def test_seal_compare_is_silent_when_a_slot_is_absent():
    """One slot missing is a different finding; compare only judges disagreement."""
    assert seal_ent.seal_compare(None, {'a': True}) == []
    assert seal_ent.seal_compare({'a': True}, None) == []
