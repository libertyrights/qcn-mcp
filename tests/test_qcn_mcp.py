"""Unit tests for qcn-mcp.

These tests exercise the parser/identifier logic against small synthetic
fixtures.  They do not touch real hardware or real QCN files.
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import qcn_mcp_server as qcn  # noqa: E402

XML_SAMPLE = """<?xml version="1.0" encoding="UTF-8"?>
<NvSource Name="test-source">
  <NvItem id="550" name="NV_UE_IMEI_I" mapping="direct" encoding="hex">0x08,0x10,0x32,0x54,0x76,0x98,0x10,0x32,0x54</NvItem>
  <NvItem id="10" name="NV_MOB_CAI_REV_I" mapping="direct" encoding="hex">0x0,0x4</NvItem>
  <NvEfsItem fullpathname="/policyman/carrier_policy.xml" name="carrier_policy" mapping="direct" encoding="hex" index="0">32,2c,31</NvEfsItem>
</NvSource>
"""

TXT_SAMPLE = (
    b"[NV items]\r\n"
    b"[Complete items - 3, Items size - 128]\r\n"
    b"00005 (0x0005)   -   OK\r\n"
    b"0A 0B 0C 0D\r\n"
    b"00100 (0x0100)   -   Inactive item\r\n"
)


def _write_tmp(content, suffix):
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "wb") as fh:
        fh.write(content)
    return path


def test_detect_format_xml():
    assert qcn.detect_format(XML_SAMPLE.encode("utf-8")) == "xml"


def test_detect_format_binary():
    assert qcn.detect_format(qcn.CFB_MAGIC + b"\x00" * 508) == "binary"


def test_detect_format_txt():
    assert qcn.detect_format(TXT_SAMPLE) == "txt"


def test_detect_format_unknown():
    assert qcn.detect_format(b"not a qcn at all") == "unknown"


def test_parse_xml_items():
    path = _write_tmp(XML_SAMPLE.encode("utf-8"), ".xml")
    try:
        qf = qcn.parse_qcn(path)
        assert qf.fmt == "xml"
        assert len(qf.items) == 3
        ids = sorted(it.id for it in qf.items if it.id is not None)
        assert ids == [10, 550]
    finally:
        os.remove(path)


def test_get_item_hex():
    path = _write_tmp(XML_SAMPLE.encode("utf-8"), ".xml")
    try:
        res = qcn.qcn_get_item(path, "550")
        assert res["count"] == 1
        assert res["items"][0]["hex"] == "081032547698103254"
    finally:
        os.remove(path)


def test_decode_tokens_bare_hex():
    assert qcn.decode_payload("32,2c,31", "hex").hex() == "322c31"
    assert qcn.decode_payload("0x0,0x4", "hex").hex() == "0004"


def test_extract_imei():
    path = _write_tmp(XML_SAMPLE.encode("utf-8"), ".xml")
    try:
        res = qcn.qcn_extract_imei(path)
        kinds = {r["kind"]: r["value"] for r in res["identifiers"]}
        assert kinds.get("imei") == "123456789012345"
    finally:
        os.remove(path)


def test_set_item_dry_run_writes_nothing():
    path = _write_tmp(XML_SAMPLE.encode("utf-8"), ".xml")
    out = path + ".out"
    try:
        res = qcn.qcn_set_item(path, "10", "0102", out)
        assert res["written"] is False
        assert res["old_hex"] == "0004"
        assert res["new_hex"] == "0102"
        assert not os.path.exists(out)
    finally:
        os.remove(path)
        if os.path.exists(out):
            os.remove(out)


def test_set_item_confirm_writes_copy():
    path = _write_tmp(XML_SAMPLE.encode("utf-8"), ".xml")
    out = path + ".out"
    try:
        res = qcn.qcn_set_item(path, "10", "0a0b0c", out, dry_run=False, confirm=True)
        assert res["written"] is True
        assert os.path.exists(out)
        reparsed = qcn.qcn_get_item(out, "10")
        assert reparsed["items"][0]["hex"] == "0a0b0c"
        # original is untouched
        assert qcn.qcn_get_item(path, "10")["items"][0]["hex"] == "0004"
    finally:
        os.remove(path)
        if os.path.exists(out):
            os.remove(out)


def test_set_item_refuses_binary_or_text():
    path = _write_tmp(TXT_SAMPLE, ".txt")
    try:
        res = qcn.qcn_set_item(path, "5", "00", path + ".out")
        assert "error" in res
    finally:
        os.remove(path)


def test_decode_imei_meid_esn():
    assert qcn.decode_imei(bytes.fromhex("081032547698103254")) == "123456789012345"
    assert qcn.decode_meid(bytes.fromhex("123456789abcde")) == "debc9a78563412"
    assert qcn.decode_esn(bytes.fromhex("12345678")) == "78563412"


def test_parse_txt():
    path = _write_tmp(TXT_SAMPLE, ".txt")
    try:
        qf = qcn.parse_qcn(path)
        assert qf.fmt == "txt"
        by_id = {it.id: it for it in qf.items}
        assert by_id[5].raw.hex() == "0a0b0c0d"
        assert 100 in by_id
    finally:
        os.remove(path)


def test_diff():
    a = _write_tmp(XML_SAMPLE.encode("utf-8"), ".xml")
    modified = XML_SAMPLE.replace(">0x0,0x4<", ">0x0,0x5<")
    b = _write_tmp(modified.encode("utf-8"), ".xml")
    try:
        res = qcn.qcn_diff(a, b)
        assert res["changed_count"] == 1
        assert res["changed"][0]["id"] == 10
    finally:
        os.remove(a)
        os.remove(b)
