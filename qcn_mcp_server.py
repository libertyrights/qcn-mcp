# qcn-mcp
# Copyright (C) 2026 libertyrights
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along with
# this program. If not, see <https://www.gnu.org/licenses/>.

"""qcn-mcp: a Model Context Protocol server for Qualcomm QCN (NV) files.

STATUS: ALPHA / UNTESTED.  This is a file-only, offline parser/viewer for
Qualcomm ``.qcn`` NV backup files.  It never talks to a radio and never writes
to a device.  Everything here parses bytes on disk.

Three on-disk containers are recognised (best-effort):

* ``xml``    - the human-readable QPST "NvSource" XML source format, i.e.
               ``<NvSource>`` with ``<NvItem id=".." name=".." encoding="hex">``
               and ``<NvEfsItem fullpathname="..">`` children.  This is the
               primary, best-supported format.
* ``binary`` - a QPST ``.qcn`` file, which is an OLE2 / Compound File Binary
               (CFB) container (magic ``D0 CF 11 E0 A1 B1 1A E1``) holding
               streams such as ``NV_ITEM_ARRAY``, ``File_Version``,
               ``Mobile_Property_Info``, ``EFS_Dir`` and ``EFS_Data``.
* ``txt``    - a QPST text dump beginning with ``[NV items]``.

The XML and binary layouts are *facts* derived from the publicly documented
behaviour of ``vtsingaras/orct`` (Clojure, GPL-3.0) and ``dl12345/qcn``
(C/C++, GPL-3.0); the NV item record framing and IMEI/MEID/ESN item ids were
cross-checked against ``fipso/qcn_parser.py`` (no licence declared; used only
as a factual reference for NV ids 0/1/85/550/1943 and the packed-BCD layouts).
No third-party code is imported, linked or copied; this file is an independent
re-implementation of those documented formats.

SAFETY / LEGAL
--------------
Changing an IMEI, MEID or ESN is illegal in many jurisdictions (for example it
is a criminal offence under 18 U.S.C. 1029 in the United States and similar
laws elsewhere) unless you are the manufacturer or an authorised repairer.
This tool does NOT help you do that: ``qcn_set_item`` only rewrites a *copy* of
an XML source file and refuses to write unless you pass BOTH ``dry_run=False``
AND ``confirm=True``.  It never flashes a device.  Writing a malformed QCN and
flashing it can brick the modem/radio.  You are responsible for anything you do
with the output.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import re
import struct
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from xml.etree import ElementTree as ET

logger = logging.getLogger("qcn-mcp")

# ---------------------------------------------------------------------------
# Format constants
# ---------------------------------------------------------------------------

CFB_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

_CFB_END = 0xFFFFFFFE
_CFB_FREE = 0xFFFFFFFF
_CFB_FAT = 0xFFFFFFFD
_CFB_DIF = 0xFFFFFFFC

# NV item ids. 550 (NV_UE_IMEI_I), 1943 (NV_MEID_I) and 0/1/85 are the
# long-established values used by common QCN tooling.  Treat all of these as
# inferred/untested beyond what you can see in a given file.
NV_ESN = 0
NV_ESN_CHKSM = 1
NV_SPC = 85
NV_IMEI = 550
NV_MEID = 1943
NV_UE_IMEISV_SVN = 5153

NV_ID_NAMES = {
    NV_ESN: "NV_ESN_I",
    NV_ESN_CHKSM: "NV_ESN_CHKSM_I",
    NV_SPC: "NV_SPC_I",
    NV_IMEI: "NV_UE_IMEI_I",
    NV_MEID: "NV_MEID_I",
    NV_UE_IMEISV_SVN: "NV_UE_IMEISV_SVN_I",
}

EFS_PARENT_STREAMS = ("NV_Items", "Provisioning_Item_Files", "EFS_Backup")


class QcnError(Exception):
    """Raised for malformed input or unsupported requests."""


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class NvItem:
    """One logical NV/EFS item recovered from a QCN container."""

    id: Optional[int] = None
    id_str: Optional[str] = None
    name: Optional[str] = None
    description: Optional[str] = None
    encoding: Optional[str] = None
    raw: bytes = b""
    source: str = "xml"
    path: Optional[str] = None
    index: Optional[int] = None
    inferred: bool = False


@dataclass
class QcnFile:
    """A parsed QCN container."""

    path: str = ""
    size: int = 0
    fmt: str = "unknown"
    version: Dict[str, object] = field(default_factory=dict)
    items: List[NvItem] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _localname(tag: str) -> str:
    """Strip an XML namespace prefix from a tag or attribute name."""
    if not isinstance(tag, str):
        return tag
    return tag.split("}", 1)[1] if "}" in tag else tag


def _read_file(path: str) -> bytes:
    if not os.path.isfile(path):
        raise QcnError(f"file not found: {path}")
    with open(path, "rb") as fh:
        return fh.read()


def _int_to_bytes(val: int) -> bytes:
    """Encode a non-negative int as big-endian minimal-length bytes."""
    if val < 0:
        val &= 0xFFFFFFFF
    n = max(1, (val.bit_length() + 7) // 8)
    return val.to_bytes(n, "big")


def _guess_ascii(data: bytes) -> str:
    if not data:
        return ""
    sample = data[:64]
    if all(32 <= b < 127 or b in (9, 10, 13) for b in sample):
        return data.decode("ascii", "replace")
    return ""


def _coerce_id(item_id) -> Optional[int]:
    if isinstance(item_id, int):
        return item_id
    if item_id is None:
        return None
    s = str(item_id).strip()
    try:
        return int(s, 0)
    except ValueError:
        pass
    try:
        return int(s, 16)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Payload (de)serialisation
# ---------------------------------------------------------------------------


def decode_payload(text: Optional[str], encoding: Optional[str] = None) -> bytes:
    """Decode an XML element body into raw bytes.

    QPST XML bodies come in several flavours: comma/space separated tokens
    (``0x0,0x0`` or bare hex like ``32,2c,31``), decimal token lists
    (``encoding="dec"``), single hex blobs, or occasionally base64.  Tokens are
    interpreted as big-endian minimal-length integers, which is how QPST emits
    multi-byte values.
    """
    if not text:
        return b""
    t = text.strip()
    if not t:
        return b""
    enc = (encoding or "").strip().lower()

    if "," in t or re.search(r"\s", t):
        return _decode_tokens(t, enc)

    low = t.lower()
    if low.startswith("0x"):
        try:
            return bytes.fromhex(t[2:])
        except ValueError:
            pass
    if enc == "dec" and t.lstrip("-").isdigit():
        try:
            return _int_to_bytes(int(t, 10))
        except ValueError:
            pass
    if enc == "hex":
        try:
            return bytes.fromhex(t)
        except ValueError:
            pass
    if re.fullmatch(r"[0-9A-Fa-f]+", t) and len(t) % 2 == 0:
        try:
            return bytes.fromhex(t)
        except ValueError:
            pass
    if t.isdigit():
        try:
            return _int_to_bytes(int(t, 10))
        except ValueError:
            pass
    try:
        decoded = base64.b64decode(t, validate=True)
        if decoded:
            return decoded
    except Exception:
        pass
    return t.encode("utf-8")


def _decode_tokens(t: str, enc: str) -> bytes:
    tokens = [tok for tok in re.split(r"[,\s]+", t) if tok]
    if enc == "dec":
        base = 10
    elif enc == "hex":
        base = 16
    elif any(tok.lower().startswith("0x") for tok in tokens):
        base = 16
    elif any(re.search(r"[A-Fa-f]", tok) for tok in tokens):
        base = 16
    else:
        base = 10
    out = bytearray()
    for tok in tokens:
        s = tok[2:] if tok.lower().startswith("0x") else tok
        try:
            val = int(s, base)
        except ValueError:
            try:
                val = int(s, 16)
            except ValueError:
                continue
        out += _int_to_bytes(val)
    return bytes(out)


def encode_payload(data: bytes, encoding: Optional[str] = None) -> str:
    """Encode raw bytes back into a QPST XML element body."""
    enc = (encoding or "").strip().lower()
    if enc == "dec":
        return ", ".join(str(b) for b in data)
    return ", ".join("0x%02x" % b for b in data)


# ---------------------------------------------------------------------------
# XML ("NvSource") parsing
# ---------------------------------------------------------------------------

_XML_ELEM_RE = re.compile(
    r"<([A-Za-z_][\w:.\-]*)\b([^>]*?)(?:/>|>(.*?)</\1\s*>)", re.DOTALL
)
_ATTR_RE = re.compile(r"([\w:.\-]+)\s*=\s*(?:\"([^\"]*)\"|'([^']*)')")


def _xml_item_from_element(el: ET.Element) -> Optional[NvItem]:
    tag = _localname(el.tag)
    attribs = {_localname(k): v for k, v in el.attrib.items()}
    is_efs = tag.lower() == "nvefsitem" or "fullpathname" in attribs
    id_attr = attribs.get("id") or None
    if id_attr is None and not is_efs:
        return None
    id_val = _coerce_id(id_attr) if id_attr is not None else None
    raw = decode_payload((el.text or "").strip(), attribs.get("encoding"))
    return NvItem(
        id=id_val,
        id_str=id_attr,
        name=attribs.get("name") or attribs.get("fullpathname"),
        description=attribs.get("description"),
        encoding=attribs.get("encoding"),
        raw=raw,
        source=tag,
        path=attribs.get("fullpathname"),
    )


def _parse_attrs(attr_text: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for m in _ATTR_RE.finditer(attr_text):
        val = m.group(2) if m.group(2) is not None else m.group(3)
        out[_localname(m.group(1))] = val
    return out


def _xml_regex_items(text: str) -> List[NvItem]:
    items: List[NvItem] = []
    for m in _XML_ELEM_RE.finditer(text):
        tag = _localname(m.group(1))
        attrs = _parse_attrs(m.group(2) or "")
        body = m.group(3) or ""
        is_efs = tag.lower() == "nvefsitem" or "fullpathname" in attrs
        id_attr = attrs.get("id") or None
        if id_attr is None and not is_efs:
            continue
        items.append(
            NvItem(
                id=_coerce_id(id_attr) if id_attr is not None else None,
                id_str=id_attr,
                name=attrs.get("name") or attrs.get("fullpathname"),
                description=attrs.get("description"),
                encoding=attrs.get("encoding"),
                raw=decode_payload(body.strip(), attrs.get("encoding")),
                source=tag,
                path=attrs.get("fullpathname"),
            )
        )
    return items


def _parse_xml(data: bytes) -> QcnFile:
    qf = QcnFile(fmt="xml")
    text = data.decode("utf-8", "replace")
    items: List[NvItem] = []
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        qf.warnings.append(
            f"XML is not well-formed ({exc}); used a tolerant regex fallback"
        )
        qf.version["root"] = "unknown"
        items = _xml_regex_items(text)
    else:
        qf.version["root"] = _localname(root.tag)
        for k, v in root.attrib.items():
            qf.version[_localname(k)] = v
        for el in root.iter():
            it = _xml_item_from_element(el)
            if it is not None:
                items.append(it)
    if not items:
        qf.warnings.append("no <NvItem>/<NvEfsItem> entries were found")
    qf.items = items
    return qf


# ---------------------------------------------------------------------------
# CFB / OLE2 compound-file reader (for binary .qcn)
# ---------------------------------------------------------------------------


class _CfbReader:
    """Minimal read-only OLE2/CFB container reader."""

    def __init__(self, data: bytes) -> None:
        if len(data) < 512 or data[:8] != CFB_MAGIC:
            raise QcnError("not an OLE2/CFB container")
        self.data = data
        self.sz = 1 << struct.unpack_from("<H", data, 30)[0]
        self.mssz = 1 << struct.unpack_from("<H", data, 32)[0]
        self.num_fat = struct.unpack_from("<I", data, 44)[0]
        self.first_dir = struct.unpack_from("<I", data, 48)[0]
        self.mini_cutoff = struct.unpack_from("<I", data, 56)[0]
        self.first_minifat = struct.unpack_from("<I", data, 60)[0]
        self.num_minifat = struct.unpack_from("<I", data, 64)[0]
        self.first_difat = struct.unpack_from("<I", data, 68)[0]
        self.num_difat = struct.unpack_from("<I", data, 72)[0]
        self._header_difat = list(struct.unpack_from("<109I", data, 76))
        if self.sz < 512 or self.mssz <= 0:
            raise QcnError("implausible sector sizes")
        self.fat = self._build_fat()
        self.entries = self._read_dir()
        self.minifat = self._read_minifat()
        self.ministream = self._read_ministream()

    # -- low level ---------------------------------------------------------

    def _sector(self, sid: int) -> bytes:
        off = 512 + sid * self.sz
        return self.data[off:off + self.sz]

    def _difat_list(self) -> List[int]:
        out = [d for d in self._header_difat if d not in (_CFB_FREE, _CFB_END)]
        per = self.sz // 4 - 1
        sid = self.first_difat
        guard = 0
        while sid not in (_CFB_END, _CFB_FREE) and guard <= self.num_difat + 4:
            sec = self._sector(sid)
            if len(sec) < self.sz:
                break
            vals = list(struct.unpack_from("<%dI" % (self.sz // 4), sec, 0))
            out.extend(v for v in vals[:per] if v not in (_CFB_FREE, _CFB_END))
            sid = vals[-1]
            guard += 1
        return out

    def _build_fat(self) -> List[int]:
        ids = self._difat_list()
        if self.num_fat:
            ids = ids[: self.num_fat]
        fat: List[int] = []
        for sid in ids:
            sec = self._sector(sid)
            if len(sec) < self.sz:
                break
            fat.extend(struct.unpack_from("<%dI" % (self.sz // 4), sec, 0))
        return fat

    def _read_chain(self, start: int, size: Optional[int] = None) -> bytes:
        chunks: List[bytes] = []
        sid = start
        guard = 0
        limit = len(self.fat) + 2
        while sid not in (_CFB_END, _CFB_FREE) and guard < limit:
            if sid >= len(self.fat):
                break
            chunks.append(self._sector(sid))
            sid = self.fat[sid]
            guard += 1
        blob = b"".join(chunks)
        return blob[:size] if size is not None else blob

    def _read_mini_chain(self, start: int, size: int) -> bytes:
        chunks: List[bytes] = []
        sid = start
        guard = 0
        while sid not in (_CFB_END, _CFB_FREE) and guard < len(self.minifat) + 2:
            off = sid * self.mssz
            chunks.append(self.ministream[off:off + self.mssz])
            sid = self.minifat[sid] if sid < len(self.minifat) else _CFB_END
            guard += 1
        return b"".join(chunks)[:size]

    def _read_stream(self, entry: Dict[str, object]) -> bytes:
        size = int(entry["size"])
        if entry["type"] != 5 and size < self.mini_cutoff:
            return self._read_mini_chain(int(entry["start"]), size)
        return self._read_chain(int(entry["start"]), size)

    def _read_dir(self) -> List[Dict[str, object]]:
        blob = self._read_chain(self.first_dir)
        entries: List[Dict[str, object]] = []
        for off in range(0, len(blob) - 127, 128):
            chunk = blob[off:off + 128]
            namelen = struct.unpack_from("<H", chunk, 64)[0]
            etype = chunk[66]
            if etype == 0 and namelen == 0:
                continue
            name = ""
            if 2 <= namelen <= 64:
                name = chunk[0:namelen - 2].decode("utf-16-le", "replace")
            entries.append({
                "name": name,
                "type": etype,
                "start": struct.unpack_from("<I", chunk, 116)[0],
                "size": struct.unpack_from("<Q", chunk, 120)[0],
                "left": struct.unpack_from("<I", chunk, 68)[0],
                "right": struct.unpack_from("<I", chunk, 72)[0],
                "child": struct.unpack_from("<I", chunk, 76)[0],
            })
        return entries

    def _read_minifat(self) -> List[int]:
        if self.first_minifat in (_CFB_END, _CFB_FREE):
            return []
        blob = self._read_chain(self.first_minifat)
        n = len(blob) // 4
        return list(struct.unpack_from("<%dI" % n, blob, 0)) if n else []

    def _read_ministream(self) -> bytes:
        for e in self.entries:
            if e["type"] == 5:
                if e["start"] in (_CFB_END, _CFB_FREE):
                    return b""
                return self._read_chain(int(e["start"]), int(e["size"]))
        return b""

    # -- public ------------------------------------------------------------

    def streams(self) -> Dict[Tuple[str, ...], bytes]:
        out: Dict[Tuple[str, ...], bytes] = {}

        def collect(idx: int) -> List[int]:
            result: List[int] = []

            def rec(i: int, depth: int) -> None:
                if i in (_CFB_FREE, _CFB_END) or i >= len(self.entries) or depth > 512:
                    return
                e = self.entries[i]
                rec(int(e["left"]), depth + 1)
                result.append(i)
                rec(int(e["right"]), depth + 1)

            rec(idx, 0)
            return result

        def build(node: int, path: List[str]) -> None:
            for cid in collect(node):
                e = self.entries[cid]
                if e["type"] == 2:
                    out[tuple(path + [str(e["name"])])] = self._read_stream(e)
                elif e["type"] == 1:
                    build(int(e["child"]), path + [str(e["name"])])

        for r in range(len(self.entries)):
            if self.entries[r]["type"] == 5:
                build(int(self.entries[r]["child"]), [])
                break
        return out


def _parse_nv_item_array(blob: bytes) -> Tuple[List[NvItem], List[str]]:
    """Parse a legacy ``NV_ITEM_ARRAY`` stream.

    Record layout (little-endian): uint16 stream_size, uint16 index,
    uint16 item_id, uint16 padding, then (stream_size - 8) payload bytes.
    """
    items: List[NvItem] = []
    warnings: List[str] = []
    pos = 0
    idx = 0
    while pos + 8 <= len(blob):
        stream_size, index, item, _pad = struct.unpack_from("<HHHH", blob, pos)
        if stream_size < 8 or pos + stream_size > len(blob):
            warnings.append(
                f"stopped at offset {pos}: malformed NV record (size={stream_size})"
            )
            break
        payload = blob[pos + 8:pos + stream_size]
        items.append(
            NvItem(
                id=item,
                name=NV_ID_NAMES.get(item),
                raw=payload,
                source="NV_ITEM_ARRAY",
                index=index if index else idx,
                inferred=True,
            )
        )
        pos += stream_size
        idx += 1
    return items, warnings


def _parse_mobile_property_info(blob: bytes) -> Dict[str, object]:
    info: Dict[str, object] = {}
    if len(blob) < 9:
        return info
    info["efs_spec"] = struct.unpack_from("<I", blob, 0)[0]
    info["mobile_model"] = struct.unpack_from("<H", blob, 4)[0]
    info["major"] = blob[6]
    info["minor"] = blob[7]
    off = 8
    if off + 2 > len(blob):
        return info
    swlen = struct.unpack_from("<H", blob, off)[0]
    off += 2
    info["sw_version"] = blob[off:off + swlen].rstrip(b"\x00").decode("latin-1", "replace")
    off += swlen
    if off + 2 <= len(blob):
        qlen = struct.unpack_from("<H", blob, off)[0]
        off += 2
        info["qpst_version"] = blob[off:off + qlen].rstrip(b"\x00").decode("latin-1", "replace")
    return info


def _parse_binary(data: bytes) -> QcnFile:
    qf = QcnFile(fmt="binary")
    qf.version["container"] = "OLE2/CFB"
    try:
        cfb = _CfbReader(data)
        streams = cfb.streams()
    except Exception as exc:
        qf.warnings.append(f"CFB parse failed: {exc}")
        return qf

    fv = streams.get(("File_Version",))
    if fv and len(fv) >= 6:
        try:
            major, minor, rev = struct.unpack_from("<HHH", fv, 0)
            qf.version["file_version"] = {
                "major": major, "minor": minor, "revision": rev
            }
        except Exception:
            pass

    mpi = streams.get(("Mobile_Property_Info",))
    if mpi:
        try:
            qf.version["mobile_property_info"] = _parse_mobile_property_info(mpi)
        except Exception:
            pass

    arr = streams.get(("NV_ITEM_ARRAY",))
    if arr:
        items, warns = _parse_nv_item_array(arr)
        qf.items.extend(items)
        qf.warnings.extend(warns)
    else:
        qf.warnings.append("NV_ITEM_ARRAY stream not found")

    for parent in EFS_PARENT_STREAMS:
        for key, blob in streams.items():
            if len(key) == 2 and key[0] == parent:
                qf.items.append(
                    NvItem(
                        id=None,
                        id_str=key[1],
                        name=key[1],
                        raw=blob,
                        source=parent,
                        inferred=True,
                    )
                )
    if not qf.items:
        qf.warnings.append("no NV items were recovered from the CFB container")
    return qf


# ---------------------------------------------------------------------------
# QPST text-dump parsing
# ---------------------------------------------------------------------------

_TXT_ITEM_RE = re.compile(r"^\s*(\d+)\s*\(0x([0-9A-Fa-f]+)\)\s*-?\s*(.*\S)?\s*$")


def _parse_txt(data: bytes) -> QcnFile:
    qf = QcnFile(fmt="txt")
    text = data.decode("latin-1")
    items: List[NvItem] = []
    cur_id: Optional[int] = None
    cur_status: Optional[str] = None
    buf = bytearray()

    def flush() -> None:
        if cur_id is None:
            return
        items.append(
            NvItem(
                id=cur_id,
                name=NV_ID_NAMES.get(cur_id) or cur_status,
                description=cur_status,
                raw=bytes(buf),
                source="qpst_text",
                inferred=True,
            )
        )

    for line in text.splitlines():
        m = _TXT_ITEM_RE.match(line)
        if m:
            flush()
            buf = bytearray()
            cur_id = int(m.group(1))
            cur_status = (m.group(3) or "").strip() or None
            continue
        if cur_id is not None:
            hexonly = re.sub(r"[^0-9A-Fa-f]", "", line)
            if hexonly:
                if len(hexonly) % 2:
                    hexonly = hexonly[:-1]
                try:
                    buf += bytes.fromhex(hexonly)
                except ValueError:
                    pass
    flush()
    qf.items = items
    if not items:
        qf.warnings.append("no NV item lines recognised in text dump")
    return qf


# ---------------------------------------------------------------------------
# Format detection & top-level parse
# ---------------------------------------------------------------------------


def detect_format(data: bytes) -> str:
    if data[:8] == CFB_MAGIC:
        return "binary"
    head = data[:512]
    if head[:3] == b"\xef\xbb\xbf":
        head = head[3:]
    head = head.lstrip(b"\x00\t\r\n ")
    if head[:1] == b"<":
        return "xml"
    if b"[NV items]" in data[:4096]:
        return "txt"
    return "unknown"


def parse_qcn(file_path: str) -> QcnFile:
    """Detect the container format of ``file_path`` and parse it."""
    data = _read_file(file_path)
    fmt = detect_format(data)
    if fmt == "xml":
        qf = _parse_xml(data)
    elif fmt == "binary":
        qf = _parse_binary(data)
    elif fmt == "txt":
        qf = _parse_txt(data)
    else:
        qf = QcnFile(fmt="unknown")
        qf.warnings.append(
            "unrecognised container; supported inputs are XML QCN sources, "
            "CFB/OLE2 binary .qcn files and QPST text dumps"
        )
    qf.path = file_path
    qf.size = len(data)
    return qf


# ---------------------------------------------------------------------------
# Identifier decoders (packed BCD as used by common QCN tooling)
# ---------------------------------------------------------------------------


def decode_imei(payload: bytes) -> Optional[str]:
    """Decode a 15-digit IMEI from a 9-byte NV 550 (NV_UE_IMEI_I) value."""
    if len(payload) < 9:
        return None
    h = payload[:9].hex()
    first = h[2]
    other = h[4:]
    return first + "".join(other[i + 1] + other[i]
                           for i in range(0, len(other) - 1, 2))


def decode_meid(payload: bytes) -> Optional[str]:
    """Decode a 14-hex-digit MEID from a 7-byte NV 1943 value."""
    if len(payload) < 7:
        return None
    h = payload[:7].hex()
    return "".join(reversed([h[i:i + 2] for i in range(0, len(h), 2)]))


def decode_esn(payload: bytes) -> Optional[str]:
    """Decode an 8-hex-digit ESN from a 4-byte NV 0 value."""
    if len(payload) < 4:
        return None
    return payload[:4][::-1].hex()


# ---------------------------------------------------------------------------
# Core tool implementations (module level so they are importable/testable)
# ---------------------------------------------------------------------------


def qcn_info(file_path: str) -> Dict[str, object]:
    qf = parse_qcn(file_path)
    ids = sorted({it.id for it in qf.items if isinstance(it.id, int)})
    return {
        "file": qf.path,
        "size": qf.size,
        "format": qf.fmt,
        "item_count": len(qf.items),
        "unique_ids": len(ids),
        "version": qf.version,
        "warnings": qf.warnings,
    }


def qcn_list_items(file_path: str, limit: int = 100) -> Dict[str, object]:
    qf = parse_qcn(file_path)
    if limit is None or limit <= 0:
        selected = qf.items
    else:
        selected = qf.items[:limit]
    items = [
        {
            "id": it.id if it.id is not None else it.id_str,
            "name": it.name,
            "index": it.index,
            "source": it.source,
            "size": len(it.raw),
            "inferred": it.inferred,
        }
        for it in selected
    ]
    return {
        "format": qf.fmt,
        "item_count": len(qf.items),
        "returned": len(items),
        "items": items,
        "warnings": qf.warnings,
    }


def qcn_get_item(file_path: str, item_id) -> Dict[str, object]:
    qf = parse_qcn(file_path)
    want = _coerce_id(item_id)
    if want is not None:
        matches = [it for it in qf.items if it.id == want]
    else:
        key = str(item_id).strip().lower()
        matches = [it for it in qf.items
                   if str(it.id_str or "").strip().lower() == key]
    if not matches:
        return {"error": f"item {item_id!r} not found", "format": qf.fmt}
    out = [
        {
            "id": it.id if it.id is not None else it.id_str,
            "name": it.name,
            "description": it.description,
            "encoding": it.encoding,
            "path": it.path,
            "source": it.source,
            "size": len(it.raw),
            "hex": it.raw.hex(),
            "ascii": _guess_ascii(it.raw),
            "inferred": it.inferred,
        }
        for it in matches
    ]
    return {"format": qf.fmt, "count": len(out), "items": out}


def qcn_extract_imei(file_path: str) -> Dict[str, object]:
    qf = parse_qcn(file_path)
    results: List[Dict[str, object]] = []
    for it in qf.items:
        label = ((it.name or "") + " " + (it.description or "")).upper()
        if it.id == NV_IMEI or "IMEI" in label:
            value = decode_imei(it.raw)
            if value:
                results.append({
                    "kind": "imei",
                    "id": it.id if it.id is not None else it.id_str,
                    "name": it.name or "NV_UE_IMEI_I",
                    "value": value,
                    "hex": it.raw.hex(),
                    "inferred": it.inferred,
                })
        if it.id == NV_MEID or "MEID" in label:
            value = decode_meid(it.raw)
            if value:
                results.append({
                    "kind": "meid",
                    "id": it.id if it.id is not None else it.id_str,
                    "name": it.name or "NV_MEID_I",
                    "value": value,
                    "hex": it.raw.hex(),
                    "inferred": it.inferred,
                })
        if it.id == NV_ESN or "ESN" in label:
            value = decode_esn(it.raw)
            if value:
                results.append({
                    "kind": "esn",
                    "id": it.id if it.id is not None else it.id_str,
                    "name": it.name or "NV_ESN_I",
                    "value": value,
                    "hex": it.raw.hex(),
                    "inferred": it.inferred,
                })
    return {"format": qf.fmt, "identifiers": results, "warnings": qf.warnings}


def qcn_to_json(file_path: str, out_path: str) -> Dict[str, object]:
    qf = parse_qcn(file_path)
    payload = {
        "file": qf.path,
        "size": qf.size,
        "format": qf.fmt,
        "version": qf.version,
        "warnings": qf.warnings,
        "items": [
            {
                "id": it.id if it.id is not None else it.id_str,
                "name": it.name,
                "description": it.description,
                "encoding": it.encoding,
                "path": it.path,
                "source": it.source,
                "size": len(it.raw),
                "hex": it.raw.hex(),
                "inferred": it.inferred,
            }
            for it in qf.items
        ],
    }
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    return {"written": out_path, "format": qf.fmt, "item_count": len(qf.items)}


def _xml_replace_item_text(text: str, item_id: int, new_text: str) -> Tuple[str, bool]:
    pattern = re.compile(
        r"(<([A-Za-z_][\w:.\-]*)\b[^>]*\bid\s*=\s*[\"']\s*"
        + re.escape(str(item_id))
        + r"\s*[\"'][^>]*>)(.*?)(</\2\s*>)",
        re.DOTALL,
    )

    def repl(m: "re.Match") -> str:
        return m.group(1) + new_text + m.group(4)

    new_text_full, count = pattern.subn(repl, text, count=1)
    return new_text_full, count > 0


def qcn_set_item(
    file_path: str,
    item_id,
    hex_data: str,
    out_path: str,
    dry_run: bool = True,
    confirm: bool = False,
) -> Dict[str, object]:
    """Rewrite one NV item in a *copy* of an XML QCN source.

    WARNING: changing an IMEI/MEID/ESN is illegal in many jurisdictions, and
    flashing a malformed QCN can brick the radio.  Nothing is written unless
    BOTH ``dry_run=False`` AND ``confirm=True`` are supplied.  Only the ``xml``
    container is supported for rewriting; binary/text inputs return an error.
    The rewrite is UNTESTED - always verify the output before using it.
    """
    qf = parse_qcn(file_path)
    if qf.fmt != "xml":
        return {
            "error": "writing is only supported for XML QCN sources, "
                     f"not {qf.fmt!r} input"
        }
    try:
        new_bytes = bytes.fromhex(re.sub(r"[\s,]+", "", hex_data or ""))
    except ValueError:
        return {"error": "hex_data must be a hexadecimal string, e.g. '0a1b2c3d'"}

    want = _coerce_id(item_id)
    if want is None:
        return {"error": f"item id {item_id!r} is not a numeric NV id"}

    matches = [it for it in qf.items if it.id == want]
    if not matches:
        return {"error": f"item {item_id!r} not found in {file_path}", "format": qf.fmt}

    change: Dict[str, object] = {
        "file": file_path,
        "item_id": want,
        "name": matches[0].name,
        "encoding": matches[0].encoding,
        "old_hex": matches[0].raw.hex(),
        "new_hex": new_bytes.hex(),
        "out_path": out_path,
    }

    if dry_run or not confirm:
        change["written"] = False
        change["note"] = (
            "dry run - nothing was written. Pass dry_run=False AND confirm=True "
            "to apply. Review old_hex vs new_hex first. This rewrite is UNTESTED."
        )
        return change

    text = _read_file(file_path).decode("utf-8", "replace")
    encoded = encode_payload(new_bytes, matches[0].encoding)
    updated, found = _xml_replace_item_text(text, want, encoded)
    if not found:
        return {"error": f"could not locate item {item_id!r} in the XML text to rewrite"}
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(updated)
    change["written"] = True
    change["note"] = (
        "written to out_path. This is an UNTESTED, reformatting rewrite - verify "
        "the file before flashing. Never change IMEI/MEID/ESN illegally."
    )
    return change


def qcn_diff(file_a: str, file_b: str) -> Dict[str, object]:
    a = parse_qcn(file_a)
    b = parse_qcn(file_b)
    da = {it.id: it for it in a.items if isinstance(it.id, int)}
    db = {it.id: it for it in b.items if isinstance(it.id, int)}
    changed: List[Dict[str, object]] = []
    for i in sorted(set(da) & set(db)):
        if da[i].raw != db[i].raw:
            changed.append({
                "id": i,
                "name": da[i].name or db[i].name,
                "a_hex": da[i].raw.hex(),
                "b_hex": db[i].raw.hex(),
            })
    return {
        "a": {"file": file_a, "format": a.fmt, "item_count": len(a.items)},
        "b": {"file": file_b, "format": b.fmt, "item_count": len(b.items)},
        "added_ids": sorted(set(db) - set(da)),
        "removed_ids": sorted(set(da) - set(db)),
        "changed": changed,
        "changed_count": len(changed),
    }


# ---------------------------------------------------------------------------
# MCP tool surface
# ---------------------------------------------------------------------------

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:  # pragma: no cover - exercised only without the SDK
    FastMCP = None


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    if FastMCP is None:
        sys.stderr.write("mcp SDK not installed. Run `pip install -e .`.\n")
        sys.exit(1)

    mcp = FastMCP("qcn-mcp")

    @mcp.tool()
    def qcn_info_tool(file_path: str) -> dict:
        """Summarise a QCN file: detected format, size and item counts."""
        try:
            return qcn_info(file_path)
        except QcnError as exc:
            return {"error": str(exc)}

    @mcp.tool()
    def qcn_list_items_tool(file_path: str, limit: int = 100) -> dict:
        """List NV items in a QCN file (id, name, size). Use limit<=0 for all."""
        try:
            return qcn_list_items(file_path, limit)
        except QcnError as exc:
            return {"error": str(exc)}

    @mcp.tool()
    def qcn_get_item_tool(file_path: str, item_id: str) -> dict:
        """Fetch one NV item by id (int or 8-hex EFS key) with hex + ascii."""
        try:
            return qcn_get_item(file_path, item_id)
        except QcnError as exc:
            return {"error": str(exc)}

    @mcp.tool()
    def qcn_extract_imei_tool(file_path: str) -> dict:
        """Extract IMEI / MEID / ESN values embedded in a QCN file.

        Note: the IMEI/MEID/ESN NV item ids and packed-BCD layouts are inferred
        from common QCN tooling and are UNTESTED here.
        """
        try:
            return qcn_extract_imei(file_path)
        except QcnError as exc:
            return {"error": str(exc)}

    @mcp.tool()
    def qcn_to_json_tool(file_path: str, out_path: str) -> dict:
        """Dump every parsed NV item of a QCN file to a JSON document."""
        try:
            return qcn_to_json(file_path, out_path)
        except QcnError as exc:
            return {"error": str(exc)}

    @mcp.tool()
    def qcn_set_item_tool(
        file_path: str,
        item_id: str,
        hex_data: str,
        out_path: str,
        dry_run: bool = True,
        confirm: bool = False,
    ) -> dict:
        """Rewrite one NV item into a COPY of an XML QCN source.

        SAFETY: writes only when BOTH dry_run=False AND confirm=True. Defaults
        are a no-op dry run that just reports old/new hex. Changing IMEI/MEID/
        ESN is illegal in many jurisdictions; flashing a bad QCN can brick the
        radio. This rewrite is UNTESTED.
        """
        try:
            return qcn_set_item(file_path, item_id, hex_data, out_path, dry_run, confirm)
        except QcnError as exc:
            return {"error": str(exc)}

    @mcp.tool()
    def qcn_diff_tool(file_a: str, file_b: str) -> dict:
        """Compare two QCN files by numeric NV id and report differences."""
        try:
            return qcn_diff(file_a, file_b)
        except QcnError as exc:
            return {"error": str(exc)}

    mcp.run()


if __name__ == "__main__":
    main()
