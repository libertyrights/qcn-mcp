# qcn-mcp

## ALPHA — NOT TESTED AGAINST REAL QCN FILES

This is an untested, best-effort implementation. The QCN container and NV item
layouts were derived from public documentation and open-source projects, but
this server has **not** been validated against a real heterogeneous set of
`.qcn` files. The binary (OLE2/CFB) path, the IMEI/MEID/ESN item ids and the
packed-BCD decoders are marked **inferred, unverified**. Use at your own risk,
only on files you own, and always keep an unaltered backup.

A single-file Python **MCP (Model Context Protocol)** server for working with
**Qualcomm QCN (NV backup) files**. It is a **file-only, offline** tool: it
parses bytes on disk and never talks to a radio, never reads/writes a device,
and never flashes anything. It is the sibling project to `sahara-mcp` and
`qcdm-mcp` and mirrors their style.

## Features

Exposes the following tools (all under the `qcn_` prefix):

| Tool | Purpose |
| --- | --- |
| `qcn_info` | Detect format (xml / binary / txt), file size, item counts |
| `qcn_list_items` | List NV items (id, name, size), `limit<=0` for all |
| `qcn_get_item` | Fetch one NV item by id — hex + ascii + metadata |
| `qcn_extract_imei` | Scan for IMEI / MEID / ESN values (inferred layout) |
| `qcn_to_json` | Dump every parsed item to a JSON document |
| `qcn_set_item` | Rewrite one NV item into a **copy** of an XML source |
| `qcn_diff` | Compare two QCN files by numeric NV id |

## Supported input formats

* **XML** — the QPST "NvSource" XML source format (`<NvItem id=".."
  encoding="hex">…</NvItem>`, `<NvEfsItem fullpathname="..">…</NvEfsItem>`).
  This is the primary format. Parsing is tolerant: ElementTree first, with a
  regex fallback for malformed or very large files.
* **Binary** — a QPST `.qcn` file: an OLE2 / Compound File Binary (CFB)
  container (magic `D0 CF 11 E0 A1 B1 1A E1`) holding streams such as
  `NV_ITEM_ARRAY`, `File_Version`, `Mobile_Property_Info`, `EFS_Dir`,
  `EFS_Data`. A minimal CFB reader extracts `NV_ITEM_ARRAY` records
  (layout: LE `u16 stream_size, u16 index, u16 item_id, u16 pad`, then
  `stream_size-8` payload bytes) plus EFS sub-streams. **Inferred, untested.**
* **txt** — a QPST text dump beginning with `[NV items]` and lines like
  `00005 (0x0005)   -   OK` followed by hex byte lines. **Inferred, untested.**

Anything else is reported as `unknown` with a helpful warning.

## Safety and legality (read this)

* **IMEI / MEID / ESN**: changing these identifiers is illegal in many
  jurisdictions (e.g. a criminal offence under 18 U.S.C. 1029 in the US) unless
  you are the manufacturer or an authorised repairer. This tool does not help
  you do that — it only rewrites a copy of an XML file, never a device.
* **Brick risk**: writing a malformed or incompatible QCN and flashing it can
  brick the modem/radio. Always verify the output, keep the original, and know
  what you are doing.
* **`qcn_set_item` refuses to write** unless you pass **both**
  `dry_run=False` **and** `confirm=True`. The defaults are a no-op dry run that
  simply reports the old vs. new hex so you can review the change first. Only
  the `xml` format supports rewriting; binary and text inputs return an error.

## Install

Requires Python 3.8+ and the `pyproject.toml` dependencies:

```
pip install "mcp"        # or: pip install -e .
```

## Usage

Run the server (stdio transport, consumed by an MCP client):

```
python qcn_mcp_server.py
```

Example tool invocations an agent might make:

```
qcn_info(file_path="C:\\nv\\backup.qcn")
qcn_info(file_path="C:\\nv\\source.xml")
qcn_list_items(file_path="site.xml", limit=0)
qcn_get_item(file_path="site.xml", item_id=10)
qcn_extract_imei(file_path="backup.qcn")
qcn_to_json(file_path="backup.qcn", out_path="backup.json")
qcn_set_item(file_path="site.xml", item_id=10, hex_data="0004",
             out_path="site_patched.xml")                       # dry run, no write
qcn_set_item(file_path="site.xml", item_id=10, hex_data="0004",
             out_path="site_patched.xml", dry_run=False, confirm=True)
qcn_diff(file_a="site.xml", file_b="site_patched.xml")
```

## Format notes (verified against references)

* Real QPST `.qcn` files are **OLE2/CFB containers, not plain XML**. Common
  CFB streams: `NV_ITEM_ARRAY`, `EFS_Dir`, `EFS_Data`, `NV_Items`,
  `File_Version`, `Mobile_Property_Info`. Source: `vtsingaras/orct`
  (`src/orct/qcn_parser.clj`). GPL-3.0 — facts only.
* Legacy `NV_ITEM_ARRAY` record layout (little-endian): `uint16 stream_size`,
  `uint16 index`, `uint16 item`, `uint16 padding`, then `stream_size - 8`
  payload bytes.
* QPST XML "source" format: root `<NvSource>` containing
  `<NvItem id="441" name="NV_BAND_PREF_I" mapping="direct" encoding="hex">
  0x0,0x0</NvItem>` and
  `<NvEfsItem fullpathname="…" name="…" mapping="direct" encoding="hex"
  index="0">32,2c,31,…</NvEfsItem>`. Tokens are comma-separated; hex may be
  `0x`-prefixed or bare (bare values like `32,2c,31` are **hex**); multi-byte
  tokens are big-endian minimal bytes; `encoding="dec"` tokens are decimal.
  Source: `dl12345/qcn` (GPL) + `vtsingaras/orct` XML sources.
* QPST text-dump format starts `[NV items]` then lines like
  `00005 (0x0005)   -   OK` followed by hex byte lines; `Inactive item` marks
  an absent item. Source: `dl12345/qcn` (GPL).
* IMEI/MEID/ESN NV item ids (from common QCN tooling; **inferred/untested**
  here): `550 = NV_UE_IMEI_I` (IMEI, 9-byte packed BCD), `1943 = NV_MEID_I`
  (MEID), `0 = NV_ESN_I` (ESN), `85 = NV_SPC_I`, `5153 = NV_UE_IMEISV_SVN_I`.
  Cross-checked against `fipso/qcn_parser.py` (no licence declared; facts
  only).

## References and licensing

* vtsingaras/**orct** — CFB stream names and NV_ITEM_ARRAY framing, QPST XML
  shape. GPL-3.0. Consulted for format facts only; **no GPL code is imported
  or copied.** https://github.com/vtsingaras/orct
* dl12345/**qcn** — QPST text-dump format facts. GPL.
  https://github.com/dl12345/qcn
* fipso/**qcn_parser.py** — NV item ids (0, 1, 85, 550, 1943) and
  IMEI/MEID/ESN packed-BCD layout (no licence declared; behavioural/factual
  reference only). https://github.com/fipso/qcn_parser.py
* P1sec/**QCSuper** — consulted for facts only. GPL-3.0.
  https://github.com/P1sec/QCSuper

This project is licensed under the **GPL-3.0 license**. See `LICENSE`.
Copyright (c) 2026 libertyrights. Our own code is GPL-3.0; the references
above were used for format facts only and retain their own licenses.