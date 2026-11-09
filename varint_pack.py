#!/usr/bin/env python3
import argparse
import csv
import glob
import json
import os
import sys

import brotli

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from arbitrum_batch_pipeline import LAYOUT, rlp_item

INT_FIELDS = {"chain_id", "nonce", "gas_price", "max_priority_fee", "max_fee", "gas", "value", "v"}
BYTES_FIELDS = {"to", "data"}
SIG_FIELDS = {"r", "s"}
LIST_FIELDS = {"access_list", "auth_list"}
ESCAPE = 0xFF

def put_varint(n, out):
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return

def get_varint(buf, pos):
    n = shift = 0
    while True:
        b = buf[pos]
        pos += 1
        n |= (b & 0x7F) << shift
        if not b & 0x80:
            return n, pos
        shift += 7

def rlp_header(base, n):
    if n <= 55:
        return bytes([base + n])
    ln = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([base + 55 + len(ln)]) + ln

def rlp_encode(item):
    if isinstance(item, list):
        body = b"".join(rlp_encode(x) for x in item)
        return rlp_header(0xC0, len(body)) + body
    if len(item) == 1 and item[0] < 0x80:
        return bytes(item)
    return rlp_header(0x80, len(item)) + bytes(item)

def int_to_bytes(n):
    return n.to_bytes((n.bit_length() + 7) // 8, "big")

def pack_tx(t):
    typ = 0 if t[0] >= 0xC0 else t[0]
    layout = LAYOUT[typ]
    body = t if typ == 0 else t[1:]
    fields, end = rlp_item(body)
    if not isinstance(fields, list) or end != len(body) or len(fields) != len(layout):
        raise ValueError("unexpected transaction layout")
    out = bytearray([typ])
    for name, val in zip(layout, fields):
        if name in INT_FIELDS:
            if not isinstance(val, (bytes, bytearray)):
                raise ValueError(f"{name} is not a byte string")
            put_varint(int.from_bytes(val, "big"), out)
        elif name in BYTES_FIELDS:
            if not isinstance(val, (bytes, bytearray)):
                raise ValueError(f"{name} is not a byte string")
            put_varint(len(val), out)
            out += val
        elif name in SIG_FIELDS:
            if not isinstance(val, (bytes, bytearray)) or len(val) > 32:
                raise ValueError(f"bad {name}")
            out += bytes(val).rjust(32, b"\0")
        elif name in LIST_FIELDS:
            if not isinstance(val, list):
                raise ValueError(f"{name} is not a list")
            enc = rlp_encode(val)
            if enc == b"\xc0":
                put_varint(0, out)
            else:
                put_varint(len(enc), out)
                out += enc
        else:
            raise ValueError(f"unhandled field {name}")
    return out

def unpack_tx(buf, pos):
    typ = buf[pos]
    pos += 1
    if typ == ESCAPE:
        ln, pos = get_varint(buf, pos)
        return bytes(buf[pos:pos + ln]), pos + ln
    parts = []
    for name in LAYOUT[typ]:
        if name in INT_FIELDS:
            n, pos = get_varint(buf, pos)
            parts.append(rlp_encode(int_to_bytes(n)))
        elif name in BYTES_FIELDS:
            ln, pos = get_varint(buf, pos)
            parts.append(rlp_encode(bytes(buf[pos:pos + ln])))
            pos += ln
        elif name in SIG_FIELDS:
            parts.append(rlp_encode(bytes(buf[pos:pos + 32]).lstrip(b"\0")))
            pos += 32
        else:
            ln, pos = get_varint(buf, pos)
            if ln == 0:
                parts.append(b"\xc0")
            else:
                parts.append(bytes(buf[pos:pos + ln]))
                pos += ln
    body = b"".join(parts)
    raw = rlp_header(0xC0, len(body)) + body
    if typ != 0:
        raw = bytes([typ]) + raw
    return raw, pos

def pack_tx_safe(t):
    try:
        rec = bytes(pack_tx(t))
        back, _ = unpack_tx(rec, 0)
        if back == t:
            return rec, False
    except Exception:
        pass
    out = bytearray([ESCAPE])
    put_varint(len(t), out)
    out += t
    return bytes(out), True

def unpack_stream(buf):
    n, pos = get_varint(buf, 0)
    txs = []
    for _ in range(n):
        t, pos = unpack_tx(buf, pos)
        txs.append(t)
    if pos != len(buf):
        raise ValueError("trailing bytes after the last record")
    return txs

def walk_l2(msg, txs, depth=0):
    if not msg:
        return
    if msg[0] == 3 and depth < 16:
        pos = 1
        while pos + 8 <= len(msg):
            n = int.from_bytes(msg[pos:pos + 8], "big")
            pos += 8
            if pos + n > len(msg):
                break
            walk_l2(msg[pos:pos + n], txs, depth + 1)
            pos += n
    elif msg[0] == 4:
        txs.append(bytes(msg[1:]))

def extract_raw_txs(raw):
    txs, pos = [], 0
    while pos < len(raw):
        try:
            seg, pos = rlp_item(raw, pos)
        except (ValueError, IndexError):
            break
        if isinstance(seg, list):
            break
        if not seg:
            continue
        if seg[0] in (0, 1):
            body = seg[1:]
            if seg[0] == 1:
                try:
                    body = brotli.decompress(body)
                except brotli.error:
                    continue
            walk_l2(body, txs)
    return txs

def process_batch(folder, args):
    with open(os.path.join(folder, "decompressed.bin"), "rb") as f:
        raw = f.read()
    txs = extract_raw_txs(raw)

    packed = bytearray()
    put_varint(len(txs), packed)
    n_escaped = 0
    for t in txs:
        rec, esc = pack_tx_safe(t)
        packed += rec
        n_escaped += esc
    packed = bytes(packed)

    if unpack_stream(packed) != txs:
        raise RuntimeError("round-trip mismatch: decoded transactions differ from the originals")

    if not args.no_write:
        with open(os.path.join(folder, "varint_packed.bin"), "wb") as f:
            f.write(packed)

    raw_tx = b"".join(txs)
    q = args.quality
    raw_tx_brotli = len(brotli.compress(raw_tx, quality=q))
    packed_brotli = len(brotli.compress(packed, quality=q))

    posted = ""
    mp = os.path.join(folder, "meta.json")
    if os.path.exists(mp):
        with open(mp) as f:
            posted = json.load(f).get("payload_bytes", "")

    return {
        "folder": os.path.basename(folder),
        "status": "ok",
        "n_txs": len(txs),
        "n_escaped": n_escaped,
        "decompressed_bytes": len(raw),
        "posted_payload_bytes": posted,
        "raw_tx_bytes": len(raw_tx),
        "packed_bytes": len(packed),
        "raw_tx_brotli_bytes": raw_tx_brotli,
        "packed_brotli_bytes": packed_brotli,
    }

def pct(before, after):
    return round(100.0 * (1 - after / before), 2) if before else ""

CSV_COLUMNS = ["folder", "status", "n_txs", "n_escaped", "decompressed_bytes", "posted_payload_bytes",
               "raw_tx_bytes", "packed_bytes", "raw_tx_brotli_bytes", "packed_brotli_bytes",
               "uncompressed_saving_pct", "brotli_saving_pct"]

def main():
    ap = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data-dir", default="arbitrum_data")
    ap.add_argument("--quality", type=int, default=11)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--no-write", action="store_true")
    ap.add_argument("--out-csv")
    args = ap.parse_args()

    paths = glob.glob(os.path.join(args.data_dir, "*", "decompressed.bin"))
    folders = sorted(os.path.dirname(p) for p in paths)
    if not folders:
        sys.exit(f"no <folder>/decompressed.bin found under {args.data_dir!r}")
    if args.limit:
        folders = folders[:args.limit]

    rows = []
    for n, folder in enumerate(folders, 1):
        name = os.path.basename(folder)
        try:
            row = process_batch(folder, args)
            row["uncompressed_saving_pct"] = pct(row["raw_tx_bytes"], row["packed_bytes"])
            row["brotli_saving_pct"] = pct(row["raw_tx_brotli_bytes"], row["packed_brotli_bytes"])
        except Exception as e:
            row = {"folder": name, "status": f"error: {e}"}
        rows.append(row)

    ok = [r for r in rows if r["status"] == "ok"]
    if ok:
        total = {"folder": "TOTAL", "status": f"{len(ok)} ok"}
        for k in ("n_txs", "n_escaped", "decompressed_bytes", "raw_tx_bytes", "packed_bytes",
                  "raw_tx_brotli_bytes", "packed_brotli_bytes"):
            total[k] = sum(r[k] for r in ok)
        posted = [r["posted_payload_bytes"] for r in ok if r["posted_payload_bytes"] != ""]
        total["posted_payload_bytes"] = sum(posted) if len(posted) == len(ok) else ""
        total["uncompressed_saving_pct"] = pct(total["raw_tx_bytes"], total["packed_bytes"])
        total["brotli_saving_pct"] = pct(total["raw_tx_brotli_bytes"], total["packed_brotli_bytes"])
        rows.append(total)
        print(f"\nTOTAL over {len(ok)} batches ({total['n_txs']:,} txs):")
        print(f"  uncompressed: {total['raw_tx_bytes']:,} -> {total['packed_bytes']:,} bytes "
              f"({total['uncompressed_saving_pct']}% smaller)")
        print(f"  brotli-{args.quality}:  {total['raw_tx_brotli_bytes']:,} -> "
              f"{total['packed_brotli_bytes']:,} bytes ({total['brotli_saving_pct']}% smaller)")

    out_csv = args.out_csv or os.path.join(args.data_dir, "varint_results.csv")
    with open(out_csv, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        w.writeheader()
        w.writerows(rows)
    print(f"\nresults: {out_csv}")

if __name__ == "__main__":
    main()
