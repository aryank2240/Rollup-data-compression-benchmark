#!/usr/bin/env python3
import argparse
import csv
import glob
import json
import os
import sys

import brotli

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from varint_pack import (LAYOUT, extract_raw_txs, get_varint, int_to_bytes,
                         pack_tx_safe as varint_pack_tx_safe, put_varint, rlp_encode,
                         rlp_header, rlp_item)

F_TYPE = 0x07
F_VALUE = 0x08
F_CHAIN = 0x10
F_LISTS = 0x20
F_PRIO = 0x40
F_STRUCT = 0x80
ESC_TYPE = 0x07

LIST_FIELDS = {"access_list", "auth_list"}
ZERO12 = bytes(12)
ZERO32 = bytes(32)


class Ctx:
    def __init__(self, chain_id, fee_base=None, use_calldata=True):
        self.chain_id = chain_id
        self.fee_base = fee_base
        self.use_calldata = use_calldata


def zigzag(d):
    return d << 1 if d >= 0 else ((-d) << 1) - 1


def unzigzag(z):
    return z >> 1 if not z & 1 else -((z + 1) >> 1)


def pack_calldata(data, body, use_struct):
    n = len(data)
    raw_rec = bytearray()
    put_varint(n, raw_rec)
    raw_rec += data
    if use_struct and n >= 36 and (n - 4) % 32 == 0:
        nw = (n - 4) // 32
        tags = bytearray((nw + 3) // 4)
        payload = bytearray()
        for i in range(nw):
            w = data[4 + 32 * i:36 + 32 * i]
            if w == ZERO32:
                tag = 0
            else:
                v = int.from_bytes(w, "big")
                if v < (1 << 64):
                    tag = 1
                    put_varint(v, payload)
                elif w[:12] == ZERO12:
                    tag = 2
                    payload += w[12:]
                else:
                    tag = 3
                    payload += w
            tags[i // 4] |= tag << (2 * (i % 4))
        rec = bytearray()
        put_varint(n, rec)
        rec += data[:4]
        rec += tags
        rec += payload
        if len(rec) < len(raw_rec):
            body += rec
            return True
    body += raw_rec
    return False


def unpack_calldata(buf, pos, structured):
    n, pos = get_varint(buf, pos)
    if not structured:
        return bytes(buf[pos:pos + n]), pos + n
    selector = bytes(buf[pos:pos + 4])
    pos += 4
    nw = (n - 4) // 32
    ntag = (nw + 3) // 4
    tags = buf[pos:pos + ntag]
    pos += ntag
    out = bytearray(selector)
    for i in range(nw):
        tag = (tags[i // 4] >> (2 * (i % 4))) & 3
        if tag == 0:
            out += ZERO32
        elif tag == 1:
            v, pos = get_varint(buf, pos)
            out += v.to_bytes(32, "big")
        elif tag == 2:
            out += ZERO12 + bytes(buf[pos:pos + 20])
            pos += 20
        else:
            out += bytes(buf[pos:pos + 32])
            pos += 32
    return bytes(out), pos


def pack_tx(t, ctx):
    typ = 0 if t[0] >= 0xC0 else t[0]
    layout = LAYOUT[typ]
    body_in = t if typ == 0 else t[1:]
    fields, end = rlp_item(body_in)
    if not isinstance(fields, list) or end != len(body_in) or len(fields) != len(layout):
        raise ValueError("unexpected transaction layout")
    rec = dict(zip(layout, fields))
    for name, val in rec.items():
        if name in LIST_FIELDS:
            if not isinstance(val, list):
                raise ValueError(f"{name} is not a list")
        elif not isinstance(val, (bytes, bytearray)):
            raise ValueError(f"{name} is not a byte string")

    flags = typ
    list_names = [n for n in layout if n in LIST_FIELDS]
    if list_names and all(rlp_encode(rec[n]) == b"\xc0" for n in list_names):
        flags |= F_LISTS

    body = bytearray()
    for name in layout:
        val = rec[name]
        if name == "chain_id":
            n = int.from_bytes(val, "big")
            if n == ctx.chain_id:
                flags |= F_CHAIN
            else:
                put_varint(n, body)
        elif name in ("nonce", "gas", "v"):
            put_varint(int.from_bytes(val, "big"), body)
        elif name in ("gas_price", "max_fee"):
            n = int.from_bytes(val, "big")
            put_varint(n if ctx.fee_base is None else zigzag(n - ctx.fee_base), body)
        elif name == "max_priority_fee":
            n = int.from_bytes(val, "big")
            if n == 0:
                flags |= F_PRIO
            else:
                put_varint(n, body)
        elif name == "to":
            if len(val) != 20:
                raise ValueError("`to` is not a 20-byte address")
            body += val
        elif name == "value":
            n = int.from_bytes(val, "big")
            if n == 0:
                flags |= F_VALUE
            else:
                put_varint(n, body)
        elif name == "data":
            if pack_calldata(bytes(val), body, ctx.use_calldata):
                flags |= F_STRUCT
        elif name in ("r", "s"):
            if len(val) > 32:
                raise ValueError(f"{name} longer than 32 bytes")
            body += bytes(val).rjust(32, b"\0")
        elif name in LIST_FIELDS:
            if not flags & F_LISTS:
                enc = rlp_encode(val)
                if enc == b"\xc0":
                    put_varint(0, body)
                else:
                    put_varint(len(enc), body)
                    body += enc
        else:
            raise ValueError(f"unhandled field {name}")
    return bytes([flags]) + bytes(body)


def unpack_tx(buf, pos, ctx):
    tag = buf[pos]
    pos += 1
    typ = tag & F_TYPE
    if typ == ESC_TYPE:
        ln, pos = get_varint(buf, pos)
        return bytes(buf[pos:pos + ln]), pos + ln
    parts = []
    for name in LAYOUT[typ]:
        if name == "chain_id":
            if tag & F_CHAIN:
                n = ctx.chain_id
            else:
                n, pos = get_varint(buf, pos)
            parts.append(rlp_encode(int_to_bytes(n)))
        elif name in ("nonce", "gas", "v"):
            n, pos = get_varint(buf, pos)
            parts.append(rlp_encode(int_to_bytes(n)))
        elif name in ("gas_price", "max_fee"):
            z, pos = get_varint(buf, pos)
            n = z if ctx.fee_base is None else ctx.fee_base + unzigzag(z)
            parts.append(rlp_encode(int_to_bytes(n)))
        elif name == "max_priority_fee":
            if tag & F_PRIO:
                n = 0
            else:
                n, pos = get_varint(buf, pos)
            parts.append(rlp_encode(int_to_bytes(n)))
        elif name == "to":
            parts.append(rlp_encode(bytes(buf[pos:pos + 20])))
            pos += 20
        elif name == "value":
            if tag & F_VALUE:
                n = 0
            else:
                n, pos = get_varint(buf, pos)
            parts.append(rlp_encode(int_to_bytes(n)))
        elif name == "data":
            data, pos = unpack_calldata(buf, pos, bool(tag & F_STRUCT))
            parts.append(rlp_encode(data))
        elif name in ("r", "s"):
            parts.append(rlp_encode(bytes(buf[pos:pos + 32]).lstrip(b"\0")))
            pos += 32
        else:
            if tag & F_LISTS:
                parts.append(b"\xc0")
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


def pack_tx_safe(t, ctx):
    try:
        rec = pack_tx(t, ctx)
        back, _ = unpack_tx(rec, 0, ctx)
        if back == t:
            return rec, False
    except Exception:
        pass
    out = bytearray([ESC_TYPE])
    put_varint(len(t), out)
    out += t
    return bytes(out), True


def pack_stream(txs, ctx):
    out = bytearray()
    put_varint(len(txs), out)
    put_varint(ctx.chain_id, out)
    put_varint(0 if ctx.fee_base is None else ctx.fee_base + 1, out)
    n_escaped = 0
    for t in txs:
        rec, esc = pack_tx_safe(t, ctx)
        out += rec
        n_escaped += esc
    return bytes(out), n_escaped


def unpack_stream(buf):
    n, pos = get_varint(buf, 0)
    chain_id, pos = get_varint(buf, pos)
    fb, pos = get_varint(buf, pos)
    ctx = Ctx(chain_id, None if fb == 0 else fb - 1)
    txs = []
    for _ in range(n):
        t, pos = unpack_tx(buf, pos, ctx)
        txs.append(t)
    if pos != len(buf):
        raise ValueError("trailing bytes after the last record")
    return txs


def varint_only_stream(txs):
    out = bytearray()
    put_varint(len(txs), out)
    for t in txs:
        rec, _ = varint_pack_tx_safe(t)
        out += rec
    return bytes(out)


def fee_value(t):
    try:
        typ = 0 if t[0] >= 0xC0 else t[0]
        layout = LAYOUT[typ]
        fields, _ = rlp_item(t if typ == 0 else t[1:])
        name = "max_fee" if "max_fee" in layout else "gas_price"
        return int.from_bytes(fields[layout.index(name)], "big")
    except Exception:
        return None


def median_fee(txs):
    fees = sorted(f for f in (fee_value(t) for t in txs) if f is not None)
    return fees[len(fees) // 2] if fees else None


def pct(before, after):
    return round(100.0 * (1 - after / before), 2) if before else ""


def process_batch(folder, args):
    with open(os.path.join(folder, "decompressed.bin"), "rb") as f:
        raw = f.read()
    txs = extract_raw_txs(raw)

    cache = {}

    def get_stream(use_calldata, fee_base):
        key = (use_calldata, fee_base)
        if key not in cache:
            cache[key] = pack_stream(txs, Ctx(args.chain_id, fee_base, use_calldata))
        return cache[key]

    base = median_fee(txs)
    if args.fee_mode == "raw" or base is None:
        fee_base = None
    elif args.fee_mode == "delta":
        fee_base = base
    else:
        fee_base = base if len(get_stream(True, base)[0]) < len(get_stream(True, None)[0]) else None
    domain, n_escaped = get_stream(True, fee_base)

    if unpack_stream(domain) != txs:
        raise RuntimeError("round-trip mismatch: decoded transactions differ from the originals")

    if not args.no_write:
        with open(os.path.join(folder, "domain_packed.bin"), "wb") as f:
            f.write(domain)

    variants = {"varint_only": varint_only_stream(txs), "domain": domain}
    if args.ablation:
        variants["domain_flags_only"] = get_stream(False, None)[0]
        variants["domain_calldata_no_fee"] = get_stream(True, None)[0]

    q = args.quality
    raw_tx = b"".join(txs)
    row = {
        "folder": os.path.basename(folder),
        "status": "ok",
        "n_txs": len(txs),
        "n_escaped": n_escaped,
        "fee_base": "" if fee_base is None else fee_base,
        "decompressed_bytes": len(raw),
        "posted_payload_bytes": "",
        "raw_tx_bytes": len(raw_tx),
        "raw_tx_brotli_bytes": len(brotli.compress(raw_tx, quality=q)),
    }
    mp = os.path.join(folder, "meta.json")
    if os.path.exists(mp):
        with open(mp) as f:
            row["posted_payload_bytes"] = json.load(f).get("payload_bytes", "")
    for name, stream in variants.items():
        row[f"{name}_bytes"] = len(stream)
        row[f"{name}_brotli_bytes"] = len(brotli.compress(stream, quality=q))
    return row, list(variants)


def add_pcts(row, variant_names):
    for name in variant_names:
        row[f"{name}_saving_pct"] = pct(row["raw_tx_bytes"], row[f"{name}_bytes"])
        row[f"{name}_brotli_saving_pct"] = pct(row["raw_tx_brotli_bytes"], row[f"{name}_brotli_bytes"])


def main():
    ap = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data-dir", default="arbitrum_data")
    ap.add_argument("--quality", type=int, default=11)
    ap.add_argument("--chain-id", type=int, default=42161)
    ap.add_argument("--fee-mode", choices=["auto", "raw", "delta"], default="auto")
    ap.add_argument("--ablation", action="store_true")
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

    rows, variant_names = [], ["varint_only", "domain"]
    for n, folder in enumerate(folders, 1):
        name = os.path.basename(folder)
        try:
            row, variant_names = process_batch(folder, args)
            add_pcts(row, variant_names)
        except Exception as e:
            row = {"folder": name, "status": f"error: {e}"}
        rows.append(row)

    ok = [r for r in rows if r["status"] == "ok"]
    if ok:
        total = {"folder": "TOTAL", "status": f"{len(ok)} ok", "fee_base": ""}
        sum_keys = ["n_txs", "n_escaped", "decompressed_bytes", "raw_tx_bytes", "raw_tx_brotli_bytes"]
        for v in variant_names:
            sum_keys += [f"{v}_bytes", f"{v}_brotli_bytes"]
        for k in sum_keys:
            total[k] = sum(r[k] for r in ok)
        posted = [r["posted_payload_bytes"] for r in ok if r["posted_payload_bytes"] != ""]
        total["posted_payload_bytes"] = sum(posted) if len(posted) == len(ok) else ""
        add_pcts(total, variant_names)
        rows.append(total)
        print(f"\nTOTAL over {len(ok)} batches ({total['n_txs']:,} txs, {total['n_escaped']:,} escaped):")
        print(f"  {'':22s}{'uncompressed':>14s}  {'brotli-' + str(args.quality):>12s}")
        print(f"  {'raw RLP txs':22s}{total['raw_tx_bytes']:>14,}  {total['raw_tx_brotli_bytes']:>12,}")
        for v in variant_names:
            print(f"  {v:22s}{total[v + '_bytes']:>14,}  {total[v + '_brotli_bytes']:>12,}  "
                  f"({total[v + '_brotli_saving_pct']}% smaller after brotli)")

    fieldnames = []
    for r in rows:
        for k in r:
            if k not in fieldnames:
                fieldnames.append(k)
    out_csv = args.out_csv or os.path.join(args.data_dir, "domain_results.csv")
    with open(out_csv, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, restval="")
        w.writeheader()
        w.writerows(rows)
    print(f"\nresults: {out_csv}")


if __name__ == "__main__":
    main()
