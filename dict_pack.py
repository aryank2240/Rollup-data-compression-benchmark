#!/usr/bin/env python3
import argparse
import csv
import glob
import json
import os
import sys
from collections import Counter

import brotli

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from varint_pack import (LAYOUT, extract_raw_txs, get_varint, int_to_bytes, put_varint,
                         rlp_encode, rlp_header, rlp_item)
from domain_pack import (Ctx as DomainCtx, ESC_TYPE, F_CHAIN, F_LISTS, F_PRIO, F_STRUCT,
                         F_TYPE, F_VALUE, LIST_FIELDS, ZERO12, ZERO32, median_fee,
                         pack_stream as domain_pack_stream, pct, unzigzag, varint_only_stream,
                         zigzag)

ADDR_LEN = 20
SEL_LEN = 4

class Dictionary:
    def __init__(self, addresses, selectors):
        self.addresses = [bytes(a) for a in addresses]
        self.selectors = [bytes(s) for s in selectors]
        self.addr_id = {a: i for i, a in enumerate(self.addresses)}
        self.sel_id = {s: i for i, s in enumerate(self.selectors)}

    def table_bytes(self):
        return ADDR_LEN * len(self.addresses) + SEL_LEN * len(self.selectors)


def varint_len(n):
    k = 1
    while n >= 0x80:
        n >>= 7
        k += 1
    return k


def build_list(counts, raw_len, min_count, max_entries):
    chosen = []
    for key, c in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
        if len(chosen) >= max_entries or c < min_count:
            break
        code_len = varint_len(len(chosen) + 1)
        if c * (raw_len - code_len) <= raw_len:
            break
        chosen.append(key)
    return chosen


def save_dictionary(path, d, trained_on, addr_counts, sel_counts):
    with open(path, "w") as f:
        json.dump({
            "trained_on": trained_on,
            "table_bytes": d.table_bytes(),
            "addresses": ["0x" + a.hex() for a in d.addresses],
            "address_train_counts": [addr_counts[a] for a in d.addresses],
            "selectors": ["0x" + s.hex() for s in d.selectors],
            "selector_train_counts": [sel_counts[s] for s in d.selectors],
        }, f, indent=1)


def load_dictionary(path):
    with open(path) as f:
        j = json.load(f)
    return Dictionary([bytes.fromhex(a[2:]) for a in j["addresses"]],
                      [bytes.fromhex(s[2:]) for s in j["selectors"]])


def to_and_selector(t):
    try:
        typ = 0 if t[0] >= 0xC0 else t[0]
        layout = LAYOUT[typ]
        fields, _ = rlp_item(t if typ == 0 else t[1:])
        to = fields[layout.index("to")]
        data = fields[layout.index("data")]
    except Exception:
        return None, None
    to = bytes(to) if len(to) == ADDR_LEN else None
    sel = bytes(data[:SEL_LEN]) if len(data) >= SEL_LEN else None
    return to, sel


def put_code(table, key, out):
    i = table.get(key)
    if i is None:
        put_varint(0, out)
        out += key
    else:
        put_varint(i + 1, out)


def get_code(buf, pos, entries, raw_len):
    c, pos = get_varint(buf, pos)
    if c == 0:
        return bytes(buf[pos:pos + raw_len]), pos + raw_len
    return entries[c - 1], pos


class Ctx:
    def __init__(self, chain_id, fee_base, dictionary, use_addr, use_sel):
        self.chain_id = chain_id
        self.fee_base = fee_base
        self.dictionary = dictionary
        self.use_addr = use_addr
        self.use_sel = use_sel


def pack_words(rest):
    nw = len(rest) // 32
    tags = bytearray((nw + 3) // 4)
    payload = bytearray()
    for i in range(nw):
        w = rest[32 * i:32 * i + 32]
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
    return bytes(tags) + bytes(payload)


def unpack_words(buf, pos, nw):
    ntag = (nw + 3) // 4
    tags = buf[pos:pos + ntag]
    pos += ntag
    out = bytearray()
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


def pack_calldata(data, body, ctx):
    n = len(data)
    put_varint(n, body)
    if n < SEL_LEN:
        body += data
        return False
    sel = data[:SEL_LEN]
    if ctx.use_sel:
        put_code(ctx.dictionary.sel_id, sel, body)
    else:
        body += sel
    rest = data[SEL_LEN:]
    if n >= 36 and len(rest) % 32 == 0:
        packed = pack_words(rest)
        if len(packed) < len(rest):
            body += packed
            return True
    body += rest
    return False


def unpack_calldata(buf, pos, structured, ctx):
    n, pos = get_varint(buf, pos)
    if n < SEL_LEN:
        return bytes(buf[pos:pos + n]), pos + n
    if ctx.use_sel:
        sel, pos = get_code(buf, pos, ctx.dictionary.selectors, SEL_LEN)
    else:
        sel = bytes(buf[pos:pos + SEL_LEN])
        pos += SEL_LEN
    if structured:
        rest, pos = unpack_words(buf, pos, (n - SEL_LEN) // 32)
    else:
        rest = bytes(buf[pos:pos + n - SEL_LEN])
        pos += n - SEL_LEN
    return sel + rest, pos


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
            if len(val) != ADDR_LEN:
                raise ValueError("`to` is not a 20-byte address")
            if ctx.use_addr:
                put_code(ctx.dictionary.addr_id, bytes(val), body)
            else:
                body += val
        elif name == "value":
            n = int.from_bytes(val, "big")
            if n == 0:
                flags |= F_VALUE
            else:
                put_varint(n, body)
        elif name == "data":
            if pack_calldata(bytes(val), body, ctx):
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
            if ctx.use_addr:
                addr, pos = get_code(buf, pos, ctx.dictionary.addresses, ADDR_LEN)
            else:
                addr = bytes(buf[pos:pos + ADDR_LEN])
                pos += ADDR_LEN
            parts.append(rlp_encode(addr))
        elif name == "value":
            if tag & F_VALUE:
                n = 0
            else:
                n, pos = get_varint(buf, pos)
            parts.append(rlp_encode(int_to_bytes(n)))
        elif name == "data":
            data, pos = unpack_calldata(buf, pos, bool(tag & F_STRUCT), ctx)
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
    out.append((1 if ctx.use_addr else 0) | (2 if ctx.use_sel else 0))
    n_escaped = 0
    for t in txs:
        rec, esc = pack_tx_safe(t, ctx)
        out += rec
        n_escaped += esc
    return bytes(out), n_escaped


def unpack_stream(buf, dictionary):
    n, pos = get_varint(buf, 0)
    chain_id, pos = get_varint(buf, pos)
    fb, pos = get_varint(buf, pos)
    dflags = buf[pos]
    pos += 1
    ctx = Ctx(chain_id, None if fb == 0 else fb - 1, dictionary, bool(dflags & 1), bool(dflags & 2))
    txs = []
    for _ in range(n):
        t, pos = unpack_tx(buf, pos, ctx)
        txs.append(t)
    if pos != len(buf):
        raise ValueError("trailing bytes after the last record")
    return txs


def load_batch(folder):
    with open(os.path.join(folder, "decompressed.bin"), "rb") as f:
        raw = f.read()
    return extract_raw_txs(raw), len(raw)


def sort_key(folder):
    name = os.path.basename(folder)
    head = name.split("_")[0]
    return (0, int(head), name) if head.isdigit() else (1, 0, name)


def pick_fee_base(txs, args):
    def dom(fb):
        return domain_pack_stream(txs, DomainCtx(args.chain_id, fb, True))[0]

    base = median_fee(txs)
    if args.fee_mode == "raw" or base is None:
        return None, dom(None)
    if args.fee_mode == "delta":
        return base, dom(base)
    with_delta, without = dom(base), dom(None)
    return (base, with_delta) if len(with_delta) < len(without) else (None, without)


def hit_counts(txs, dictionary):
    ah = at = sh = st = 0
    for t in txs:
        to, sel = to_and_selector(t)
        if to is not None:
            at += 1
            ah += to in dictionary.addr_id
        if sel is not None:
            st += 1
            sh += sel in dictionary.sel_id
    return ah, at, sh, st


def ratio_pct(hits, total):
    return round(100.0 * hits / total, 2) if total else ""


def evaluate(folder, dictionary, args, in_sample):
    txs, raw_len = load_batch(folder)
    fee_base, domain_stream = pick_fee_base(txs, args)

    def build(use_addr, use_sel):
        stream, esc = pack_stream(txs, Ctx(args.chain_id, fee_base, dictionary, use_addr, use_sel))
        if unpack_stream(stream, dictionary) != txs:
            raise RuntimeError("round-trip mismatch: decoded transactions differ from the originals")
        return stream, esc

    dict_stream, n_escaped = build(True, True)
    variants = {"varint_only": varint_only_stream(txs), "domain": domain_stream, "dict": dict_stream}
    if args.ablation:
        variants["dict_addr_only"] = build(True, False)[0]
        variants["dict_sel_only"] = build(False, True)[0]

    if not args.no_write:
        with open(os.path.join(folder, "dict_packed.bin"), "wb") as f:
            f.write(dict_stream)

    q = args.quality
    raw_tx = b"".join(txs)
    ah, at, sh, st = hit_counts(txs, dictionary)
    row = {
        "folder": os.path.basename(folder),
        "status": "ok",
        "in_sample": "yes" if in_sample else "no",
        "n_txs": len(txs),
        "n_escaped": n_escaped,
        "fee_base": "" if fee_base is None else fee_base,
        "addr_hits": ah, "addr_total": at, "addr_hit_pct": ratio_pct(ah, at),
        "sel_hits": sh, "sel_total": st, "sel_hit_pct": ratio_pct(sh, st),
        "decompressed_bytes": raw_len,
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
    ap.add_argument("--train-frac", type=float, default=0.5)
    ap.add_argument("--min-count", type=int, default=3)
    ap.add_argument("--max-addresses", type=int, default=4096)
    ap.add_argument("--max-selectors", type=int, default=1024)
    ap.add_argument("--ablation", action="store_true")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--no-write", action="store_true")
    ap.add_argument("--dict-file")
    ap.add_argument("--out-csv")
    args = ap.parse_args()

    paths = glob.glob(os.path.join(args.data_dir, "*", "decompressed.bin"))
    folders = sorted((os.path.dirname(p) for p in paths), key=sort_key)
    if not folders:
        sys.exit(f"no <folder>/decompressed.bin found under {args.data_dir!r}")
    if args.limit:
        folders = folders[:args.limit]

    if len(folders) == 1:
        train = test = folders
    else:
        k = min(len(folders) - 1, max(1, int(round(len(folders) * args.train_frac))))
        train, test = folders[:k], folders[k:]
    in_sample = train is test

    addr_counts, sel_counts = Counter(), Counter()
    for folder in train:
        txs, _ = load_batch(folder)
        for t in txs:
            to, sel = to_and_selector(t)
            if to is not None:
                addr_counts[to] += 1
            if sel is not None:
                sel_counts[sel] += 1

    dictionary = Dictionary(
        build_list(addr_counts, ADDR_LEN, args.min_count, args.max_addresses),
        build_list(sel_counts, SEL_LEN, args.min_count, args.max_selectors))
    table = dictionary.table_bytes()
    dict_path = args.dict_file or os.path.join(args.data_dir, "dictionary.json")
    save_dictionary(dict_path, dictionary, [os.path.basename(f) for f in train], addr_counts, sel_counts)

    rows, variant_names = [], ["varint_only", "domain", "dict"]
    for n, folder in enumerate(test, 1):
        name = os.path.basename(folder)
        try:
            row, variant_names = evaluate(folder, dictionary, args, in_sample)
            add_pcts(row, variant_names)
        except Exception as e:
            row = {"folder": name, "status": f"error: {e}"}
        rows.append(row)

    ok = [r for r in rows if r["status"] == "ok"]
    if ok:
        total = {"folder": "TOTAL", "status": f"{len(ok)} ok", "in_sample": "yes" if in_sample else "no",
                 "fee_base": ""}
        sum_keys = ["n_txs", "n_escaped", "addr_hits", "addr_total", "sel_hits", "sel_total",
                    "decompressed_bytes", "raw_tx_bytes", "raw_tx_brotli_bytes"]
        for v in variant_names:
            sum_keys += [f"{v}_bytes", f"{v}_brotli_bytes"]
        for k in sum_keys:
            total[k] = sum(r[k] for r in ok)
        total["addr_hit_pct"] = ratio_pct(total["addr_hits"], total["addr_total"])
        total["sel_hit_pct"] = ratio_pct(total["sel_hits"], total["sel_total"])
        posted = [r["posted_payload_bytes"] for r in ok if r["posted_payload_bytes"] != ""]
        total["posted_payload_bytes"] = sum(posted) if len(posted) == len(ok) else ""
        add_pcts(total, variant_names)
        total["dictionary_table_bytes"] = table
        total["dict_brotli_plus_table_bytes"] = total["dict_brotli_bytes"] + table
        total["dict_plus_table_saving_vs_raw_brotli_pct"] = pct(total["raw_tx_brotli_bytes"],
                                                                total["dict_brotli_plus_table_bytes"])
        total["dict_plus_table_saving_vs_domain_brotli_pct"] = pct(total["domain_brotli_bytes"],
                                                                   total["dict_brotli_plus_table_bytes"])
        rows.append(total)

        print(f"\nTOTAL over {len(ok)} held-out batches ({total['n_txs']:,} txs, {total['n_escaped']:,} escaped):")
        print(f"  address hit rate {total['addr_hit_pct']}% | selector hit rate {total['sel_hit_pct']}%")
        print(f"  {'':22s}{'uncompressed':>14s}  {'brotli-' + str(args.quality):>12s}")
        print(f"  {'raw RLP txs':22s}{total['raw_tx_bytes']:>14,}  {total['raw_tx_brotli_bytes']:>12,}")
        for v in variant_names:
            print(f"  {v:22s}{total[v + '_bytes']:>14,}  {total[v + '_brotli_bytes']:>12,}  "
                  f"({total[v + '_brotli_saving_pct']}% smaller than raw after brotli)")
        print(f"\n  dictionary table: {table:,} bytes, shipped/known once and reused by every batch")
        print(f"  dict + table (brotli): {total['dict_brotli_plus_table_bytes']:,} bytes -> "
              f"{total['dict_plus_table_saving_vs_domain_brotli_pct']}% vs domain-only, "
              f"{total['dict_plus_table_saving_vs_raw_brotli_pct']}% vs raw")

    fieldnames = []
    for r in rows:
        for k in r:
            if k not in fieldnames:
                fieldnames.append(k)
    out_csv = args.out_csv or os.path.join(args.data_dir, "dict_results.csv")
    with open(out_csv, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, restval="")
        w.writeheader()
        w.writerows(rows)
    print(f"\nresults: {out_csv}")


if __name__ == "__main__":
    main()
