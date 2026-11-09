#!/usr/bin/env python3
import argparse
import glob
import os
import sys
from argparse import Namespace
from collections import Counter

import brotli

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dict_pack as dp
from domain_pack import ZERO12, ZERO32
from varint_pack import get_varint, put_varint

try:
    import zstandard as zstd
except ImportError:
    zstd = None

STATE = {"index": {}, "list": [], "seen": set(), "inbatch_raw": True, "hits": 0, "cand": 0}
ORIG_PACK, ORIG_UNPACK = dp.pack_words, dp.unpack_words

def pack_words_cached(rest):
    nw = len(rest) // 32
    tags = bytearray((nw + 3) // 4)
    payload = bytearray()
    flags = []
    for i in range(nw):
        w = rest[32 * i:32 * i + 32]
        if w == ZERO32:
            tag = 0
        else:
            v = int.from_bytes(w, "big")
            if v < (1 << 64):
                tag = 1
                put_varint(v, payload)
            else:
                tag = 2 if w[:12] == ZERO12 else 3
                idx = STATE["index"].get(w)
                STATE["cand"] += 1
                if idx is not None and not (STATE["inbatch_raw"] and w in STATE["seen"]):
                    flags.append(1)
                    put_varint(idx, payload)
                    STATE["hits"] += 1
                else:
                    flags.append(0)
                    payload += w[12:] if tag == 2 else w
                STATE["seen"].add(w)
        tags[i // 4] |= tag << (2 * (i % 4))
    bitmap = bytearray((len(flags) + 7) // 8)
    for j, f in enumerate(flags):
        if f:
            bitmap[j // 8] |= 1 << (j % 8)
    return bytes(tags) + bytes(bitmap) + bytes(payload)

def unpack_words_cached(buf, pos, nw):
    ntag = (nw + 3) // 4
    tags = buf[pos:pos + ntag]
    pos += ntag
    classes = [(tags[i // 4] >> (2 * (i % 4))) & 3 for i in range(nw)]
    n23 = sum(1 for c in classes if c >= 2)
    nb = (n23 + 7) // 8
    bitmap = buf[pos:pos + nb]
    pos += nb
    out = bytearray()
    j = 0
    for c in classes:
        if c == 0:
            out += ZERO32
        elif c == 1:
            v, pos = get_varint(buf, pos)
            out += v.to_bytes(32, "big")
        else:
            hit = (bitmap[j // 8] >> (j % 8)) & 1
            j += 1
            if hit:
                idx, pos = get_varint(buf, pos)
                out += STATE["list"][idx]
            elif c == 2:
                out += ZERO12 + bytes(buf[pos:pos + 20])
                pos += 20
            else:
                out += bytes(buf[pos:pos + 32])
                pos += 32
    return bytes(out), pos

def calldata_of(t):
    try:
        typ = 0 if t[0] >= 0xC0 else t[0]
        layout = dp.LAYOUT[typ]
        fields, _ = dp.rlp_item(t if typ == 0 else t[1:])
        return bytes(fields[layout.index("data")])
    except Exception:
        return b""

def tracked_words(txs):
    seen, out = set(), []
    for t in txs:
        d = calldata_of(t)
        if len(d) >= 36 and (len(d) - 4) % 32 == 0:
            for k in range(4, len(d), 32):
                w = d[k:k + 32]
                if w[:24] != bytes(24) and w not in seen:
                    seen.add(w)
                    out.append(w)
    return out

def build_cache(batch_words, i, k, cap):
    seen, lst = set(), []
    for j in range(i - 1, max(-1, i - k - 1), -1):
        for w in batch_words[j]:
            if w not in seen:
                seen.add(w)
                lst.append(w)
                if len(lst) >= cap:
                    return lst
    return lst

def main():
    ap = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data-dir", default="arbitrum_data")
    ap.add_argument("--train-frac", type=float, default=0.7)
    ap.add_argument("--windows", type=int, nargs="+", default=[1, 5, 20])
    ap.add_argument("--max-entries", type=int, default=65536)
    ap.add_argument("--quality", type=int, default=11)
    ap.add_argument("--chain-id", type=int, default=42161)
    ap.add_argument("--min-count", type=int, default=3)
    ap.add_argument("--max-addresses", type=int, default=4096)
    ap.add_argument("--max-selectors", type=int, default=1024)
    ap.add_argument("--zstd-prev", type=int, default=1)
    ap.add_argument("--zstd-level", type=int, default=19)
    ap.add_argument("--keep-inbatch", action="store_true")
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()
    STATE["inbatch_raw"] = not args.keep_inbatch

    folders = sorted((os.path.dirname(p) for p in
                      glob.glob(os.path.join(args.data_dir, "*", "decompressed.bin"))), key=dp.sort_key)
    if args.limit:
        folders = folders[:args.limit]
    if len(folders) < 3:
        sys.exit("need several batches")
    k = min(len(folders) - 1, max(1, int(round(len(folders) * args.train_frac))))

    addr_c, sel_c, batch_words = Counter(), Counter(), []
    for n, folder in enumerate(folders):
        txs, _ = dp.load_batch(folder)
        batch_words.append(tracked_words(txs))
        if n < k:
            for t in txs:
                to, sel = dp.to_and_selector(t)
                if to is not None:
                    addr_c[to] += 1
                if sel is not None:
                    sel_c[sel] += 1

    dictionary = dp.Dictionary(dp.build_list(addr_c, dp.ADDR_LEN, args.min_count, args.max_addresses),
                               dp.build_list(sel_c, dp.SEL_LEN, args.min_count, args.max_selectors))
    table = dictionary.table_bytes()

    def bro(b):
        return len(brotli.compress(bytes(b), quality=args.quality))

    use_zstd = zstd is not None and args.zstd_prev > 0
    ns = Namespace(chain_id=args.chain_id, fee_mode="auto")
    tot = Counter()
    hit = {w: [0, 0] for w in args.windows}
    cache_sizes = {w: 0 for w in args.windows}

    test_idx = list(range(k, len(folders)))
    for n, i in enumerate(test_idx, 1):
        txs, _ = dp.load_batch(folders[i])
        raw = b"".join(txs)
        fee_base, _ = dp.pick_fee_base(txs, ns)
        ctx = dp.Ctx(args.chain_id, fee_base, dictionary, True, True)

        tot["raw_bytes"] += len(raw)
        tot["raw_brotli"] += bro(raw)
        dp.pack_words, dp.unpack_words = ORIG_PACK, ORIG_UNPACK
        tot["dict_brotli"] += bro(dp.pack_stream(txs, ctx)[0])

        for w in args.windows:
            lst = build_cache(batch_words, i, w, args.max_entries)
            STATE.update(list=lst, index={x: j for j, x in enumerate(lst)}, seen=set(), hits=0, cand=0)
            dp.pack_words, dp.unpack_words = pack_words_cached, unpack_words_cached
            stream, _ = dp.pack_stream(txs, ctx)
            if dp.unpack_stream(stream, dictionary) != txs:
                raise RuntimeError(f"round-trip mismatch (batch {folders[i]}, window {w})")
            dp.pack_words, dp.unpack_words = ORIG_PACK, ORIG_UNPACK
            tot[f"cache{w}_brotli"] += bro(stream)
            hit[w][0] += STATE["hits"]
            hit[w][1] += STATE["cand"]
            cache_sizes[w] += len(lst)

        if use_zstd:
            prev = b"".join(b"".join(dp.load_batch(folders[j])[0])
                            for j in range(max(0, i - args.zstd_prev), i))
            zc = zstd.ZstdCompressor(level=args.zstd_level, dict_data=zstd.ZstdCompressionDict(prev))
            tot["zstd_prev"] += len(zc.compress(raw))

    base = tot["raw_brotli"]
    pc = lambda x: f"{100 * (1 - x / base):6.2f}%"
    print(f"\nTOTAL over {len(test_idx)} held-out batches (raw txs {tot['raw_bytes']:,} B, brotli-{args.quality}):")
    print(f"  {'method':40s}{'bytes':>14s}  vs raw brotli")
    print(f"  {'raw txs + brotli':40s}{base:>14,}  {pc(base)}")
    d = tot["dict_brotli"] + table
    print(f"  {'dict_pack + brotli (+ table)':40s}{d:>14,}  {pc(d)}")
    for w in args.windows:
        c = tot[f"cache{w}_brotli"] + table
        h, cand = hit[w]
        print(f"  {f'dict_pack + cache(last {w}) + brotli':40s}{c:>14,}  {pc(c)}   "
              f"[hit rate {100 * h / max(1, cand):.1f}% of words >= 2^64, avg cache "
              f"{cache_sizes[w] // len(test_idx):,} words, {100 * (1 - c / d):.2f}% vs dict_pack]")
    if use_zstd:
        z = tot["zstd_prev"]
        print(f"  {f'raw txs + zstd, previous {args.zstd_prev} batch(es)':40s}{z:>14,}  {pc(z)}")

if __name__ == "__main__":
    main()
