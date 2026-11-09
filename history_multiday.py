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

try:
    import zstandard as zstd
except ImportError:
    zstd = None

BROTLI_LIMIT = (1 << 24) - 16


def main():
    ap = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data-dir", default="arbitrum_data_days")
    ap.add_argument("--windows", type=int, nargs="+", default=[1, 3, 6, 10])
    ap.add_argument("--train-segments", type=int, default=2)
    ap.add_argument("--per-segment", type=int, default=10)
    ap.add_argument("--gap-blocks", type=int, default=300)
    ap.add_argument("--quality", type=int, default=11)
    ap.add_argument("--zstd-level", type=int, default=19)
    ap.add_argument("--chain-id", type=int, default=42161)
    ap.add_argument("--min-count", type=int, default=3)
    ap.add_argument("--zstd-only", action="store_true")
    ap.add_argument("--max-addresses", type=int, default=4096)
    ap.add_argument("--max-selectors", type=int, default=1024)
    args = ap.parse_args()
    q = args.quality
    windows = sorted(set(args.windows))
    maxw = windows[-1]
    use_zstd = zstd is not None

    folders = sorted((os.path.dirname(p) for p in
                      glob.glob(os.path.join(args.data_dir, "*", "decompressed.bin"))), key=dp.sort_key)
    folders = [f for f in folders if os.path.basename(f).split("_")[0].isdigit()]
    if not folders:
        sys.exit("no numbered batch folders found")
    blocks = [int(os.path.basename(f).split("_")[0]) for f in folders]
    segs, cur = [], [0]
    for i in range(1, len(folders)):
        if blocks[i] - blocks[i - 1] > args.gap_blocks:
            segs.append(cur)
            cur = []
        cur.append(i)
    segs.append(cur)
    if len(segs) <= args.train_segments:
        sys.exit("need more segments than --train-segments")

    train_idx = [i for s in segs[:args.train_segments] for i in s]
    addr_c, sel_c = Counter(), Counter()
    for n, i in enumerate(train_idx, 1):
        for t in dp.load_batch(folders[i])[0]:
            to, sel = dp.to_and_selector(t)
            if to is not None:
                addr_c[to] += 1
            if sel is not None:
                sel_c[sel] += 1
    dictionary = dp.Dictionary(dp.build_list(addr_c, dp.ADDR_LEN, args.min_count, args.max_addresses),
                               dp.build_list(sel_c, dp.SEL_LEN, args.min_count, args.max_selectors))
    table = dictionary.table_bytes()

    eval_list = []
    for si in range(args.train_segments, len(segs)):
        picked = segs[si][maxw:maxw + args.per_segment]
        eval_list += [(si, i) for i in picked]
    if not eval_list:
        sys.exit("nothing to evaluate")

    ns = Namespace(chain_id=args.chain_id, fee_mode="auto")
    cache = {"txs": {}, "raw": {}, "pack": {}}

    def get_txs(i):
        if i not in cache["txs"]:
            cache["txs"][i] = dp.load_batch(folders[i])[0]
        return cache["txs"][i]

    def get_raw(i):
        if i not in cache["raw"]:
            cache["raw"][i] = b"".join(get_txs(i))
        return cache["raw"][i]

    def get_packed(i):
        if i not in cache["pack"]:
            txs = get_txs(i)
            fee_base, _ = dp.pick_fee_base(txs, ns)
            cache["pack"][i] = dp.pack_stream(txs, dp.Ctx(args.chain_id, fee_base, dictionary, True, True))[0]
        return cache["pack"][i]

    def evict(i):
        for c in cache.values():
            for j in [j for j in c if j < i - maxw]:
                del c[j]

    def bro(b):
        return len(brotli.compress(b, quality=q))

    def bro_hist(prev, cur):
        if len(prev) + len(cur) > BROTLI_LIMIT:
            return None
        both = len(brotli.compress(prev + cur, quality=q, lgwin=24))
        return both - len(brotli.compress(prev, quality=q, lgwin=24))

    zparams = (zstd.ZstdCompressionParameters.from_level(args.zstd_level, window_log=27)
               if use_zstd else None)

    def zstd_hist(prev, cur):
        d = zstd.ZstdCompressionDict(prev, dict_type=zstd.DICT_TYPE_RAWCONTENT)
        return len(zstd.ZstdCompressor(dict_data=d, compression_params=zparams).compress(cur))

    tot, seg_cnt, na = Counter(), {}, set()
    for n, (si, i) in enumerate(eval_list, 1):
        raw, packed = get_raw(i), get_packed(i)
        ah, at, sh, st = dp.hit_counts(get_txs(i), dictionary)
        m = {"raw_bytes": len(raw), "raw_brotli": bro(raw), "packed_brotli": bro(packed),
             "ah": ah, "at": at, "sh": sh, "st": st, "n": 1}
        for w in windows:
            prev_raw = b"".join(get_raw(j) for j in range(i - w, i))
            prev_pack = b"".join(get_packed(j) for j in range(i - w, i))

            if args.zstd_only:
                m[f"raw_brotli_h{w}"] = m[f"packed_brotli_h{w}"] = None
            else:
                m[f"raw_brotli_h{w}"] = bro_hist(prev_raw, raw)
                m[f"packed_brotli_h{w}"] = bro_hist(prev_pack, packed)
            if use_zstd:
                m[f"raw_zstd_h{w}"] = zstd_hist(prev_raw, raw)
                m[f"packed_zstd_h{w}"] = zstd_hist(prev_pack, packed)
        sc = seg_cnt.setdefault(si, Counter())
        for k, v in m.items():
            if v is None:
                na.add(k)
            else:
                tot[k] += v
                sc[k] += v
        evict(i)

    def pc(base, x):
        return f"{100 * (1 - x / base):6.2f}%" if base else "   n/a "

    base = tot["raw_brotli"]
    print(f"\n=== TOTAL over {tot['n']} evaluated batches (raw txs {tot['raw_bytes']:,} B, brotli-{q}) ===")
    print(f"  raw txs + brotli:                    {base:>12,}")
    print(f"  dict_pack + brotli (+table):         {tot['packed_brotli'] + table:>12,}  "
          f"{pc(base, tot['packed_brotli'] + table)}")

    def sweep(title, kr_fmt, kp_fmt):
        print(f"\n--- {title}: each saving is vs raw brotli without history ---")
        print(f"{'history':>9s}{'raw':>10s}{'extra vs prev':>15s}{'dict_pack(+table)':>19s}{'encoding adds':>15s}")
        prev = None
        for w in windows:
            kr, kp = kr_fmt.format(w), kp_fmt.format(w)
            if kr in na or kp in na:
                print(f"{w:>9d}   n/a (does not fit the 16 MiB brotli window)")
                continue
            r, p = tot[kr], tot[kp] + table
            extra = pc(prev if prev else base, r)
            print(f"{w:>9d}{pc(base, r):>10s}{extra:>15s}{pc(base, p):>19s}{pc(r, p):>15s}")
            prev = r

    if not args.zstd_only:
        sweep("window sweep, brotli", "raw_brotli_h{}", "packed_brotli_h{}")    
    if use_zstd:
        sweep("window sweep, zstd", "raw_zstd_h{}", "packed_zstd_h{}")


if __name__ == "__main__":
    main()
