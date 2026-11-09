#!/usr/bin/env python3
import argparse
import glob
import math
import os
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from arbitrum_batch_pipeline import parse_batch

DEFAULT_SELECTORS = ["f28a9fc9", "d31cba4a", "7ebc83f7", "45c6b8c7"]
TRACKED = ("u128", "addr", "neg", "rpad", "full")
Z32 = bytes(32)

def classify(w):
    if w == Z32:
        return "zero"
    if int.from_bytes(w, "big") < (1 << 64):
        return "small"
    if w[:16] == bytes(16):
        return "u128"
    if w[:12] == bytes(12):
        return "addr"
    if w[:16] == b"\xff" * 16:
        return "neg"
    if w[-12:] == bytes(12):
        return "rpad"
    return "full"

def sig_bytes(w, cls):
    if cls in ("u128", "addr"):
        return len(w.lstrip(b"\0"))
    return 32

def sort_key(path):
    name = os.path.basename(os.path.dirname(path))
    head = name.split("_")[0]
    return (0, int(head), name) if head.isdigit() else (1, 0, name)

def h2(p):
    return 0.0 if p <= 0 or p >= 1 else -(p * math.log2(p) + (1 - p) * math.log2(1 - p))

def main():
    ap = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data-dir", default="arbitrum_data")
    ap.add_argument("--selectors", nargs="+", default=DEFAULT_SELECTORS)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--warmup", type=int, default=5)
    ap.add_argument("--baseline-brotli", type=int, default=0)
    args = ap.parse_args()
    all_sel = [s.lower() for s in args.selectors] == ["all"]
    wanted = None if all_sel else {s.lower().removeprefix("0x") for s in args.selectors}

    paths = sorted(glob.glob(os.path.join(args.data_dir, "*", "decompressed.bin")), key=sort_key)
    if args.limit:
        paths = paths[:args.limit]
    if not paths:
        sys.exit("no batches found")

    last_seen = {}
    batch_sets = []
    C = defaultdict(Counter)
    sav = defaultdict(float)

    for b, p in enumerate(paths):
        with open(p, "rb") as f:
            txs, _ = parse_batch(f.read())
        size_all = max(2, len(last_seen))
        size_5 = max(2, len(set().union(*batch_sets[-5:])) if batch_sets else 2)
        cost_all, cost_5 = math.log2(size_all) / 8, math.log2(size_5) / 8
        cur = set()
        counted = b >= args.warmup
        for t in txs:
            d = t["data"]
            if len(d) < 36:
                continue
            sel = d[:4].hex()
            if wanted is not None and sel not in wanted:
                continue
            group = "ALL" if all_sel else sel
            for k in range(4, len(d) - 31, 32):
                w = d[k:k + 32]
                cls = classify(w)
                if cls not in TRACKED:
                    continue
                sb = sig_bytes(w, cls)
                key = (group, cls)
                if counted:
                    c = C[key]
                    c["n"] += 1
                    c["bytes"] += sb
                if w in cur:
                    if counted:
                        c["inbatch"] += 1
                else:
                    last = last_seen.get(w)
                    if last is None:
                        if counted:
                            c["new"] += 1
                    else:
                        dist = b - last
                        if counted:
                            c["<=1" if dist <= 1 else "<=5" if dist <= 5 else "older"] += 1
                            c["hit_all"] += 1
                            sav[key + ("all",)] += sb - cost_all
                            if dist <= 5:
                                c["hit_5"] += 1
                                sav[key + ("5",)] += sb - cost_5
                cur.add(w)
                last_seen[w] = b
        batch_sets.append(cur)

    def table(title, keyfn):
        agg, sv = defaultdict(Counter), defaultdict(float)
        for key, c in C.items():
            agg[keyfn(key)].update(c)
            for cache in ("all", "5"):
                sv[keyfn(key) + (cache,)] += sav.get(key + (cache,), 0.0)
        print(f"\n=== {title} ===")
        print(f"{'':16s}{'words':>10s}{'sig MB':>8s}{'in-batch':>9s}{'<=1':>6s}{'<=5':>6s}"
              f"{'older':>7s}{'new':>6s} | {'net KB, last 5':>15s}{'net KB, all':>13s}")
        tot_net = {"5": 0.0, "all": 0.0}
        tot_bytes = 0
        for g in sorted(agg, key=lambda g: -agg[g]["bytes"]):
            c = agg[g]
            n = c["n"]
            if not n:
                continue
            cand = n - c["inbatch"]
            net = {}
            for cache, hits in (("5", c["hit_5"]), ("all", c["hit_all"])):
                flag = cand * h2(hits / cand) / 8 if cand else 0.0
                net[cache] = sv[g + (cache,)] - flag
                tot_net[cache] += net[cache]
            tot_bytes += c["bytes"]
            pc = lambda k: f"{100 * c[k] / n:.0f}%"
            print(f"{'/'.join(g):16s}{n:>10,}{c['bytes'] / 1e6:>8.2f}{pc('inbatch'):>9s}{pc('<=1'):>6s}"
                  f"{pc('<=5'):>6s}{pc('older'):>7s}{pc('new'):>6s} | "
                  f"{net['5'] / 1e3:>15,.0f}{net['all'] / 1e3:>13,.0f}")
        print(f"{'TOTAL':16s}{'':>10s}{tot_bytes / 1e6:>8.2f}{'':>9s}{'':>6s}{'':>6s}{'':>7s}{'':>6s} | "
              f"{tot_net['5'] / 1e3:>15,.0f}{tot_net['all'] / 1e3:>13,.0f}")
        if tot_bytes:
            print(f"  net saving as share of the tracked words' significant bytes: "
                  f"{100 * tot_net['5'] / tot_bytes:.1f}% (last 5), {100 * tot_net['all'] / tot_bytes:.1f}% (all)")
        if args.baseline_brotli:
            print(f"  as share of total brotli baseline ({args.baseline_brotli:,} B): "
                  f"{100 * tot_net['5'] / args.baseline_brotli:.2f}% (last 5), "
                  f"{100 * tot_net['all'] / args.baseline_brotli:.2f}% (all)")

    counted_batches = max(0, len(paths) - args.warmup)
    print(f"{len(paths)} batches, {counted_batches} counted after {args.warmup} warm-up")
    table("by selector", lambda k: (k[0],))
    table("by word class", lambda k: (k[1],))

if __name__ == "__main__":
    main()
