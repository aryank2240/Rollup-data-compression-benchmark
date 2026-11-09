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
CLASSES = ["zero", "small", "u128", "addr", "neg", "rpad", "full"]
Z32 = bytes(32)

def classify(w):
    if w == Z32:
        return "zero"
    v = int.from_bytes(w, "big")
    if v < (1 << 64):
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

def entropy_bits(counter):
    n = sum(counter.values())
    return -sum(c / n * math.log2(c / n) for c in counter.values()) if n else 0.0

def short(w):
    h = w.hex()
    return h if len(h) <= 24 else h[:10] + ".." + h[-10:]

def main():
    ap = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data-dir", default="arbitrum_data")
    ap.add_argument("--selectors", nargs="+", default=DEFAULT_SELECTORS)
    ap.add_argument("--limit", type=int, default=30)
    ap.add_argument("--samples", type=int, default=2)
    ap.add_argument("--max-words", type=int, default=40)
    args = ap.parse_args()
    wanted = {s.lower().removeprefix("0x") for s in args.selectors}

    folders = sorted(glob.glob(os.path.join(args.data_dir, "*", "decompressed.bin")))[:args.limit]
    if not folders:
        sys.exit("no batches found")

    calls = defaultdict(list)
    for i, p in enumerate(folders, 1):
        with open(p, "rb") as f:
            txs, _ = parse_batch(f.read())
        for t in txs:
            d = t["data"]
            if len(d) >= 4 and d[:4].hex() in wanted:
                calls[d[:4].hex()].append((t["to"], d))
    print()

    for sel in args.selectors:
        sel = sel.lower().removeprefix("0x")
        rows = calls.get(sel, [])
        print("=" * 78)
        if not rows:
            print(f"selector {sel}: no txs found in {len(folders)} batches")
            continue
        lens = Counter(len(d) for _, d in rows)
        tos = Counter(to for to, _ in rows)
        seen, dups = set(), 0
        for _, d in rows:
            dups += d in seen
            seen.add(d)
        print(f"selector 0x{sel}: {len(rows):,} txs | total calldata {sum(len(d) for _, d in rows):,} B")
        print(f"  to: {len(tos)} distinct, top {tos.most_common(1)[0][0]} x{tos.most_common(1)[0][1]}")
        print(f"  lengths (top 5): {lens.most_common(5)}")
        print(f"  exact duplicate calldata: {dups:,} ({100 * dups / len(rows):.1f}%)")

        words_seen, repeat_words, total_words = set(), 0, 0
        for _, d in rows:
            body = d[4:]
            for k in range(0, len(body) - 31, 32):
                w = body[k:k + 32]
                total_words += 1
                repeat_words += w in words_seen
                words_seen.add(w)
        if total_words:
            print(f"  32-byte words seen earlier under this selector: {100 * repeat_words / total_words:.1f}% "
                  f"of {total_words:,}")

        top_len = lens.most_common(1)[0][0]
        group = [d for _, d in rows if len(d) == top_len]
        nw = (top_len - 4) // 32
        print(f"\n  profile of the most common length ({top_len} B, {len(group):,} txs, "
              f"{nw} words{'' if (top_len - 4) % 32 == 0 else ', NOT 32-aligned'}):")
        print(f"  {'pos':>4s} {'distinct':>8s} {'H(bits)':>8s} {'=prev%':>7s}  class mix")
        for pos in range(min(nw, args.max_words)):
            col = [d[4 + 32 * pos:36 + 32 * pos] for d in group]
            cls = Counter(classify(w) for w in col)
            same_prev = sum(a == b for a, b in zip(col, col[1:]))
            mix = " ".join(f"{c}:{100 * cls[c] // len(col)}%" for c in CLASSES if cls[c])
            print(f"  {pos:>4d} {len(set(col)):>8d} {entropy_bits(Counter(col)):>8.1f} "
                  f"{100 * same_prev / max(1, len(col) - 1):>6.0f}%  {mix}")
        if nw > args.max_words:
            print(f"  ... {nw - args.max_words} more positions")

        print(f"\n  {args.samples} sample(s):")
        step = max(1, len(group) // args.samples)
        for d in group[::step][:args.samples]:
            print(f"   --- {len(d)} bytes, selector 0x{d[:4].hex()}")
            for pos in range((len(d) - 4) // 32)[:args.max_words]:
                w = d[4 + 32 * pos:36 + 32 * pos]
                print(f"   [{pos:>3d}] {short(w):26s} {classify(w)}")
    print("=" * 78)


if __name__ == "__main__":
    main()
