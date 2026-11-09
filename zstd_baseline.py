#!/usr/bin/env python3
import argparse
import csv
import glob
import os
import random
import sys

import brotli
import zstandard as zstd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from varint_pack import extract_raw_txs


def sort_key(folder):
    name = os.path.basename(folder)
    head = name.split("_")[0]
    return (0, int(head), name) if head.isdigit() else (1, 0, name)


def load_txs(folder):
    with open(os.path.join(folder, "decompressed.bin"), "rb") as f:
        return extract_raw_txs(f.read())


def pct(before, after):
    return round(100.0 * (1 - after / before), 2) if before else ""


def main():
    ap = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data-dir", default="arbitrum_data")
    ap.add_argument("--train-frac", type=float, default=0.5)
    ap.add_argument("--level", type=int, default=19)
    ap.add_argument("--quality", type=int, default=11)
    ap.add_argument("--dict-size", type=int, default=65536)
    ap.add_argument("--max-samples", type=int, default=30000)
    ap.add_argument("--out-csv")
    args = ap.parse_args()

    folders = sorted((os.path.dirname(p) for p in
                      glob.glob(os.path.join(args.data_dir, "*", "decompressed.bin"))), key=sort_key)
    if len(folders) < 2:
        sys.exit("need at least 2 batch folders")
    k = min(len(folders) - 1, max(1, int(round(len(folders) * args.train_frac))))
    train, test = folders[:k], folders[k:]

    rng = random.Random(0)
    per_batch = max(1, args.max_samples // len(train))
    samples = []
    for folder in train:
        txs = load_txs(folder)
        samples += rng.sample(txs, min(per_batch, len(txs)))
    zdict = zstd.train_dictionary(args.dict_size, samples, level=args.level, threads=-1)
    dict_bytes = len(zdict.as_bytes())

    plain = zstd.ZstdCompressor(level=args.level)
    withdict = zstd.ZstdCompressor(level=args.level, dict_data=zdict)

    def bro(b):
        return len(brotli.compress(b, quality=args.quality))

    keys = ["raw_bytes", "raw_brotli", "raw_zstd", "raw_zstd_dict", "packed_brotli", "packed_zstd"]
    tot = {key: 0 for key in keys}
    rows, have_packed = [], True
    for n, folder in enumerate(test, 1):
        raw = b"".join(load_txs(folder))
        row = {"folder": os.path.basename(folder), "raw_bytes": len(raw),
               "raw_brotli": bro(raw), "raw_zstd": len(plain.compress(raw)),
               "raw_zstd_dict": len(withdict.compress(raw))}
        pp = os.path.join(folder, "dict_packed.bin")
        if os.path.exists(pp):
            with open(pp, "rb") as f:
                packed = f.read()
            row["packed_brotli"] = bro(packed)
            row["packed_zstd"] = len(plain.compress(packed))
        else:
            have_packed = False
        for key in keys:
            tot[key] += row.get(key, 0)
        rows.append(row)

    base = tot["raw_brotli"]
    print(f"\nTOTAL over {len(test)} held-out batches, raw txs {tot['raw_bytes']:,} bytes")
    print(f"  {'method':32s}{'bytes':>14s}  vs raw brotli")
    lines = [("raw txs + brotli", base),
             (f"raw txs + zstd-{args.level}", tot["raw_zstd"]),
             ("raw txs + zstd + trained dict", tot["raw_zstd_dict"]),
             (f"  ... plus dict ({dict_bytes:,} B)", tot["raw_zstd_dict"] + dict_bytes)]
    if have_packed:
        lines += [("dict_pack + brotli", tot["packed_brotli"]),
                  ("dict_pack + zstd", tot["packed_zstd"])]
    for name, size in lines:
        print(f"  {name:32s}{size:>14,}  {pct(base, size)}% smaller")

    out = args.out_csv or os.path.join(args.data_dir, "zstd_results.csv")
    with open(out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["folder"] + keys, restval="")
        w.writeheader()
        w.writerows(rows)
        w.writerow({"folder": "TOTAL", **tot})
    print(f"results: {out}")


if __name__ == "__main__":
    main()
