#!/usr/bin/env python3

import argparse
import csv
import math
import os

GAS_PER_BLOB = 1 << 17
BLOB_BASE_COST = 1 << 13
MIN_BLOB_BASE_FEE = 1
UPDATE_FRACTION = 11_684_671        
USABLE = 130_048                     
FRAMING = 64_527_823 / 63_898_503     
BASELINE = 19_123_377

SAVINGS = {
    "first": [
        ("A", "raw txs + brotli (baseline)", 0.00, "stateless"),
        ("B", "dict_pack + brotli (+table)", 2.61, "stateless"),
        ("C", "dict_pack + cache(last 5)", 4.22, "stateful"),
        ("D", "dict_pack + brotli, history 1", 8.61, "stateful"),
        ("E", "raw + brotli, history 3", 10.78, "stateful"),
        ("F", "dict_pack + brotli, history 3", 11.82, "stateful"),
    ],
    "multiday": [  
        ("A", "raw txs + brotli (baseline)", 0.00, "stateless"),
        ("B", "dict_pack + brotli (+table)", 2.18, "stateless"),
        ("C", "dict_pack + zstd, history 3", 9.37, "stateful"),
        ("D", "dict_pack + brotli h3 (estimate)", 10.36, "stateful"),
        ("E", "dict_pack + zstd, history 10", 12.29, "stateful"),
        ("F", "dict_pack + brotli h10 (estimate)", 13.23, "stateful"),
    ],
}

def fake_exponential(factor, numerator, denominator):
   
    i, out, acc = 1, 0, factor * denominator
    while acc > 0:
        out += acc
        acc = (acc * numerator) // (denominator * i)
        i += 1
    return out // denominator


def blobs_for(nbytes, usable):
    return max(1, math.ceil(nbytes / usable))

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--txs", type=int, default=101_278, help="transactions in the measured set")
    ap.add_argument("--usable-bytes", type=int, default=USABLE)
    ap.add_argument("--set", choices=list(SAVINGS), default="multiday", help="which measured dataset to use")
    ap.add_argument("--update-fraction", type=int, default=UPDATE_FRACTION)
    ap.add_argument("--framing", type=float, default=FRAMING, help="posted bytes / brotli(raw txs)")
    ap.add_argument("--eth-usd", type=float, default=3000.0, help="ASSUMED ETH price, set your own")
    ap.add_argument("--l1-base-fee-gwei", type=float, default=0.1,
                    help="ASSUMED L1 base fee for the EIP-7918 reserve row (0 = skip the row)")
    ap.add_argument("--csv", default=os.path.join("arbitrum_data", "dict_results.csv"))
    a = ap.parse_args()
    SCENARIOS = [(k, n, int(round(BASELINE * (1 - s / 100))), kind) for k, n, s, kind in SAVINGS[a.set]]
   
    print(f"usable bytes/blob {a.usable_bytes:,} | framing x{a.framing:.4f} | {a.txs:,} txs | "
          f"update fraction {a.update_fraction:,}\n")
    print("=== 1. size and blobs per 1,000 txs (amortized, batches filled to capacity) ===")
    print(f"{'':3s}{'scenario':32s}{'decoder':10s}{'bytes (50 batches)':>19s}{'B/tx':>9s}"
          f"{'blobs/1k tx':>13s}{'saving':>9s}")
    for key, name, b, kind in SCENARIOS:
        per_tx = b * a.framing / a.txs
        print(f"{key:3s}{name:32s}{kind:10s}{b:>19,}{per_tx:>9.1f}"
              f"{per_tx * 1000 / a.usable_bytes:>13.3f}{100 * (1 - b / BASELINE):>8.2f}%")

    levels = [("1 wei (floor)", 1), ("1,000 wei", 10 ** 3), ("0.001 gwei", 10 ** 6),
              ("0.01 gwei", 10 ** 7), ("0.1 gwei", 10 ** 8), ("1 gwei", 10 ** 9), ("10 gwei", 10 ** 10)]
    if a.l1_base_fee_gwei > 0:
        reserve = int(a.l1_base_fee_gwei * 1e9) * BLOB_BASE_COST // GAS_PER_BLOB
        levels.append((f"EIP-7918 reserve @{a.l1_base_fee_gwei:g}gwei L1", max(reserve, MIN_BLOB_BASE_FEE)))

    def usd_per_million(b, price):
        blobs = b * a.framing / a.usable_bytes * (1_000_000 / a.txs)
        return blobs * GAS_PER_BLOB * price / 1e18 * a.eth_usd

    print(f"\n=== 2. cost in USD per 1,000,000 txs (assumed ETH = ${a.eth_usd:,.0f}); amortized ===")
    print(f"{'blob base fee':32s}{'excess gas':>12s}" + "".join(f"{k:>11s}" for k, *_ in SCENARIOS))
    for label, price in levels:
        exc = a.update_fraction * math.log(price) if price > 1 else 0.0
        row = "".join(f"{usd_per_million(b, price):>11.3g}" for _, _, b, _ in SCENARIOS)
        print(f"{label:32s}{exc / 1e6:>10,.1f}M{row}")
    best = min(b for *_, b, _ in SCENARIOS)
    print(f"\nA -> best scenario: {100 * (1 - best / BASELINE):.2f}% cheaper at every fee level "
          f"(the percentage does not depend on the price; only the absolute dollars do).")
    print("'excess gas' = excess_blob_gas that produces that price via fake_exponential; the market must "
          "accumulate this much over target before the price gets there.")
    print("Check: fake_exponential(1, excess, fraction) at 1 gwei level = "
          f"{fake_exponential(MIN_BLOB_BASE_FEE, int(a.update_fraction * math.log(10 ** 9)), a.update_fraction):,} wei")

    # ---------------- table 3: per-batch rounding with real batch sizes
    if not os.path.exists(a.csv):
        print(f"\n(no {a.csv}: skipping the per-batch rounding table. Run dict_pack.py first.)")
        return
    with open(a.csv, newline="") as f:
        rows = [r for r in csv.DictReader(f) if r.get("folder") != "TOTAL" and r.get("status") == "ok"
                and r.get("raw_tx_brotli_bytes")]
    sizes = [int(r["raw_tx_brotli_bytes"]) for r in rows]
    if not sizes:
        print("\n(csv has no usable per-batch rows)")
        return
    avg_blobs = sum(sizes) * a.framing / len(sizes) / a.usable_bytes
    print(f"\n=== 3. per-batch rounding: {len(sizes)} real held-out batches from {a.csv} ===")
    print(f"baseline batch = {avg_blobs:.2f} blobs on average (min {min(sizes) * a.framing / a.usable_bytes:.2f}, "
          f"max {max(sizes) * a.framing / a.usable_bytes:.2f})")
    print("fixed content: every batch keeps its txs, so only a crossed blob boundary saves a blob.\n")
    print(f"{'':3s}{'scenario':32s}{'blobs, ceil/batch':>19s}{'saving':>9s}{'blobs, amortized':>18s}{'saving':>9s}")
    base_ceil = base_am = None
    for key, name, b, _ in SCENARIOS:
        ratio = b / BASELINE
        scaled = [s * ratio * a.framing for s in sizes]
        ceil_n = sum(blobs_for(x, a.usable_bytes) for x in scaled)
        am_n = sum(scaled) / a.usable_bytes
        if base_ceil is None:
            base_ceil, base_am = ceil_n, am_n
        print(f"{key:3s}{name:32s}{ceil_n:>19,}{100 * (1 - ceil_n / base_ceil):>8.2f}%"
              f"{am_n:>18,.1f}{100 * (1 - am_n / base_am):>8.2f}%")
    print("\nIf the ceil column saves much less than the amortized column, the poster must re-pack more txs "
          "per batch for the saving to be real. Your posted batches already sit at ~99% of 3 blobs, "
          "which suggests it does.")
if __name__ == "__main__":
    main()
