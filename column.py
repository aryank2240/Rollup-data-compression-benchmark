#!/usr/bin/env python3
import argparse
import csv
import glob
import json
import os
import sys
from collections import Counter, defaultdict

import brotli

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from arbitrum_batch_pipeline import parse_batch
from varint_pack import extract_raw_txs, put_varint

COLUMNS = ["type", "chain_id", "nonce", "max_priority_fee", "fee_cap", "gas", "value",
           "to", "data_len", "selector", "calldata", "v", "signature"]

KNOWN_SELECTORS = {
    "a9059cbb": "ERC-20 transfer",
    "095ea7b3": "ERC-20 approve",
    "23b872dd": "transferFrom",
    "3593564c": "Universal Router execute",
    "ac9650d8": "multicall(bytes[])",
    "5ae401dc": "multicall(uint256,bytes[])",
    "414bf389": "exactInputSingle (V3)",
    "04e45aaf": "exactInputSingle (SwapRouter02)",
    "38ed1739": "swapExactTokensForTokens",
    "d0e30db0": "deposit()",
    "2e1a7d4d": "withdraw(uint256)",
}

ZERO12 = bytes(12)
ZERO32 = bytes(32)


def vi(n):
    out = bytearray()
    put_varint(n, out)
    return bytes(out)


def natural_len(n):
    return (n.bit_length() + 7) // 8


def share(a, b):
    return round(100.0 * a / b, 2) if b else ""


def load_batch(folder):
    with open(os.path.join(folder, "decompressed.bin"), "rb") as f:
        raw = f.read()
    txs, _ = parse_batch(raw)
    return txs, raw


def classify_words(d, wc):
    n = len(d)
    if n == 0:
        return
    if n < 36 or (n - 4) % 32:
        wc["unaligned_bytes"] += n
        return
    wc["aligned_bytes"] += n
    for i in range(4, n, 32):
        w = d[i:i + 32]
        if w == ZERO32:
            wc["zero_words"] += 1
        else:
            v = int.from_bytes(w, "big")
            if v < (1 << 64):
                wc["small_words"] += 1
            elif w[:12] == ZERO12:
                wc["address_words"] += 1
            else:
                wc["full_words"] += 1


def main():
    ap = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data-dir", default="arbitrum_data")
    ap.add_argument("--quality", type=int, default=11)
    ap.add_argument("--top-selectors", type=int, default=12)
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()
    q = args.quality

    def bz(b):
        return len(brotli.compress(bytes(b), quality=q)) if b else 0

    folders = sorted(os.path.dirname(p) for p in
                     glob.glob(os.path.join(args.data_dir, "*", "decompressed.bin")))
    if not folders:
        sys.exit(f"no <folder>/decompressed.bin found under {args.data_dir!r}")
    if args.limit:
        folders = folders[:args.limit]

    sel_raw = Counter()
    for folder in folders:
        try:
            txs, _ = load_batch(folder)
        except Exception:
            continue
        for t in txs:
            d = t["data"]
            if len(d) >= 4:
                sel_raw[d[:4].hex()] += len(d) - 4
    top = [s for s, _ in sel_raw.most_common(args.top_selectors)]
    topset = set(top)

    col_raw, col_brotli = Counter(), Counter()
    grp_raw, grp_brotli, grp_n = Counter(), Counter(), Counter()
    sel_to = defaultdict(Counter)
    wc = Counter()
    n_txs = n_batches = 0
    base_raw = base_brotli = framing_raw = posted_total = 0
    calldata_single = calldata_grouped = 0

    for i, folder in enumerate(folders, 1):
        name = os.path.basename(folder)
        try:
            txs, raw = load_batch(folder)
        except Exception:
            continue
        raw_txs = extract_raw_txs(raw)
        base_raw += sum(len(t) for t in raw_txs)
        base_brotli += bz(b"".join(raw_txs))

        streams = {c: bytearray() for c in COLUMNS}
        groups = defaultdict(bytearray)
        content_raw = 0
        for t in txs:
            d = t["data"]
            streams["type"].append(t["type"])
            c = 1 if t["type"] != 0 else 0
            if t["chain_id"] is not None:
                streams["chain_id"] += vi(t["chain_id"])
                c_chain = natural_len(t["chain_id"])
                col_raw["chain_id"] += c_chain
                c += c_chain
            col_raw["type"] += 1 if t["type"] != 0 else 0
            streams["nonce"] += vi(t["nonce"])
            col_raw["nonce"] += natural_len(t["nonce"])
            c += natural_len(t["nonce"])
            if t["max_priority_fee"] is not None:
                streams["max_priority_fee"] += vi(t["max_priority_fee"])
                col_raw["max_priority_fee"] += natural_len(t["max_priority_fee"])
                c += natural_len(t["max_priority_fee"])
            streams["fee_cap"] += vi(t["fee_cap"])
            col_raw["fee_cap"] += natural_len(t["fee_cap"])
            c += natural_len(t["fee_cap"])
            streams["gas"] += vi(t["gas"])
            col_raw["gas"] += natural_len(t["gas"])
            c += natural_len(t["gas"])
            streams["value"] += vi(t["value_wei"])
            col_raw["value"] += natural_len(t["value_wei"])
            c += natural_len(t["value_wei"])
            if t["to"] != "(create)":
                streams["to"] += bytes.fromhex(t["to"][2:])
                col_raw["to"] += 20
                c += 20
            streams["data_len"] += vi(len(d))
            if len(d) >= 4:
                sel = d[:4].hex()
                rest = d[4:]
                streams["selector"] += d[:4]
                col_raw["selector"] += 4
            else:
                sel = None
                rest = d
            streams["calldata"] += rest
            col_raw["calldata"] += len(rest)
            c += len(d)
            v = int.from_bytes(t["v"], "big")
            streams["v"] += vi(v)
            col_raw["v"] += len(t["v"])
            c += len(t["v"])
            streams["signature"] += t["r"].rjust(32, b"\0") + t["s"].rjust(32, b"\0")
            col_raw["signature"] += len(t["r"]) + len(t["s"])
            c += len(t["r"]) + len(t["s"])
            content_raw += c

            g = sel if sel in topset else "other"
            groups[g] += rest
            grp_n[g] += 1
            grp_raw[g] += len(rest)
            if g != "other":
                sel_to[g][t["to"]] += 1
            classify_words(d, wc)

        framing_raw += sum(t["raw_len"] for t in txs) - content_raw
        for c_name, stream in streams.items():
            col_brotli[c_name] += bz(stream)
        calldata_single += bz(streams["calldata"])
        for g, stream in groups.items():
            b = bz(stream)
            grp_brotli[g] += b
            calldata_grouped += b
        n_txs += len(txs)
        n_batches += 1

        mp = os.path.join(folder, "meta.json")
        if os.path.exists(mp):
            with open(mp) as f:
                p = json.load(f).get("payload_bytes")
            posted_total += p or 0

    if not n_batches:
        sys.exit("no batch could be read")

    cols_sum = sum(col_brotli.values())
    print(f"\n=== {n_batches} batches, {n_txs:,} transactions, brotli-{q}, each batch compressed separately ===\n")
    print(f"{'column':18s}{'raw bytes':>12s}{'brotli bytes':>14s}{'% of columns':>14s}{'brotli B/tx':>13s}")
    rows = []
    for c_name in sorted(COLUMNS, key=lambda c: -col_brotli[c]):
        rows.append({"column": c_name, "raw_bytes": col_raw[c_name], "brotli_bytes": col_brotli[c_name],
                     "share_of_columns_pct": share(col_brotli[c_name], cols_sum),
                     "brotli_bytes_per_tx": round(col_brotli[c_name] / n_txs, 2)})
        r = rows[-1]
        print(f"{c_name:18s}{r['raw_bytes']:>12,}{r['brotli_bytes']:>14,}"
              f"{r['share_of_columns_pct']:>13}%{r['brotli_bytes_per_tx']:>13}")
    print(f"{'RLP framing (cut)':18s}{framing_raw:>12,}{'':>14s}")
    print(f"{'sum of columns':18s}{sum(col_raw.values()):>12,}{cols_sum:>14,}")
    print(f"{'baseline (raw RLP)':18s}{base_raw:>12,}{base_brotli:>14,}   <- brotli of the raw transactions")
    saving = share(base_brotli - cols_sum, base_brotli)
    print(f"\nsplitting into columns alone: {base_brotli:,} -> {cols_sum:,} bytes ({saving}% smaller)")
    sig_floor = col_brotli["signature"]
    print(f"signature floor: {sig_floor:,} bytes = {share(sig_floor, cols_sum)}% of the column total "
          f"({share(sig_floor, base_brotli)}% of the baseline). Everything else: {cols_sum - sig_floor:,} bytes.")
    if posted_total:
        print(f"(for reference, the posted payloads of these batches total {posted_total:,} bytes)")
    rows.append({"column": "TOTAL_columns", "raw_bytes": sum(col_raw.values()), "brotli_bytes": cols_sum,
                 "share_of_columns_pct": 100.0, "brotli_bytes_per_tx": round(cols_sum / n_txs, 2)})
    rows.append({"column": "BASELINE_raw_rlp_txs", "raw_bytes": base_raw, "brotli_bytes": base_brotli,
                 "share_of_columns_pct": "", "brotli_bytes_per_tx": round(base_brotli / n_txs, 2)})
    rows.append({"column": "RLP_framing_dropped", "raw_bytes": framing_raw, "brotli_bytes": "",
                 "share_of_columns_pct": "", "brotli_bytes_per_tx": ""})

    print("\n=== calldata, by function selector (the 4-byte selector itself is in the selector column) ===\n")
    print(f"calldata as one stream: {calldata_single:,} bytes | grouped by selector "
          f"(top {len(top)} + other, separate streams): {calldata_grouped:,} bytes "
          f"({share(calldata_single - calldata_grouped, calldata_single)}% smaller)\n")
    print(f"{'selector':12s}{'txs':>8s}{'raw bytes':>12s}{'brotli bytes':>14s}{'ratio':>8s}{'B/tx':>8s}"
          f"  {'to (distinct, top)':28s} name")
    sel_rows = []
    for g in top + ["other"]:
        if g not in grp_n:
            continue
        n_g, r_g, b_g = grp_n[g], grp_raw[g], grp_brotli[g]
        ratio = round(r_g / b_g, 2) if b_g else ""
        if g != "other" and sel_to[g]:
            top_to, top_cnt = sel_to[g].most_common(1)[0]
            to_txt = f"{len(sel_to[g])} distinct, {top_to[:10]}.. x{top_cnt}"
        else:
            to_txt = ""
        label = KNOWN_SELECTORS.get(g, "") if g != "other" else "(all other selectors, short/no calldata)"
        sel_rows.append({"selector": g, "txs": n_g, "raw_calldata_bytes": r_g, "brotli_bytes": b_g,
                         "ratio": ratio, "brotli_bytes_per_tx": round(b_g / n_g, 2) if n_g else "",
                         "distinct_to": len(sel_to[g]) if g != "other" else "",
                         "top_to": sel_to[g].most_common(1)[0][0] if g != "other" and sel_to[g] else "",
                         "name": label})
        print(f"{g:12s}{n_g:>8,}{r_g:>12,}{b_g:>14,}{ratio:>8}{round(b_g / n_g, 1):>8}  {to_txt:28s} {label}")

    words = wc["zero_words"] + wc["small_words"] + wc["address_words"] + wc["full_words"]
    cd_total = wc["aligned_bytes"] + wc["unaligned_bytes"]
    print("\n=== calldata structure ===\n")
    print(f"ABI-aligned calldata (4 + 32k bytes): {wc['aligned_bytes']:,} bytes ({share(wc['aligned_bytes'], cd_total)}% "
          f"of all calldata) | other layouts: {wc['unaligned_bytes']:,} bytes")
    if words:
        for label, key in (("zero words", "zero_words"), ("small numbers (< 2^64)", "small_words"),
                           ("address-like (12 leading zero bytes)", "address_words"),
                           ("full 32-byte values", "full_words")):
            print(f"  {label:38s}{wc[key]:>10,} words  {share(wc[key], words):>6}%  "
                  f"({wc[key] * 32:,} raw bytes)")
        print("  Zero words, small numbers and addresses can be shrunk by an ABI-aware encoding; "
              "full 32-byte values (hashes, large amounts) cannot.")

    out1 = os.path.join(args.data_dir, "column_report.csv")
    with open(out1, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["column", "raw_bytes", "brotli_bytes", "share_of_columns_pct",
                                          "brotli_bytes_per_tx"])
        w.writeheader()
        w.writerows(rows)
    out2 = os.path.join(args.data_dir, "calldata_by_selector.csv")
    with open(out2, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["selector", "txs", "raw_calldata_bytes", "brotli_bytes", "ratio",
                                          "brotli_bytes_per_tx", "distinct_to", "top_to", "name"])
        w.writeheader()
        w.writerows(sel_rows)
    print(f"\nresults: {out1}\n         {out2}")


if __name__ == "__main__":
    main()
