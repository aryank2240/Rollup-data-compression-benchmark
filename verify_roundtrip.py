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


def main():
    ap = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data-dir", default="arbitrum_data")
    ap.add_argument("--train-frac", type=float, default=0.7)
    ap.add_argument("--window", type=int, default=3)
    ap.add_argument("--max-test", type=int, default=10)
    ap.add_argument("--quality", type=int, default=9)
    ap.add_argument("--chain-id", type=int, default=42161)
    args = ap.parse_args()
    w = args.window

    folders = sorted((os.path.dirname(p) for p in
                      glob.glob(os.path.join(args.data_dir, "*", "decompressed.bin"))), key=dp.sort_key)
    k = min(len(folders) - 1, max(w, int(round(len(folders) * args.train_frac))))
    test = list(range(k, min(len(folders), k + args.max_test)))

    addr_c, sel_c = Counter(), Counter()
    for f in folders[:k]:
        for t in dp.load_batch(f)[0]:
            to, sel = dp.to_and_selector(t)
            if to is not None:
                addr_c[to] += 1
            if sel is not None:
                sel_c[sel] += 1
    dictionary = dp.Dictionary(dp.build_list(addr_c, dp.ADDR_LEN, 3, 4096),
                               dp.build_list(sel_c, dp.SEL_LEN, 3, 1024))
    ns = Namespace(chain_id=args.chain_id, fee_mode="auto")

    def pack(txs):
        fb, _ = dp.pick_fee_base(txs, ns)
        return dp.pack_stream(txs, dp.Ctx(args.chain_id, fb, dictionary, True, True))

    enc_hist, dec_hist = {}, {}
    for j in range(k - w, k):
        enc_hist[j] = dec_hist[j] = pack(dp.load_batch(folders[j])[0])[0]

    bad, tot_raw, tot_tx, tot_esc = 0, 0, 0, 0
    for i in test:
        txs, raw_len = dp.load_batch(folders[i])
        raw = b"".join(txs)
        packed, esc = pack(txs)
        tot_raw, tot_tx, tot_esc = tot_raw + raw_len, tot_tx + len(raw), tot_esc + esc

        back = dp.unpack_stream(brotli.decompress(brotli.compress(packed, quality=args.quality)), dictionary)
        ok_stateless = back == txs and b"".join(back) == raw

        ok_stateful = None
        if zstd is not None:
            pe = b"".join(enc_hist[j] for j in range(i - w, i))
            pd = b"".join(dec_hist[j] for j in range(i - w, i))
            z = zstd.ZstdCompressor(level=19, dict_data=zstd.ZstdCompressionDict(
                pe, dict_type=zstd.DICT_TYPE_RAWCONTENT)).compress(packed)
            dec = zstd.ZstdDecompressor(dict_data=zstd.ZstdCompressionDict(
                pd, dict_type=zstd.DICT_TYPE_RAWCONTENT)).decompress(z)
            ok_stateful = dec == packed and dp.unpack_stream(dec, dictionary) == txs
            enc_hist[i], dec_hist[i] = packed, dec
            for h in (enc_hist, dec_hist):
                h.pop(i - w, None)

        mutated = bytearray(packed)
        mutated[len(mutated) // 2] ^= 0x01
        try:
            detected = dp.unpack_stream(bytes(mutated), dictionary) != txs
        except Exception:
            detected = True

        bad += not (ok_stateless and ok_stateful in (True, None) and detected)

    print(f"\n{len(test)} batches checked, {bad} problems.")
    print(f"decompressed.bin: {tot_raw:,} B, of which signed txs {tot_tx:,} B; "
          f"{tot_raw - tot_tx:,} B ({100 * (tot_raw - tot_tx) / tot_raw:.2f}%) lie outside the txs and are "
          f"not covered by these codecs.")
    print(f"{tot_esc} txs went through the escape path.")


if __name__ == "__main__":
    main()
