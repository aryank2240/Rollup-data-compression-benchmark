#!/usr/bin/env python3
import argparse
import csv
import glob
import json
import os
import re
import shutil
import sys
import time
from collections import Counter
from datetime import datetime, timezone

import brotli
import requests

BLOBSCAN = "https://api.blobscan.com"
BLOB_SIZE = 131072
FIELD_ELEMENTS = 4096

def http_get(url, retries=5):
    last = None
    for attempt in range(retries):
        try:
            r = requests.get(url, timeout=90)
            if r.status_code == 200:
                return r
            if r.status_code in (429, 500, 502, 503, 504):
                last = f"HTTP {r.status_code}"
                time.sleep(2 ** attempt)
                continue
            r.raise_for_status()
        except requests.RequestException as e:
            last = e
            time.sleep(2 ** attempt)
    raise RuntimeError(f"GET {url} failed: {last}")

def clean_hex(text):
    t = text.strip().strip('"').strip()
    return t[2:] if t.startswith("0x") else t

def fetch_blob_hex(base, versioned_hash):
    r = http_get(f"{base}/blobs/{versioned_hash}/data")
    try:
        j = r.json()
        text = j["data"] if isinstance(j, dict) else j
    except ValueError:
        text = r.text
    return clean_hex(text)

def unpack_blob(blob):
    main = b"".join(blob[i + 1:i + 32] for i in range(0, len(blob), 32))
    spare, acc, bits = bytearray(), 0, 0
    for i in range(0, len(blob), 32):
        acc |= blob[i] << bits
        bits += 6
        if bits >= 8:
            spare.append(acc & 0xFF)
            acc >>= 8
            bits -= 8
    if bits != 0:
        raise ValueError(f"unexpected {bits} leftover spare bits")
    return main + bytes(spare)

def rlp_unwrap(stream):
    p = stream[0]
    if p < 0x80:
        return stream[:1], 1
    if p <= 0xB7:
        length, start = p - 0x80, 1
    elif p <= 0xBF:
        ll = p - 0xB7
        length, start = int.from_bytes(stream[1:1 + ll], "big"), 1 + ll
    else:
        raise ValueError("blob data does not start with an RLP string")
    return stream[start:start + length], length

def rlp_item(b, i=0):
    p = b[i]
    if p < 0x80:
        return b[i:i + 1], i + 1
    if p <= 0xBF:
        if p <= 0xB7:
            n, s = p - 0x80, i + 1
        else:
            ll = p - 0xB7
            n, s = int.from_bytes(b[i + 1:i + 1 + ll], "big"), i + 1 + ll
        if s + n > len(b):
            raise ValueError("truncated")
        return b[s:s + n], s + n
    if p <= 0xF7:
        n, s = p - 0xC0, i + 1
    else:
        ll = p - 0xF7
        n, s = int.from_bytes(b[i + 1:i + 1 + ll], "big"), i + 1 + ll
    end, items = s + n, []
    if end > len(b):
        raise ValueError("truncated")
    while s < end:
        it, s = rlp_item(b, s)
        items.append(it)
    return items, end

LAYOUT = {
    0: ["nonce", "gas_price", "gas", "to", "value", "data", "v", "r", "s"],
    1: ["chain_id", "nonce", "gas_price", "gas", "to", "value", "data", "access_list", "v", "r", "s"],
    2: ["chain_id", "nonce", "max_priority_fee", "max_fee", "gas", "to", "value", "data",
        "access_list", "v", "r", "s"],
    4: ["chain_id", "nonce", "max_priority_fee", "max_fee", "gas", "to", "value", "data",
        "access_list", "auth_list", "v", "r", "s"],
}
ib = lambda x: int.from_bytes(x, "big")

def parse_signed_tx(t, txs, bad):
    typ = 0 if t[0] >= 0xC0 else t[0]
    layout = LAYOUT.get(typ)
    if layout is None:
        bad[f"tx_type_{typ}"] += 1
        return
    try:
        fields, _ = rlp_item(t if typ == 0 else t[1:])
        rec = dict(zip(layout, fields))
        fee = rec["max_fee"] if "max_fee" in rec else rec["gas_price"]
        txs.append({
            "seq": len(txs),
            "type": typ,
            "chain_id": ib(rec["chain_id"]) if "chain_id" in rec else None,
            "nonce": ib(rec["nonce"]),
            "max_priority_fee": ib(rec["max_priority_fee"]) if "max_priority_fee" in rec else None,
            "fee_cap": ib(fee),
            "gas": ib(rec["gas"]),
            "to": "0x" + rec["to"].hex() if rec["to"] else "(create)",
            "value_wei": ib(rec["value"]),
            "data": rec["data"],
            "v": rec["v"], "r": rec["r"], "s": rec["s"],
            "raw_len": len(t),
        })
    except Exception:
        bad["tx_parse_error"] += 1

def parse_l2(msg, txs, l2_kinds, bad, depth=0):
    if not msg:
        return
    k = msg[0]
    l2_kinds[k] += 1
    if k == 3:
        if depth >= 16:
            bad["batch_too_deep"] += 1
            return
        pos = 1
        while pos + 8 <= len(msg):
            n = int.from_bytes(msg[pos:pos + 8], "big")
            pos += 8
            if pos + n > len(msg):
                bad["batch_len_overrun"] += 1
                break
            parse_l2(msg[pos:pos + n], txs, l2_kinds, bad, depth + 1)
            pos += n
    elif k == 4:
        parse_signed_tx(msg[1:], txs, bad)

def parse_batch(raw):
    segments, pos = [], 0
    bad = Counter()
    while pos < len(raw):
        try:
            item, pos = rlp_item(raw, pos)
        except (ValueError, IndexError):
            bad["trailing_or_truncated"] += 1
            break
        if isinstance(item, list):
            bad["list_segment"] += 1
            break
        segments.append(item)

    seg_kinds, l2_kinds, txs = Counter(), Counter(), []
    for seg in segments:
        if not seg:
            continue
        seg_kinds[seg[0]] += 1
        if seg[0] in (0, 1):
            body = seg[1:]
            if seg[0] == 1:
                try:
                    body = brotli.decompress(body)
                except brotli.error:
                    bad["segment_brotli"] += 1
                    continue
            parse_l2(body, txs, l2_kinds, bad)

    stats = {
        "n_segments": len(segments),
        "segment_kinds": {str(k): v for k, v in sorted(seg_kinds.items())},
        "l2_message_kinds": {str(k): v for k, v in sorted(l2_kinds.items())},
        "problems": dict(bad),
    }
    return txs, stats

def write_bytes(path, data):
    with open(path, "wb") as f:
        f.write(data)

def run_stages(folder, meta, baseline, keep_all):
    extra = os.path.join(folder, "extra")
    hex_files = sorted(glob.glob(os.path.join(extra, "blobs_hex", "blob_*.txt")),
                       key=lambda p: int(re.search(r"blob_(\d+)", p).group(1)))
    if not hex_files:
        raise RuntimeError("no blobs found to decode")
    meta["n_blobs"] = len(hex_files)

    bin_dir = os.path.join(extra, "blobs_bin")
    os.makedirs(bin_dir, exist_ok=True)
    blobs = []
    for i, p in enumerate(hex_files):
        with open(p, "r") as f:
            b = bytes.fromhex(clean_hex(f.read()))
        if len(b) != BLOB_SIZE:
            raise RuntimeError(f"blob_{i} is {len(b)} bytes, expected {BLOB_SIZE}")
        write_bytes(os.path.join(bin_dir, f"blob_{i}.bin"), b)
        blobs.append(b)

    stream = b"".join(unpack_blob(b) for b in blobs)
    payload, declared = rlp_unwrap(stream)
    meta["payload_declared_bytes"] = declared
    meta["payload_bytes"] = len(payload)
    meta["payload_complete"] = len(payload) == declared
    if len(payload) < declared:
        raise RuntimeError(f"payload truncated: declared {declared}, have {len(payload)}")
    write_bytes(os.path.join(extra, "payload.bin"), payload)

    flag = payload[0]
    meta["flag_byte"] = flag
    if flag != 0x00:
        raise RuntimeError(f"unsupported payload flag byte 0x{flag:02x}")
    d = brotli.Decompressor()
    out = d.process(payload[1:])
    meta["decompress_finished"] = d.is_finished()
    meta["decompressed_bytes"] = len(out)
    if not d.is_finished():
        raise RuntimeError("brotli stream did not finish")
    write_bytes(os.path.join(folder, "decompressed.bin"), out)
    if baseline:
        meta["brotli11_of_decompressed_bytes"] = len(brotli.compress(out, quality=11))

    txs, stats = parse_batch(out)
    meta.update(stats)
    meta["n_transactions"] = len(txs)
    meta["tx_bytes"] = sum(t["raw_len"] for t in txs)
    meta["signature_bytes"] = sum(len(t["r"]) + len(t["s"]) + len(t["v"]) for t in txs)
    meta["calldata_bytes"] = sum(len(t["data"]) for t in txs)

    with open(os.path.join(folder, "transactions.csv"), "w", newline="") as f:
        cols = ["seq", "type", "chain_id", "nonce", "max_priority_fee", "fee_cap", "gas", "to",
                "value_wei", "data_len", "selector", "sig_bytes", "raw_len"]
        w = csv.writer(f)
        w.writerow(cols)
        for t in txs:
            w.writerow([t["seq"], t["type"], t["chain_id"], t["nonce"], t["max_priority_fee"],
                        t["fee_cap"], t["gas"], t["to"], t["value_wei"], len(t["data"]),
                        t["data"][:4].hex(), len(t["r"]) + len(t["s"]) + len(t["v"]), t["raw_len"]])

    if keep_all:
        with open(os.path.join(extra, "transactions_full.jsonl"), "w") as f:
            for t in txs:
                row = dict(t)
                for k in ("data", "v", "r", "s"):
                    row[k] = row[k].hex()
                f.write(json.dumps(row) + "\n")

def save_meta(folder, meta):
    with open(os.path.join(folder, "meta.json"), "w") as f:
        json.dump(meta, f, indent=2)

def finish_ok(folder, meta, keep_all):
    meta["status"] = "ok"
    save_meta(folder, meta)
    if not keep_all:
        shutil.rmtree(os.path.join(folder, "extra"), ignore_errors=True)

def find_folder(out, short):
    hits = glob.glob(os.path.join(out, f"*_{short}"))
    return hits[0] if hits else None

def already_done(folder):
    mp = os.path.join(folder, "meta.json")
    if not (os.path.exists(mp) and os.path.exists(os.path.join(folder, "decompressed.bin"))):
        return None
    with open(mp) as f:
        m = json.load(f)
    return m if m.get("status") == "ok" else None

def process_tx(tx_hash, args):
    tx_hash = tx_hash.strip().lower()
    short = tx_hash[2:10]
    folder = find_folder(args.out, short)

    if folder and not args.force:
        done = already_done(folder)
        if done:
            return folder, done

    extra = os.path.join(folder, "extra") if folder else None
    tx = None
    if extra and os.path.exists(os.path.join(extra, "tx_blobscan.json")):
        with open(os.path.join(extra, "tx_blobscan.json")) as f:
            tx = json.load(f)
    if tx is None:
        tx = http_get(f"{args.base_url}/transactions/{tx_hash}").json()

    block = tx.get("blockNumber") or (tx.get("block") or {}).get("number")
    if folder is None:
        folder = os.path.join(args.out, f"{block}_{short}" if block else f"tx_{short}")
    extra = os.path.join(folder, "extra")
    os.makedirs(os.path.join(extra, "blobs_hex"), exist_ok=True)
    with open(os.path.join(extra, "tx_blobscan.json"), "w") as f:
        json.dump(tx, f, indent=2)

    meta = {"tx_hash": tx_hash, "eth_block": block,
            "processed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "status": "started"}
    try:
        blob_list = sorted(tx["blobs"], key=lambda b: b.get("index", 0))
        meta["versioned_hashes"] = [b["versionedHash"] for b in blob_list]
        for i, b in enumerate(blob_list):
            p = os.path.join(extra, "blobs_hex", f"blob_{i}.txt")
            if args.force or not os.path.exists(p):
                text = fetch_blob_hex(args.base_url, b["versionedHash"])
                with open(p, "w") as f:
                    f.write(text)
                time.sleep(args.delay)
        run_stages(folder, meta, args.baseline, args.keep_all)
        finish_ok(folder, meta, args.keep_all)
    except Exception as e:
        meta["status"] = f"error: {e}"
        save_meta(folder, meta)
        raise
    return folder, meta

def process_local(files, name, args):
    folder = os.path.join(args.out, f"local_{name}")
    os.makedirs(os.path.join(folder, "extra", "blobs_hex"), exist_ok=True)
    for i, src in enumerate(files):
        with open(src, "r") as f:
            text = clean_hex(f.read())
        with open(os.path.join(folder, "extra", "blobs_hex", f"blob_{i}.txt"), "w") as f:
            f.write(text)
    meta = {"source": "local files", "files": files,
            "processed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "status": "started"}
    try:
        run_stages(folder, meta, args.baseline, args.keep_all)
        finish_ok(folder, meta, args.keep_all)
    except Exception as e:
        meta["status"] = f"error: {e}"
        save_meta(folder, meta)
        raise
    return folder, meta

def rebuild_index(out):
    rows = []
    for mp in sorted(glob.glob(os.path.join(out, "*", "meta.json"))):
        with open(mp) as f:
            m = json.load(f)
        rows.append({
            "folder": os.path.basename(os.path.dirname(mp)),
            "tx_hash": m.get("tx_hash", ""),
            "eth_block": m.get("eth_block", ""),
            "status": m.get("status", ""),
            "n_blobs": m.get("n_blobs", ""),
            "payload_bytes": m.get("payload_bytes", ""),
            "decompressed_bytes": m.get("decompressed_bytes", ""),
            "brotli11_of_decompressed_bytes": m.get("brotli11_of_decompressed_bytes", ""),
            "n_transactions": m.get("n_transactions", ""),
            "calldata_bytes": m.get("calldata_bytes", ""),
            "signature_bytes": m.get("signature_bytes", ""),
        })
    if rows:
        with open(os.path.join(out, "index.csv"), "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0]))
            w.writeheader()
            w.writerows(rows)

SEQUENCER_INBOX = "0x1c479675ad559dc151f6ec7ed3fbf8cee79582b6"

def tx_hash_for_blob(base, versioned_hash):
    j = http_get(f"{base}/blobs/{versioned_hash}").json()
    cands = []
    for t in (j.get("transactions") or []):
        h = t.get("hash") or t.get("txHash") or t.get("transactionHash")
        if h:
            cands.append((h.lower(), (t.get("to") or "").lower()))
    for h, to in cands:
        if to == SEQUENCER_INBOX:
            return h
    return cands[0][0] if cands else None

def tx_hashes_from_blob_ids(path, args):
    with open(path) as f:
        ids = json.load(f)
    covered, tx_hashes = set(), []
    for n, vh in enumerate(ids, 1):
        if vh in covered:
            continue
        try:
            h = tx_hash_for_blob(args.base_url, vh)
            if not h:
                continue
            tx = http_get(f"{args.base_url}/transactions/{h}").json()
            covered.update(b["versionedHash"] for b in tx.get("blobs", []))
            covered.add(vh)
            tx_hashes.append(h)
        except Exception:
            pass
        time.sleep(args.delay)
    tx_hashes.reverse()
    out = os.path.join(args.out, "tx_hashes.txt")
    with open(out, "w") as f:
        f.write("\n".join(tx_hashes) + "\n")
    return tx_hashes

def main():
    ap = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("tx_hashes", nargs="*")
    ap.add_argument("--file")
    ap.add_argument("--out", default="arbitrum_data")
    ap.add_argument("--base-url", default=BLOBSCAN)
    ap.add_argument("--delay", type=float, default=0.5)
    ap.add_argument("--baseline", action="store_true")
    ap.add_argument("--keep-all", action="store_true")
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--local-blobs", nargs="+", metavar="HEXFILE")
    ap.add_argument("--blob-ids")
    ap.add_argument("--max-txs", type=int, default=0)
    ap.add_argument("--name", default="local")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)

    if args.local_blobs:
        process_local(args.local_blobs, args.name, args)
        rebuild_index(args.out)
        return
    hashes = list(args.tx_hashes)
    if args.file:
        with open(args.file) as f:
            hashes += [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    if args.blob_ids:
        hashes += tx_hashes_from_blob_ids(args.blob_ids, args)
    if args.max_txs:
        hashes = hashes[:args.max_txs]
    if not hashes:
        ap.error("give at least one transaction hash, --file, --blob-ids, or --local-blobs")
    
    for h in hashes:
        try:
            process_tx(h, args)
        except Exception:
            pass
    rebuild_index(args.out)

if __name__ == "__main__":
    main()
