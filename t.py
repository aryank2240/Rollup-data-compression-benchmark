import brotli, csv
from collections import Counter

raw = open("batch_decompressed.bin", "rb").read()

def rlp_item(b, i=0):
    """Return (item, next_index). Item is bytes or a list of items."""
    p = b[i]
    if p < 0x80:
        return b[i:i + 1], i + 1
    if p <= 0xBF:                                   # string
        if p <= 0xB7:
            n, s = p - 0x80, i + 1
        else:
            ll = p - 0xB7
            n, s = int.from_bytes(b[i + 1:i + 1 + ll], "big"), i + 1 + ll
        if s + n > len(b):
            raise ValueError("truncated")
        return b[s:s + n], s + n
    if p <= 0xF7:                                   # list
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
    2: ["chain_id", "nonce", "max_priority_fee", "max_fee", "gas", "to", "value", "data", "access_list", "v", "r", "s"],
}
ib = lambda x: int.from_bytes(x, "big")
seg_kinds, l2_kinds, bad, txs = Counter(), Counter(), Counter(), []

def parse_signed_tx(t):
    typ = 0 if t[0] >= 0xC0 else t[0]
    if typ not in LAYOUT:
        bad[f"tx_type_{typ}"] += 1
        return
    try:
        fields, _ = rlp_item(t if typ == 0 else t[1:])
        rec = dict(zip(LAYOUT[typ], fields))
        fee = rec["max_fee"] if "max_fee" in rec else rec["gas_price"]
        txs.append({
            "type": typ, "nonce": ib(rec["nonce"]),
            "to": "0x" + rec["to"].hex() if rec["to"] else "(create)",
            "value_wei": ib(rec["value"]), "gas": ib(rec["gas"]), "fee_cap": ib(fee),
            "data_len": len(rec["data"]), "selector": rec["data"][:4].hex(),
            "sig_bytes": len(rec["r"]) + len(rec["s"]) + len(rec["v"]),
            "raw_len": len(t),
        })
    except Exception:
        bad["tx_parse_error"] += 1

def parse_l2(msg, depth=0):
    if not msg:
        return
    k = msg[0]
    l2_kinds[k] += 1
    if k == 3:                                      # batch of nested messages
        pos = 1
        while pos + 8 <= len(msg):
            n = int.from_bytes(msg[pos:pos + 8], "big")
            pos += 8
            if pos + n > len(msg):
                bad["batch_len_overrun"] += 1
                break
            parse_l2(msg[pos:pos + n], depth + 1)
            pos += n
    elif k == 4:                                    # signed tx
        parse_signed_tx(msg[1:])

# 1. split into segments
pos, segments = 0, []
while pos < len(raw):
    try:
        item, pos = rlp_item(raw, pos)
    except (ValueError, IndexError):
        break
    if isinstance(item, list):
        bad["list_segment"] += 1
        break
    segments.append(item)

# 2. walk segments
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
                bad["seg_brotli"] += 1
                continue
        parse_l2(body)

# 3. report
print("segments:", len(segments), "| kinds:", dict(seg_kinds))
print("L2 message kinds:", dict(l2_kinds), "| problems:", dict(bad))
n = len(txs)
tot = sum(t["raw_len"] for t in txs)
sig = sum(t["sig_bytes"] for t in txs)
dat = sum(t["data_len"] for t in txs)
print(f"\n{n} transactions, {tot} tx bytes of {len(raw)} total")
if n:
    print(f"  signatures: {sig} B ({100*sig/tot:.1f}%) | calldata: {dat} B ({100*dat/tot:.1f}%) "
          f"| to-address: {20*n} B ({100*20*n/tot:.1f}%)")
    print("top destinations:", Counter(t["to"] for t in txs).most_common(5))
    print("top selectors:   ", Counter(t["selector"] for t in txs).most_common(5))
    print("\nfirst 10 txs:")
    for t in txs[:10]:
        print(t)
    with open("txs.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(txs[0]))
        w.writeheader()
        w.writerows(txs)
    print("\nwrote txs.csv")
