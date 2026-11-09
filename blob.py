import requests, time

BASE = "https://api.blobscan.com"
TX = "0x1bcbba24043bd809ffa37a306d145956a84c6e7f1adda577b4e3f7275c6d01a1"

tx = requests.get(f"{BASE}/transactions/{TX}", timeout=30).json()
blobs = sorted(tx["blobs"], key=lambda b: b.get("index", 0))

for i, b in enumerate(blobs):
    vh = b["versionedHash"]
    r = requests.get(f"{BASE}/blobs/{vh}/data", timeout=60)
    r.raise_for_status()
    try:
        j = r.json()
        text = j["data"] if isinstance(j, dict) else j
    except ValueError:
        text = r.text
    text = text.strip().strip('"')
    open(f"blob_{i}.txt", "w").write(text)
    print(i, vh, len(text), "chars")   # expect 262146 (0x + 262144 hex digits)
    time.sleep(0.5)                    # be polite to the free API
