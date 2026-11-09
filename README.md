

## Main files

| File | What it does |
|---|---|
| `extract_blob.js`, `extract_days.js` | Find Arbitrum batch blobs on Ethereum (latest 500 blobs / 6 sampled days) |
| `arbitrum_batch_pipeline.py` | Downloads blobs, decodes them to transactions (`arbitrum_data/`) |
| `column.py` | Where the compressed bytes go, per field |
| `calldata_sampling.py`, `recurrence.py` | Look inside calldata; how often words repeat across batches |
| `varint_pack.py` | Encoding 1: varints instead of RLP |
| `domain_pack.py` | Encoding 2: flags byte, fee deltas, ABI-word tags |
| `dict_pack.py` | Encoding 3: address/selector dictionary |
| `zstd_baseline.py` | zstd baselines |
| `cache_pack.py`, `history_pack.py`, `history_multiday.py` | Use earlier batches (word cache, history) |
| `verify_roundtrip.py` | Checks decoding gives back the exact transactions |
| `blob_cost_model.py` | Savings in blobs and dollars |

## Run

```bash
pip install brotli requests zstandard
npm install ethers

node extract_blob.js                     
python arbitrum_batch_pipeline.py --blob-ids arbitrum_blob_ids.json --out arbitrum_data

python column.py
python dict_pack.py --train-frac 0.7      
python zstd_baseline.py --train-frac 0.7
python history_pack.py --train-frac 0.7 --windows 1 3
python verify_roundtrip.py --train-frac 0.7
python blob_cost_model.py
```

Multi-day data: `node extract_days.js`, then
`python arbitrum_batch_pipeline.py --file tx_hashes_days.txt --out arbitrum_data_days`, then
`python history_multiday.py --data-dir arbitrum_data_days --zstd-only`.


