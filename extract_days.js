const { ethers } = require("ethers");
const fs = require("fs");

const RPC_URL = process.env.RPC_URL || "https://ethereum-rpc.publicnode.com";
const provider = new ethers.JsonRpcProvider(RPC_URL);
const SEQ = "0x1c479675ad559dc151f6ec7ed3fbf8cee79582b6";
const DAYS_BACK = (process.env.DAYS_BACK || "1,2,3,5,8,12").split(",").map(Number);
const PER_DAY = Number(process.env.PER_DAY || 40);   // batch transactions per chunk
const BLOCKS_PER_DAY = 7200;
const OUT = process.env.OUT || "tx_hashes_days.txt";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function getBlockRetry(n) {
  for (let a = 0; a < 6; a++) {
    try {
      return await provider.getBlock(n, true);
    } catch (e) {
      console.error(`block ${n}: ${e.message}, retry ${a + 1}`);
      await sleep(1000 * (a + 1));
    }
  }
  throw new Error(`block ${n} failed after retries`);
}

async function collect(startBlock, want) {
  const hashes = [];
  let n = startBlock;
  while (hashes.length < want) {
    const block = await getBlockRetry(n);
    if (!block) { console.error(`reached chain head at ${n}`); break; }
    for (const tx of block.prefetchedTransactions || []) {
      if (hashes.length >= want) break;
      if (tx.to && tx.to.toLowerCase() === SEQ && tx.type === 3) hashes.push(tx.hash);
    }
    n++;
  }
  return { hashes, endBlock: n - 1 };
}

async function main() {
  const head = await provider.getBlockNumber();
  fs.writeFileSync(OUT, `# head ${head}, ${PER_DAY} batches per chunk\n`);
  for (const d of DAYS_BACK) {
    const start = head - d * BLOCKS_PER_DAY;
    console.log(`chunk ${d} days back: scanning from block ${start}...`);
    const { hashes, endBlock } = await collect(start, PER_DAY);
    fs.appendFileSync(OUT, `# ${d} days back: blocks ${start}..${endBlock}\n${hashes.join("\n")}\n`);
    console.log(`  ${hashes.length} batch txs, blocks ${start}..${endBlock}`);
  }
  console.log(`saved ${OUT}`);
}

main().catch(console.error);
