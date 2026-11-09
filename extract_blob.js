const { ethers } = require("ethers");
const fs = require("fs"); // Import the file system module

// Replace with your own Ethereum Mainnet RPC URL
const RPC_URL = "https://ethereum-rpc.publicnode.com";
const provider = new ethers.JsonRpcProvider(RPC_URL);

const ARBITRUM_SEQUENCER = "0x1c479675ad559dc151f6ec7ed3fbf8cee79582b6".toLowerCase();
const TARGET_BLOB_COUNT = 500;

async function getArbitrumBlobIds() {
  const blobIds = [];
  let currentBlockNum = await provider.getBlockNumber();

  console.log(`Scanning backwards from block ${currentBlockNum}...`);

  while (blobIds.length < TARGET_BLOB_COUNT) {
    try {
      const block = await provider.getBlock(currentBlockNum, true);

      if (block && block.prefetchedTransactions) {
        for (const tx of block.prefetchedTransactions) {
          if (tx.to && tx.to.toLowerCase() === ARBITRUM_SEQUENCER) {
            if (tx.type === 3 && tx.blobVersionedHashes) {
              blobIds.push(...tx.blobVersionedHashes);
              console.log(`Found ${tx.blobVersionedHashes.length} blob(s) in tx: ${tx.hash}`);
            }
          }
        }
      }

      currentBlockNum--;

    } catch (error) {
      console.error(`Error fetching block ${currentBlockNum}: ${error.message}`);
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
  }

  const finalBlobIds = blobIds.slice(0, TARGET_BLOB_COUNT);

  // Save the array to a formatted JSON file
  fs.writeFileSync("arbitrum_blob_ids.json", JSON.stringify(finalBlobIds, null, 2));

  console.log(`\n✅ Extraction Complete.`);
  console.log(`Total IDs Extracted: ${finalBlobIds.length}`);
  console.log(`Data successfully saved to arbitrum_blob_ids.json`);

  return finalBlobIds;
}

getArbitrumBlobIds().catch(console.error);
