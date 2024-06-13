import { Keypair } from "@solana/web3.js";
import { HDKey } from "micro-ed25519-hdkey";
import * as bip39 from "bip39";
import bs58 from 'bs58';

const mnemonic = "scheme spot photo card baby mountain device kick cradle pact join borrow";

// arguments: (mnemonic, password)
const seed = bip39.mnemonicToSeedSync(mnemonic, "");
const hd = HDKey.fromMasterSeed(seed.toString("hex"));

for (let i = 0; i < 2; i++) {
  const path = `m/44'/501'/${i}'/0'`;
  const keypair = Keypair.fromSeed(hd.derive(path).privateKey);
  console.log(`${path} => ${keypair.publicKey.toBase58()}`);
  console.log(bs58.encode(keypair.secretKey));
}