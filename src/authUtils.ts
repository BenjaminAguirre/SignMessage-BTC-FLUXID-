// src/utils/authUtils.ts
import "dotenv/config";
import * as bitcoinMessage from "bitcoinjs-message";
import { ECPairFactory } from "ecpair";
import * as ecc from "@bitcoinerlab/secp256k1";
import axios from "axios";

export interface Network {
  messagePrefix: string;
  bech32: string;
  bip32: { public: number; private: number };
  pubKeyHash: number;
  scriptHash: number;
  wif: number;
}

export const bitcoin: Network = {
  messagePrefix: '\x18Bitcoin Signed Message:\n',
  bech32: 'bc',
  bip32: { public: 0x0488b21e, private: 0x0488ade4 },
  pubKeyHash: 0x00,
  scriptHash: 0x05,
  wif: 0x80,
};

const ECPair = ECPairFactory(ecc);

export function SignMessage(message: string, privKey: string): string {
  try {
    const keyPair = ECPair.fromWIF(privKey, bitcoin);
    const privateKey = keyPair.privateKey;
    if (!privateKey) throw new Error("Private key not found.");

    const privKeyBuffer = Buffer.from(privateKey);
    const compressed = true;

    const signature = bitcoinMessage.sign(message, privKeyBuffer, compressed);
    return signature.toString("base64");
  } catch (error) {
    console.error("Error signing message:", error);
    return "Error signing";
  }
}

export async function GetZelIdAuthHeader(
  zelid: string,
  privKey: string,
  loginPhrase: string
): Promise<string> {
  try {
    const FLUX_API_URL = "https://api.runonflux.io";
    const signature = SignMessage(loginPhrase, privKey);
    const encodedSignature = encodeURIComponent(signature);

    const authHeader = `zelid=${zelid}&signature=${encodedSignature}&loginPhrase=${loginPhrase}`;

    const body = { loginPhrase, zelid, signature };
    const verify = await axios.post(`${FLUX_API_URL}/id/verifylogin`, body);

    if (verify.data.status === "success") {
      return authHeader;
    }
    return "Error verifying login";
  } catch (error) {
    console.error("Error fetching or verifying login phrase:", error);
    return "Error signing";
  }
}

// CLI entry
if (require.main === module) {
  const [,, privKey, message] = process.argv;
  if (!privKey || !message) {
    console.log("Usage: ts-node src/utils/authUtils.ts <WIF-privKey> <message>");
    process.exit(1);
  }
  const sig = SignMessage(message, privKey);
  console.log("Signature:", sig);
}

