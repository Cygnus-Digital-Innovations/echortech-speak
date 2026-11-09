export interface DirectoryEntry {
  keyId: number;
  name: string;
  publicKey: string;
  status: "active" | "retired";
}

export interface WireMessage {
  seq: number;
  ciphertext: string;
}

export interface PowSolution {
  payload: string;
  signature: string;
  counter: number;
}

export const MAX_MESSAGES_PER_THREAD = 200;

export function hasLeadingZeroBits(hash: Uint8Array, bits: number): boolean {
  for (let i = 0; i < bits; i++) {
    if ((hash[i >> 3]! >> (7 - (i & 7))) & 1) return false;
  }
  return true;
}
