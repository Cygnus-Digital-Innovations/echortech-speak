export interface DirectoryEntry {
  keyId: number;
  name: string;
  publicKey: string;
  status: "active" | "retired" | "revoked";
}

export interface WireMessage {
  seq: number;
  ciphertext: string;
  author: "sender" | "recipient";
}

export interface PowSolution {
  payload: string;
  signature: string;
  counter: number;
}

export const MAX_MESSAGES_PER_THREAD = 200;

export function validateDirectory(directory: unknown): asserts directory is DirectoryEntry[] {
  if (!Array.isArray(directory)) throw new Error("Directory must be a list");
  const ids = new Set<number>();
  const keys = new Set<string>();
  const activeNames = new Set<string>();
  for (const entry of directory as DirectoryEntry[]) {
    const label = JSON.stringify(entry?.name ?? entry);
    if (!Number.isSafeInteger(entry?.keyId) || entry.keyId < 1) throw new Error(`Invalid keyId for ${label}`);
    if (ids.has(entry.keyId)) throw new Error(`Duplicate keyId ${entry.keyId}`);
    ids.add(entry.keyId);
    if (typeof entry.name !== "string" || entry.name.trim() === "") throw new Error(`Invalid name for keyId ${entry.keyId}`);
    if (typeof entry.publicKey !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(entry.publicKey)) throw new Error(`Invalid publicKey for ${label}`);
    if (keys.has(entry.publicKey)) throw new Error(`Duplicate publicKey for ${label}`);
    keys.add(entry.publicKey);
    if (!["active", "retired", "revoked"].includes(entry.status)) throw new Error(`Invalid status for ${label}`);
    if (entry.status === "active") {
      if (activeNames.has(entry.name)) throw new Error(`More than one active key for ${label}`);
      activeNames.add(entry.name);
    }
  }
}

export function hasLeadingZeroBits(hash: Uint8Array, bits: number): boolean {
  for (let i = 0; i < bits; i++) {
    if ((hash[i >> 3]! >> (7 - (i & 7))) & 1) return false;
  }
  return true;
}
