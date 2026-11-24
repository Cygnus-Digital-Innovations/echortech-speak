import { deriveFromCode, deriveSenderCode } from "../crypto";
import type { WireMessage } from "../types";
import { api, b64 } from "./ui";

export interface SentChat {
  code: string;
  fromKey: boolean;
  id: string;
  status: string;
  recipient: string;
  last: WireMessage;
  threadKey: Uint8Array;
  accessToken: Uint8Array;
}

const BATCH = 20;
type Found = Pick<SentChat, "id" | "status" | "recipient" | "last"> | null;

async function lookup(codes: string[]): Promise<Found[]> {
  const { threads } = await api<{ threads: Found[] }>("/api/sender/lookup", { accessTokens: codes.map((code) => b64(deriveFromCode(code).accessToken)) });
  return threads;
}

export async function lookupCodes(codes: string[]): Promise<SentChat[]> {
  const chats: SentChat[] = [];
  for (let start = 0; start < codes.length; start += BATCH) {
    const batch = codes.slice(start, start + BATCH);
    (await lookup(batch)).forEach((thread, i) => {
      if (thread) chats.push({ ...deriveFromCode(batch[i]!), ...thread, code: batch[i]!, fromKey: false });
    });
  }
  return chats;
}

export async function findSentChats(privateKey: Uint8Array): Promise<{ chats: SentChat[]; nextIndex: number }> {
  const chats: SentChat[] = [];
  let nextIndex = 0;
  for (let start = 0; ; start += BATCH) {
    const codes = Array.from({ length: BATCH }, (_, i) => deriveSenderCode(privateKey, start + i));
    let found = false;
    (await lookup(codes)).forEach((thread, i) => {
      if (!thread) return;
      found = true;
      nextIndex = start + i + 1;
      chats.push({ ...deriveFromCode(codes[i]!), ...thread, code: codes[i]!, fromKey: true });
    });
    if (!found) return { chats, nextIndex };
  }
}
