// What this browser remembers, so people aren't asked for codes and keys on every visit.
import { lockWithPin, type PinLock, type ReaderKeyPair } from "../crypto";
import { b64, fromB64 } from "./ui";

const CODES = "sayit.codes";
const KEY = "sayit.key";
const READ = "sayit.read";

export function savedCodes(): string[] {
  try {
    const codes = JSON.parse(localStorage.getItem(CODES) ?? "[]") as unknown;
    return Array.isArray(codes) ? codes.filter((code): code is string => typeof code === "string") : [];
  } catch {
    return [];
  }
}

export function saveCode(code: string): boolean {
  try {
    const codes = savedCodes();
    if (!codes.includes(code)) localStorage.setItem(CODES, JSON.stringify([...codes, code]));
    return savedCodes().includes(code);
  } catch {
    return false;
  }
}

export function removeCodes(remove: string[]): void {
  try {
    localStorage.setItem(CODES, JSON.stringify(savedCodes().filter((code) => !remove.includes(code))));
  } catch {
    // Nothing stored.
  }
}

export function readUpTo(id: string): number {
  try {
    return (JSON.parse(localStorage.getItem(READ) ?? "{}") as Record<string, number>)[id] ?? 0;
  } catch {
    return 0;
  }
}

export function markRead(id: string, seq: number): void {
  try {
    const read = JSON.parse(localStorage.getItem(READ) ?? "{}") as Record<string, number>;
    localStorage.setItem(READ, JSON.stringify({ ...read, [id]: seq }));
  } catch {
    // The reply dot just stays on.
  }
}

export function forgetCodes(): void {
  try {
    localStorage.removeItem(CODES);
  } catch {
    // Nothing stored.
  }
}

// With a PIN, the saved key is locked and Messages asks for the PIN before opening.
export function rememberKeys(keys: ReaderKeyPair, pin = ""): boolean {
  try {
    const stored = pin ? { pin: lockWithPin(keys, pin) } : { publicKey: b64(keys.publicKey), privateKey: b64(keys.privateKey) };
    localStorage.setItem(KEY, JSON.stringify(stored));
    return localStorage.getItem(KEY) !== null;
  } catch {
    return false;
  }
}

export function rememberedKeys(): ReaderKeyPair | null {
  try {
    const stored = JSON.parse(localStorage.getItem(KEY) ?? "null") as { publicKey: string; privateKey: string; pin?: PinLock } | null;
    return stored && !stored.pin ? { publicKey: fromB64(stored.publicKey), privateKey: fromB64(stored.privateKey) } : null;
  } catch {
    return null;
  }
}

export function pinLock(): PinLock | null {
  try {
    const stored = JSON.parse(localStorage.getItem(KEY) ?? "null") as { pin?: PinLock } | null;
    return stored?.pin ?? null;
  } catch {
    return null;
  }
}

export function forgetKeys(): void {
  try {
    localStorage.removeItem(KEY);
  } catch {
    // Nothing stored.
  }
}
