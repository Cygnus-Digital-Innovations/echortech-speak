import sodium from "libsodium-wrappers-sumo";
import type { WireMessage } from "./types.ts";

export const MAX_MESSAGE_CHARS = 4000;
export const THREAD_ID_BYTES = 16;
export const SEALED_THREAD_KEY_BYTES = 80;
export const CIPHERTEXT_BYTES = 16424;
export const MIN_PASSPHRASE_CHARS = 12;

const PADDED_BYTES = 16384;
const THREAD_KEY_BYTES = 32;
const CODE_BYTES = 20;
const CODE_CHARS = 32;
const CODE_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const HEADER_BYTES = 6;
const FORMAT_VERSION = 1;
const LOGIN_PREFIX = new TextEncoder().encode("speak-login-v1:");
const LOGIN_RANDOM_BYTES = 32;

export type Author = "sender" | "recipient";

export interface ReaderKeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export interface KeyFile {
  version: 1;
  publicKey: string;
  salt: string;
  opsLimit: number;
  memLimit: number;
  nonce: string;
  wrappedPrivateKey: string;
}

export interface MessageContent {
  author: Author;
  sentAt: Date;
  text: string;
}

export interface MessagePosition {
  threadId: Uint8Array;
  seq: number;
}

export class CryptoError extends Error {
  override name = "CryptoError";
}

export async function initCrypto(): Promise<void> {
  await sodium.ready;
}

export function newThreadId(): Uint8Array {
  return sodium.randombytes_buf(THREAD_ID_BYTES);
}

export function generateReaderKeys(): ReaderKeyPair {
  const { publicKey, privateKey } = sodium.crypto_box_keypair();
  return { publicKey, privateKey };
}

function passphraseKey(passphrase: string, salt: Uint8Array, opsLimit: number, memLimit: number): Uint8Array {
  return sodium.crypto_pwhash(
    sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
    passphrase,
    salt,
    opsLimit,
    memLimit,
    sodium.crypto_pwhash_ALG_ARGON2ID13,
  );
}

export function createKeyFile(keys: ReaderKeyPair, passphrase: string): KeyFile {
  if (Array.from(passphrase).length < MIN_PASSPHRASE_CHARS) {
    throw new CryptoError(`Passphrase must be at least ${MIN_PASSPHRASE_CHARS} characters`);
  }
  const salt = sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);
  const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  const opsLimit = sodium.crypto_pwhash_OPSLIMIT_MODERATE;
  const memLimit = sodium.crypto_pwhash_MEMLIMIT_MODERATE;
  const wrapped = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    keys.privateKey,
    keys.publicKey,
    null,
    nonce,
    passphraseKey(passphrase, salt, opsLimit, memLimit),
  );
  return {
    version: 1,
    publicKey: sodium.to_base64(keys.publicKey),
    salt: sodium.to_base64(salt),
    opsLimit,
    memLimit,
    nonce: sodium.to_base64(nonce),
    wrappedPrivateKey: sodium.to_base64(wrapped),
  };
}

export function openKeyFile(file: KeyFile, passphrase: string): ReaderKeyPair {
  if (
    file.version !== 1 ||
    file.opsLimit < sodium.crypto_pwhash_OPSLIMIT_MODERATE ||
    file.opsLimit > sodium.crypto_pwhash_OPSLIMIT_SENSITIVE ||
    file.memLimit < sodium.crypto_pwhash_MEMLIMIT_MODERATE ||
    file.memLimit > sodium.crypto_pwhash_MEMLIMIT_SENSITIVE
  ) {
    throw new CryptoError("Invalid key file");
  }
  try {
    const publicKey = sodium.from_base64(file.publicKey);
    const privateKey = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      sodium.from_base64(file.wrappedPrivateKey),
      publicKey,
      sodium.from_base64(file.nonce),
      passphraseKey(passphrase, sodium.from_base64(file.salt), file.opsLimit, file.memLimit),
    );
    return { publicKey, privateKey };
  } catch {
    throw new CryptoError("Wrong passphrase or damaged key file");
  }
}

function encodeCode(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += CODE_ALPHABET[(value >>> bits) & 31];
    }
    value &= (1 << bits) - 1;
  }
  return out.match(/.{4}/g)!.join("-");
}

function decodeCode(code: string): Uint8Array {
  const clean = code
    .toUpperCase()
    .replace(/[\s-]/g, "")
    .replace(/O/g, "0")
    .replace(/[IL]/g, "1");
  if (clean.length !== CODE_CHARS) throw new CryptoError("Invalid secret code");
  const out = new Uint8Array(CODE_BYTES);
  let bits = 0;
  let value = 0;
  let index = 0;
  for (const char of clean) {
    const digit = CODE_ALPHABET.indexOf(char);
    if (digit < 0) throw new CryptoError("Invalid secret code");
    value = (value << 5) | digit;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out[index++] = (value >>> bits) & 255;
      value &= (1 << bits) - 1;
    }
  }
  return out;
}

export function newSecretCode(): string {
  return encodeCode(sodium.randombytes_buf(CODE_BYTES));
}

export function deriveFromCode(code: string): { threadKey: Uint8Array; accessToken: Uint8Array } {
  const master = sodium.crypto_generichash(sodium.crypto_kdf_KEYBYTES, decodeCode(code), null);
  return {
    threadKey: sodium.crypto_kdf_derive_from_key(THREAD_KEY_BYTES, 1, "spkthrkv", master),
    accessToken: sodium.crypto_kdf_derive_from_key(32, 2, "spkaccsv", master),
  };
}

export function hashAccessToken(accessToken: Uint8Array): Uint8Array {
  return sodium.crypto_hash_sha256(accessToken);
}

export function newOneWayThreadKey(): Uint8Array {
  return sodium.randombytes_buf(THREAD_KEY_BYTES);
}

export function sealThreadKey(threadKey: Uint8Array, recipientPublicKey: Uint8Array): Uint8Array {
  if (threadKey.length !== THREAD_KEY_BYTES) throw new CryptoError("Invalid thread key");
  return sodium.crypto_box_seal(threadKey, recipientPublicKey);
}

export function openThreadKey(sealed: Uint8Array, keys: ReaderKeyPair): Uint8Array {
  let threadKey: Uint8Array;
  try {
    threadKey = sodium.crypto_box_seal_open(sealed, keys.publicKey, keys.privateKey);
  } catch {
    throw new CryptoError("Could not unlock thread key");
  }
  if (threadKey.length !== THREAD_KEY_BYTES) throw new CryptoError("Invalid thread key");
  return threadKey;
}

function associatedData({ threadId, seq }: MessagePosition): Uint8Array {
  if (threadId.length !== THREAD_ID_BYTES) throw new CryptoError("Invalid thread id");
  if (!Number.isSafeInteger(seq) || seq < 1) throw new CryptoError("Invalid message number");
  const out = new Uint8Array(THREAD_ID_BYTES + 8);
  out.set(threadId);
  new DataView(out.buffer).setBigUint64(THREAD_ID_BYTES, BigInt(seq));
  return out;
}

export function encryptMessage(
  threadKey: Uint8Array,
  position: MessagePosition,
  content: MessageContent,
): Uint8Array {
  const additional = associatedData(position);
  if (content.text.trim().length === 0) throw new CryptoError("Message is empty");
  if (Array.from(content.text).length > MAX_MESSAGE_CHARS) throw new CryptoError("Message is too long");

  const text = new TextEncoder().encode(content.text);
  const plain = new Uint8Array(HEADER_BYTES + text.length);
  const header = new DataView(plain.buffer);
  header.setUint8(0, FORMAT_VERSION);
  header.setUint8(1, content.author === "sender" ? 0 : 1);
  header.setUint32(2, Math.floor(content.sentAt.getTime() / 60000));
  plain.set(text, HEADER_BYTES);

  const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  const sealed = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    sodium.pad(plain, PADDED_BYTES),
    additional,
    null,
    nonce,
    threadKey,
  );
  const out = new Uint8Array(nonce.length + sealed.length);
  out.set(nonce);
  out.set(sealed, nonce.length);
  return out;
}

export function decryptMessage(
  threadKey: Uint8Array,
  position: MessagePosition,
  ciphertext: Uint8Array,
): MessageContent {
  const additional = associatedData(position);
  if (ciphertext.length !== CIPHERTEXT_BYTES) throw new CryptoError("Invalid message size");
  const nonceBytes = sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
  let plain: Uint8Array;
  try {
    plain = sodium.unpad(
      sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        null,
        ciphertext.subarray(nonceBytes),
        additional,
        ciphertext.subarray(0, nonceBytes),
        threadKey,
      ),
      PADDED_BYTES,
    );
  } catch {
    throw new CryptoError("Message could not be decrypted");
  }
  const header = new DataView(plain.buffer, plain.byteOffset, plain.byteLength);
  if (plain.length < HEADER_BYTES || header.getUint8(0) !== FORMAT_VERSION) {
    throw new CryptoError("Unsupported message format");
  }
  return {
    author: header.getUint8(1) === 0 ? "sender" : "recipient",
    sentAt: new Date(header.getUint32(2) * 60000),
    text: new TextDecoder().decode(plain.subarray(HEADER_BYTES)),
  };
}

// The server records which side posted each message. Both sides hold the
// thread key, so the author inside the encryption alone could be forged.
export function decryptWireMessage(threadKey: Uint8Array, threadId: Uint8Array, message: WireMessage): MessageContent {
  const content = decryptMessage(threadKey, { threadId, seq: message.seq }, sodium.from_base64(message.ciphertext));
  if (content.author !== message.author) throw new CryptoError("Message author doesn't match");
  return content;
}

export function createLoginChallenge(
  recipientPublicKey: Uint8Array,
  answer: Uint8Array = sodium.randombytes_buf(LOGIN_RANDOM_BYTES),
): {
  challenge: Uint8Array;
  expectedAnswer: Uint8Array;
} {
  if (answer.length !== LOGIN_RANDOM_BYTES) throw new CryptoError("Invalid login answer");
  const expectedAnswer = answer;
  const plain = new Uint8Array(LOGIN_PREFIX.length + LOGIN_RANDOM_BYTES);
  plain.set(LOGIN_PREFIX);
  plain.set(expectedAnswer, LOGIN_PREFIX.length);
  return { challenge: sodium.crypto_box_seal(plain, recipientPublicKey), expectedAnswer };
}

// The prefix check stops a hacked server passing off a sealed thread key as a
// login challenge and getting the browser to hand back the unlocked key.
export function answerLoginChallenge(challenge: Uint8Array, keys: ReaderKeyPair): Uint8Array {
  let plain: Uint8Array;
  try {
    plain = sodium.crypto_box_seal_open(challenge, keys.publicKey, keys.privateKey);
  } catch {
    throw new CryptoError("Invalid login challenge");
  }
  const prefix = plain.subarray(0, LOGIN_PREFIX.length);
  if (
    plain.length !== LOGIN_PREFIX.length + LOGIN_RANDOM_BYTES ||
    !sodium.memcmp(prefix, LOGIN_PREFIX)
  ) {
    throw new CryptoError("Invalid login challenge");
  }
  return plain.slice(LOGIN_PREFIX.length);
}
