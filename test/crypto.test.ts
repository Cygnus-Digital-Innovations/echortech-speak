import { beforeAll, describe, expect, it } from "vitest";
import {
  answerLoginChallenge,
  CIPHERTEXT_BYTES,
  createKeyFile,
  createLoginChallenge,
  CryptoError,
  decryptMessage,
  deriveFromCode,
  encryptMessage,
  generateReaderKeys,
  hashAccessToken,
  initCrypto,
  MAX_MESSAGE_CHARS,
  newOneWayThreadKey,
  newSecretCode,
  newThreadId,
  openKeyFile,
  openThreadKey,
  SEALED_THREAD_KEY_BYTES,
  sealThreadKey,
  type MessageContent,
} from "../src/crypto";

const PASSPHRASE = "correct horse battery";
const sentAt = new Date("2026-11-09T10:15:00.000Z");
const message = (text: string, author: MessageContent["author"] = "sender"): MessageContent => ({
  author,
  sentAt,
  text,
});
const flipByte = (bytes: Uint8Array, index = bytes.length - 1): Uint8Array => {
  const copy = bytes.slice();
  copy[index]! ^= 1;
  return copy;
};

beforeAll(initCrypto);

describe("key files", () => {
  it("restores the key pair with the right passphrase", () => {
    const keys = generateReaderKeys();
    const opened = openKeyFile(createKeyFile(keys, PASSPHRASE), PASSPHRASE);
    expect(opened.publicKey).toEqual(keys.publicKey);
    expect(opened.privateKey).toEqual(keys.privateKey);
  });

  it("never contains the raw private key", () => {
    const keys = generateReaderKeys();
    const file = JSON.stringify(createKeyFile(keys, PASSPHRASE));
    expect(file).not.toContain(Buffer.from(keys.privateKey).toString("base64url").replace(/=+$/, ""));
  });

  it("rejects a wrong passphrase", () => {
    const file = createKeyFile(generateReaderKeys(), PASSPHRASE);
    expect(() => openKeyFile(file, "wrong passphrase here")).toThrow(CryptoError);
  });

  it("rejects a short passphrase", () => {
    expect(() => createKeyFile(generateReaderKeys(), "short")).toThrow(CryptoError);
  });

  it("rejects a key file whose public key was swapped", () => {
    const file = createKeyFile(generateReaderKeys(), PASSPHRASE);
    const other = createKeyFile(generateReaderKeys(), PASSPHRASE);
    expect(() => openKeyFile({ ...file, publicKey: other.publicKey }, PASSPHRASE)).toThrow(CryptoError);
  });

  it("rejects weakened or absurd work settings", () => {
    const file = createKeyFile(generateReaderKeys(), PASSPHRASE);
    expect(() => openKeyFile({ ...file, memLimit: 1024 }, PASSPHRASE)).toThrow(CryptoError);
    expect(() => openKeyFile({ ...file, opsLimit: 1e9 }, PASSPHRASE)).toThrow(CryptoError);
  });

  it("rejects malformed key file contents", () => {
    const file = createKeyFile(generateReaderKeys(), PASSPHRASE);
    expect(() => openKeyFile({ ...file, nonce: "%%%" }, PASSPHRASE)).toThrow(CryptoError);
  });
});

describe("secret codes", () => {
  it("is grouped and unique", () => {
    const code = newSecretCode();
    expect(code).toMatch(/^([0-9A-Z]{4}-){7}[0-9A-Z]{4}$/);
    expect(newSecretCode()).not.toBe(code);
  });

  it("derives the same keys every time, and two different keys", () => {
    const code = newSecretCode();
    const first = deriveFromCode(code);
    expect(deriveFromCode(code)).toEqual(first);
    expect(first.threadKey).not.toEqual(first.accessToken);
  });

  it("tolerates lowercase, spaces and missing dashes", () => {
    const code = newSecretCode();
    const messy = ` ${code.toLowerCase().replace(/-/g, " ")} `;
    expect(deriveFromCode(messy)).toEqual(deriveFromCode(code));
  });

  it("gives different keys for a different code", () => {
    expect(deriveFromCode(newSecretCode()).threadKey).not.toEqual(deriveFromCode(newSecretCode()).threadKey);
  });

  it.each(["", "ABCD-EFGH", "U".repeat(32), "!".repeat(32), "0".repeat(33)])("rejects invalid code %j", (code) => {
    expect(() => deriveFromCode(code)).toThrow(CryptoError);
  });

  it("hashes the access token to 32 bytes without exposing it", () => {
    const { accessToken } = deriveFromCode(newSecretCode());
    const hash = hashAccessToken(accessToken);
    expect(hash).toHaveLength(32);
    expect(hash).not.toEqual(accessToken);
  });
});

describe("sealing the thread key", () => {
  it("only the recipient can unlock it, and it fits the schema", () => {
    const keys = generateReaderKeys();
    const threadKey = newOneWayThreadKey();
    const sealed = sealThreadKey(threadKey, keys.publicKey);
    expect(sealed).toHaveLength(SEALED_THREAD_KEY_BYTES);
    expect(openThreadKey(sealed, keys)).toEqual(threadKey);
  });

  it("fails for another person's key", () => {
    const sealed = sealThreadKey(newOneWayThreadKey(), generateReaderKeys().publicKey);
    expect(() => openThreadKey(sealed, generateReaderKeys())).toThrow(CryptoError);
  });

  it("fails if tampered with", () => {
    const keys = generateReaderKeys();
    const sealed = sealThreadKey(newOneWayThreadKey(), keys.publicKey);
    expect(() => openThreadKey(flipByte(sealed), keys)).toThrow(CryptoError);
  });

  it("refuses a thread key of the wrong size", () => {
    expect(() => sealThreadKey(new Uint8Array(16), generateReaderKeys().publicKey)).toThrow(CryptoError);
  });
});

describe("messages", () => {
  const position = () => ({ threadId: newThreadId(), seq: 1 });

  it.each([
    ["English", "The manager is taking bribes"],
    ["Urdu", "یہ ایک خفیہ پیغام ہے"],
    ["Hindi", "यह एक गुप्त संदेश है"],
    ["emoji", "🔐👩🏽‍💻🎉"],
    ["new lines and quotes", 'line 1\nline "2"\t\\end'],
    ["control characters", "\u0001\u0002 text"],
  ])("round-trips %s", (_name, text) => {
    const key = newOneWayThreadKey();
    const at = position();
    expect(decryptMessage(key, at, encryptMessage(key, at, message(text)))).toEqual(message(text));
  });

  it("keeps who wrote it", () => {
    const key = newOneWayThreadKey();
    const at = position();
    expect(decryptMessage(key, at, encryptMessage(key, at, message("hi", "recipient"))).author).toBe("recipient");
  });

  it("makes every message exactly the same size", () => {
    const key = newOneWayThreadKey();
    const at = position();
    for (const text of ["a", "b".repeat(MAX_MESSAGE_CHARS), "😀".repeat(MAX_MESSAGE_CHARS), "\u0001".repeat(MAX_MESSAGE_CHARS)]) {
      expect(encryptMessage(key, at, message(text))).toHaveLength(CIPHERTEXT_BYTES);
    }
  });

  it("round-trips the longest allowed emoji message", () => {
    const key = newOneWayThreadKey();
    const at = position();
    const text = "😀".repeat(MAX_MESSAGE_CHARS);
    expect(decryptMessage(key, at, encryptMessage(key, at, message(text))).text).toBe(text);
  });

  it("rejects one character over the limit", () => {
    const text = "a".repeat(MAX_MESSAGE_CHARS + 1);
    expect(() => encryptMessage(newOneWayThreadKey(), position(), message(text))).toThrow(CryptoError);
  });

  it.each(["", "   ", "\n\t "])("rejects empty message %j", (text) => {
    expect(() => encryptMessage(newOneWayThreadKey(), position(), message(text))).toThrow(CryptoError);
  });

  it("encrypts the same text differently each time", () => {
    const key = newOneWayThreadKey();
    const at = position();
    expect(encryptMessage(key, at, message("same"))).not.toEqual(encryptMessage(key, at, message("same")));
  });

  it("rounds the time down to the minute", () => {
    const key = newOneWayThreadKey();
    const at = position();
    const content = { ...message("hi"), sentAt: new Date("2026-11-09T10:15:42.500Z") };
    expect(decryptMessage(key, at, encryptMessage(key, at, content)).sentAt).toEqual(sentAt);
  });

  it("detects tampering", () => {
    const key = newOneWayThreadKey();
    const at = position();
    const cipher = encryptMessage(key, at, message("hi"));
    expect(() => decryptMessage(key, at, flipByte(cipher))).toThrow(CryptoError);
    expect(() => decryptMessage(key, at, flipByte(cipher, 0))).toThrow(CryptoError);
  });

  it("fails with the wrong key", () => {
    const at = position();
    const cipher = encryptMessage(newOneWayThreadKey(), at, message("hi"));
    expect(() => decryptMessage(newOneWayThreadKey(), at, cipher)).toThrow(CryptoError);
  });

  it("detects a message moved to another thread", () => {
    const key = newOneWayThreadKey();
    const at = position();
    const cipher = encryptMessage(key, at, message("hi"));
    expect(() => decryptMessage(key, { ...at, threadId: newThreadId() }, cipher)).toThrow(CryptoError);
  });

  it("detects a message replayed at another position", () => {
    const key = newOneWayThreadKey();
    const at = position();
    const cipher = encryptMessage(key, at, message("hi"));
    expect(() => decryptMessage(key, { ...at, seq: 2 }, cipher)).toThrow(CryptoError);
  });

  it("rejects a truncated message", () => {
    const key = newOneWayThreadKey();
    const at = position();
    const cipher = encryptMessage(key, at, message("hi"));
    expect(() => decryptMessage(key, at, cipher.subarray(0, 100))).toThrow(CryptoError);
  });

  it.each([0, -1, 1.5])("rejects invalid message number %s", (seq) => {
    expect(() => encryptMessage(newOneWayThreadKey(), { threadId: newThreadId(), seq }, message("hi"))).toThrow(CryptoError);
  });

  it("rejects a bad thread id", () => {
    expect(() => encryptMessage(newOneWayThreadKey(), { threadId: new Uint8Array(4), seq: 1 }, message("hi"))).toThrow(CryptoError);
  });
});

describe("login challenge", () => {
  it("proves the reader holds the private key", () => {
    const keys = generateReaderKeys();
    const { challenge, expectedAnswer } = createLoginChallenge(keys.publicKey);
    expect(answerLoginChallenge(challenge, keys)).toEqual(expectedAnswer);
  });

  it("cannot be answered with another key", () => {
    const { challenge } = createLoginChallenge(generateReaderKeys().publicKey);
    expect(() => answerLoginChallenge(challenge, generateReaderKeys())).toThrow(CryptoError);
  });

  it("refuses a sealed thread key disguised as a challenge", () => {
    const keys = generateReaderKeys();
    const disguised = sealThreadKey(newOneWayThreadKey(), keys.publicKey);
    expect(() => answerLoginChallenge(disguised, keys)).toThrow(CryptoError);
  });

  it("is rejected as a thread key", () => {
    const keys = generateReaderKeys();
    const { challenge } = createLoginChallenge(keys.publicKey);
    expect(() => openThreadKey(challenge, keys)).toThrow(CryptoError);
  });
});

describe("full conversation", () => {
  it("works both ways using only what each side holds", () => {
    const recipient = generateReaderKeys();
    const threadId = newThreadId();

    const code = newSecretCode();
    const senderSide = deriveFromCode(code);
    const sealedKey = sealThreadKey(senderSide.threadKey, recipient.publicKey);
    const first = encryptMessage(senderSide.threadKey, { threadId, seq: 1 }, message("Can we talk?"));

    const recipientKey = openThreadKey(sealedKey, recipient);
    expect(decryptMessage(recipientKey, { threadId, seq: 1 }, first).text).toBe("Can we talk?");
    const reply = encryptMessage(recipientKey, { threadId, seq: 2 }, message("Yes, go on.", "recipient"));

    const returning = deriveFromCode(code);
    const received = decryptMessage(returning.threadKey, { threadId, seq: 2 }, reply);
    expect(received.text).toBe("Yes, go on.");
    expect(received.author).toBe("recipient");
  });
});
