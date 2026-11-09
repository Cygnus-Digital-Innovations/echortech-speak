import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Server } from "node:http";
import { DatabaseSync } from "node:sqlite";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import {
  answerLoginChallenge,
  decryptMessage,
  deriveFromCode,
  encryptMessage,
  generateReaderKeys,
  hashAccessToken,
  initCrypto,
  newOneWayThreadKey,
  newSecretCode,
  newThreadId,
  openThreadKey,
  sealThreadKey,
  type ReaderKeyPair,
} from "../src/crypto";
import { createApp, seedDirectory } from "../src/server";
import { hasLeadingZeroBits, type DirectoryEntry, type PowSolution } from "../src/types";

const b64 = (value: Uint8Array) => Buffer.from(value).toString("base64url");
const unb64 = (value: string) => new Uint8Array(Buffer.from(value, "base64url"));
const content = (text: string, author: "sender" | "recipient" = "sender") => ({ author, sentAt: new Date(), text });

const POW_BITS = 4;
let publicDir: string;
let alice: ReaderKeyPair;
let bob: ReaderKeyPair;
let db: DatabaseSync;
let server: Server;
let base: string;

interface Res<T = any> {
  status: number;
  body: T;
  cookie: string | null;
  headers: Headers;
}

async function call<T = any>(path: string, body?: unknown, cookie?: string, contentType = "application/json"): Promise<Res<T>> {
  const response = await fetch(base + path, {
    method: body === undefined ? "GET" : "POST",
    headers: { ...(body === undefined ? {} : { "Content-Type": contentType }), ...(cookie ? { Cookie: cookie } : {}) },
    body: body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body),
  });
  return {
    status: response.status,
    body: (await response.json().catch(() => null)) as T,
    cookie: response.headers.get("set-cookie")?.split(";")[0] ?? null,
    headers: response.headers,
  };
}

async function pow(): Promise<PowSolution> {
  const { body } = await call("/api/pow");
  for (let counter = 0; ; counter++) {
    const hash = createHash("sha256").update(`${body.payload}:${counter}`).digest();
    if (hasLeadingZeroBits(hash, body.bits)) return { payload: body.payload, signature: body.signature, counter };
  }
}

async function sendOneWay(text = "hello", recipient = 1, keys = alice) {
  const threadId = newThreadId();
  const threadKey = newOneWayThreadKey();
  const res = await call("/api/threads", {
    id: b64(threadId),
    recipientKeyId: recipient,
    sealedThreadKey: b64(sealThreadKey(threadKey, keys.publicKey)),
    accessTokenHash: null,
    ciphertext: b64(encryptMessage(threadKey, { threadId, seq: 1 }, content(text))),
    pow: await pow(),
  });
  return { res, threadId, threadKey };
}

async function startChat(text = "can we talk?") {
  const code = newSecretCode();
  const { threadKey, accessToken } = deriveFromCode(code);
  const threadId = newThreadId();
  const res = await call("/api/threads", {
    id: b64(threadId),
    recipientKeyId: 1,
    sealedThreadKey: b64(sealThreadKey(threadKey, alice.publicKey)),
    accessTokenHash: b64(hashAccessToken(accessToken)),
    ciphertext: b64(encryptMessage(threadKey, { threadId, seq: 1 }, content(text))),
    pow: await pow(),
  });
  return { res, code, threadKey, accessToken, threadId };
}

async function login(keys: ReaderKeyPair): Promise<string> {
  const start = await call("/api/login/start", { publicKey: b64(keys.publicKey) });
  const answer = answerLoginChallenge(unb64(start.body.challenge), keys);
  const finish = await call("/api/login/finish", { challengeId: start.body.challengeId, answer: b64(answer) });
  expect(finish.status).toBe(200);
  return finish.cookie!;
}

beforeAll(async () => {
  await initCrypto();
  publicDir = mkdtempSync(join(tmpdir(), "speak-"));
  mkdirSync(join(publicDir, "assets"));
  for (const page of ["send", "chat", "inbox", "setup"]) writeFileSync(join(publicDir, `${page}.html`), `<h1>${page}</h1>`);
  writeFileSync(join(publicDir, "style.css"), "body{}");
  writeFileSync(join(publicDir, "assets", "send.js"), "1");
});

afterAll(() => rmSync(publicDir, { recursive: true, force: true }));

beforeEach(async () => {
  alice = generateReaderKeys();
  bob = generateReaderKeys();
  db = new DatabaseSync(":memory:");
  db.exec("PRAGMA foreign_keys = ON");
  db.exec(readFileSync(new URL("../db/schema.sql", import.meta.url), "utf8"));
  const directory: DirectoryEntry[] = [
    { keyId: 1, name: "Alice", publicKey: b64(alice.publicKey), status: "active" },
    { keyId: 2, name: "Bob", publicKey: b64(bob.publicKey), status: "active" },
    { keyId: 3, name: "Gone", publicKey: b64(generateReaderKeys().publicKey), status: "retired" },
  ];
  seedDirectory(db, directory);
  server = createApp({ db, directory, publicDir, powBits: POW_BITS, secureCookies: false });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterEach(async () => {
  server.closeAllConnections();
  await new Promise((resolve) => server.close(resolve));
  db.close();
});

describe("one-way messages", () => {
  it("reach the recipient, who alone can read them", async () => {
    const { res } = await sendOneWay("the secret");
    expect(res.status).toBe(200);
    const cookie = await login(alice);
    const inbox = await call("/api/inbox", undefined, cookie);
    expect(inbox.body.threads).toHaveLength(1);
    const thread = inbox.body.threads[0];
    expect(thread.canReply).toBe(false);
    const key = openThreadKey(unb64(thread.sealedThreadKey), alice);
    const opened = decryptMessage(key, { threadId: unb64(thread.id), seq: 1 }, unb64(thread.last.ciphertext));
    expect(opened.text).toBe("the secret");
    expect(() => openThreadKey(unb64(thread.sealedThreadKey), bob)).toThrow();
  });

  it("are stored without any readable text", async () => {
    await sendOneWay("findable-plaintext");
    const row = db.prepare("SELECT ciphertext FROM messages").get() as { ciphertext: Uint8Array };
    expect(Buffer.from(row.ciphertext).includes("findable-plaintext")).toBe(false);
  });

  it("cannot be replied to", async () => {
    const { threadId, threadKey } = await sendOneWay();
    const cookie = await login(alice);
    const res = await call(
      `/api/inbox/${b64(threadId)}/messages`,
      { seq: 2, ciphertext: b64(encryptMessage(threadKey, { threadId, seq: 2 }, content("x", "recipient"))) },
      cookie,
    );
    expect(res.status).toBe(403);
  });

  it("reject a retired or unknown recipient", async () => {
    expect((await sendOneWay("x", 3)).res.status).toBe(404);
    expect((await sendOneWay("x", 99)).res.status).toBe(404);
  });
});

describe("spam check", () => {
  const validBody = async (powValue: unknown) => {
    const threadId = newThreadId();
    const threadKey = newOneWayThreadKey();
    return {
      id: b64(threadId),
      recipientKeyId: 1,
      sealedThreadKey: b64(sealThreadKey(threadKey, alice.publicKey)),
      accessTokenHash: null,
      ciphertext: b64(encryptMessage(threadKey, { threadId, seq: 1 }, content("x"))),
      pow: powValue,
    };
  };

  it("is required", async () => {
    expect((await call("/api/threads", await validBody(undefined))).status).toBe(400);
  });

  it("cannot be reused", async () => {
    const solved = await pow();
    expect((await call("/api/threads", await validBody(solved))).status).toBe(200);
    expect((await call("/api/threads", await validBody(solved))).status).toBe(400);
  });

  it("rejects a forged signature", async () => {
    const solved = await pow();
    expect((await call("/api/threads", await validBody({ ...solved, signature: b64(new Uint8Array(32)) }))).status).toBe(400);
  });

  it("rejects a wrong answer", async () => {
    const solved = await pow();
    let counter = solved.counter + 1;
    while (hasLeadingZeroBits(createHash("sha256").update(`${solved.payload}:${counter}`).digest(), POW_BITS)) counter++;
    expect((await call("/api/threads", await validBody({ ...solved, counter }))).status).toBe(400);
  });
});

describe("chats", () => {
  it("work both ways using the secret code", async () => {
    const chat = await startChat();
    expect(chat.res.status).toBe(200);
    const cookie = await login(alice);
    const id = b64(chat.threadId);
    const reply = await call(`/api/inbox/${id}/messages`, { seq: 2, ciphertext: b64(encryptMessage(chat.threadKey, { threadId: chat.threadId, seq: 2 }, content("yes", "recipient"))) }, cookie);
    expect(reply.status).toBe(200);

    const back = deriveFromCode(chat.code);
    const seen = await call("/api/sender/thread", { accessToken: b64(back.accessToken) });
    expect(seen.body.messages).toHaveLength(2);
    expect(decryptMessage(back.threadKey, { threadId: unb64(seen.body.id), seq: 2 }, unb64(seen.body.messages[1].ciphertext)).text).toBe("yes");
  });

  it("reject a wrong code", async () => {
    await startChat();
    const res = await call("/api/sender/thread", { accessToken: b64(deriveFromCode(newSecretCode()).accessToken) });
    expect(res.status).toBe(404);
  });

  it("let only one of two simultaneous replies through", async () => {
    const chat = await startChat();
    const cookie = await login(alice);
    const id = b64(chat.threadId);
    const ciphertext = () => b64(encryptMessage(chat.threadKey, { threadId: chat.threadId, seq: 2 }, content("x", "recipient")));
    const statuses = (await Promise.all([call(`/api/inbox/${id}/messages`, { seq: 2, ciphertext: ciphertext() }, cookie), call(`/api/inbox/${id}/messages`, { seq: 2, ciphertext: ciphertext() }, cookie)])).map((r) => r.status);
    expect(statuses.sort()).toEqual([200, 409]);
  });

  it("reject a skipped message number", async () => {
    const chat = await startChat();
    const cookie = await login(alice);
    const res = await call(`/api/inbox/${b64(chat.threadId)}/messages`, { seq: 5, ciphertext: b64(encryptMessage(chat.threadKey, { threadId: chat.threadId, seq: 5 }, content("x", "recipient"))) }, cookie);
    expect(res.status).toBe(409);
  });

  it("stop accepting messages from both sides once closed", async () => {
    const chat = await startChat();
    const cookie = await login(alice);
    const id = b64(chat.threadId);
    expect((await call(`/api/inbox/${id}/close`, {}, cookie)).status).toBe(200);
    const senderSide = await call("/api/sender/messages", { accessToken: b64(chat.accessToken), seq: 2, ciphertext: b64(encryptMessage(chat.threadKey, { threadId: chat.threadId, seq: 2 }, content("late"))), pow: await pow() });
    expect(senderSide.status).toBe(403);
    expect((await call(`/api/sender/thread`, { accessToken: b64(chat.accessToken) })).body.status).toBe("closed");
  });

  it("stop at the message limit", async () => {
    const chat = await startChat();
    const insert = db.prepare("INSERT INTO messages (thread_id, seq, ciphertext) VALUES (?, ?, ?)");
    for (let seq = 2; seq <= 200; seq++) insert.run(chat.threadId, seq, new Uint8Array(16424));
    const res = await call("/api/sender/messages", { accessToken: b64(chat.accessToken), seq: 201, ciphertext: b64(encryptMessage(chat.threadKey, { threadId: chat.threadId, seq: 201 }, content("x"))), pow: await pow() });
    expect(res.status).toBe(429);
  });
});

describe("inbox access", () => {
  it("needs a login", async () => {
    expect((await call("/api/inbox")).status).toBe(401);
    expect((await call("/api/inbox", undefined, "sid=made-up")).status).toBe(401);
  });

  it("rejects a wrong login answer and one-time challenges", async () => {
    const start = await call("/api/login/start", { publicKey: b64(alice.publicKey) });
    const bad = await call("/api/login/finish", { challengeId: start.body.challengeId, answer: b64(new Uint8Array(32)) });
    expect(bad.status).toBe(401);
    const right = answerLoginChallenge(unb64(start.body.challenge), alice);
    expect((await call("/api/login/finish", { challengeId: start.body.challengeId, answer: b64(right) })).status).toBe(401);
  });

  it("rejects an unknown key", async () => {
    expect((await call("/api/login/start", { publicKey: b64(generateReaderKeys().publicKey) })).status).toBe(404);
  });

  it("keeps each person to their own messages", async () => {
    const { threadId } = await sendOneWay();
    const bobCookie = await login(bob);
    expect((await call("/api/inbox", undefined, bobCookie)).body.threads).toHaveLength(0);
    expect((await call(`/api/inbox/${b64(threadId)}/messages`, undefined, bobCookie)).status).toBe(404);
    expect((await call(`/api/inbox/${b64(threadId)}/hide`, { hidden: true }, bobCookie)).status).toBe(404);
  });

  it("hides without deleting and tracks reading without going backwards", async () => {
    const { threadId } = await sendOneWay();
    const cookie = await login(alice);
    const id = b64(threadId);
    await call(`/api/inbox/${id}/hide`, { hidden: true }, cookie);
    await call(`/api/inbox/${id}/read`, { seq: 5 }, cookie);
    await call(`/api/inbox/${id}/read`, { seq: 2 }, cookie);
    const thread = (await call("/api/inbox", undefined, cookie)).body.threads[0];
    expect(thread.hidden).toBe(true);
    expect(thread.lastReadSeq).toBe(5);
  });

  it("sets a cookie scripts can't read", async () => {
    const start = await call("/api/login/start", { publicKey: b64(alice.publicKey) });
    const response = await fetch(`${base}/api/login/finish`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ challengeId: start.body.challengeId, answer: b64(answerLoginChallenge(unb64(start.body.challenge), alice)) }),
    });
    expect(response.headers.get("set-cookie")).toMatch(/HttpOnly; SameSite=Strict/);
  });
});

describe("request handling", () => {
  it("rejects non-JSON and bad JSON", async () => {
    expect((await call("/api/login/start", "{}", undefined, "text/plain")).status).toBe(415);
    expect((await call("/api/login/start", "{not json")).status).toBe(400);
    expect((await call("/api/login/start", "[1]")).status).toBe(400);
  });

  it("rejects an oversized body", async () => {
    const response = await fetch(`${base}/api/login/start`, { method: "POST", headers: { "Content-Type": "application/json" }, body: "x".repeat(70000) }).catch(() => null);
    expect(response === null || response.status === 413).toBe(true);
  });

  it.each(["aaa", "!!!", "", 7, null])("rejects a bad message value %j", async (ciphertext) => {
    const chat = await startChat();
    const res = await call("/api/sender/messages", { accessToken: b64(chat.accessToken), seq: 2, ciphertext, pow: await pow() });
    expect(res.status).toBe(400);
  });

  it("serves pages with strict security headers", async () => {
    const response = await fetch(`${base}/`);
    const policy = response.headers.get("content-security-policy") ?? "";
    expect(response.status).toBe(200);
    expect(policy).toContain("default-src 'none'");
    expect(policy).toContain("script-src 'self' 'wasm-unsafe-eval'");
    expect(policy).not.toContain("https:");
    expect(response.headers.get("referrer-policy")).toBe("no-referrer");
  });

  it("does not serve files outside the allowed list", async () => {
    for (const path of ["/../package.json", "/assets/../../package.json", "/speak.db", "/assets/missing.js"]) {
      expect((await fetch(base + path)).status).toBe(404);
    }
  });

  it("never stores request details such as IP", () => {
    const columns = ["threads", "messages", "reader_keys"].flatMap((table) => (db.prepare(`PRAGMA table_info(${table})`).all() as { name: string }[]).map((c) => c.name));
    expect(columns.join(",")).not.toMatch(/(^|[,_])(ip|ip_address|user_agent|created|time|timestamp|sent_at)([,_]|$)/i);
  });
});
