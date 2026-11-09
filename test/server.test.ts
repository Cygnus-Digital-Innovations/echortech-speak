import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { connect, type AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Server } from "node:http";
import { DatabaseSync } from "node:sqlite";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import {
  answerLoginChallenge,
  decryptMessage,
  decryptWireMessage,
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
import { createApp } from "../src/server";
import { hasLeadingZeroBits, type DirectoryEntry, type PowSolution } from "../src/types";

const b64 = (value: Uint8Array) => Buffer.from(value).toString("base64url");
const unb64 = (value: string) => new Uint8Array(Buffer.from(value, "base64url"));
const content = (text: string, author: "sender" | "recipient" = "sender") => ({ author, sentAt: new Date(), text });

const POW_BITS = 4;
const INVITE = "test-invite-code";
let publicDir: string;
let alice: ReaderKeyPair;
let bob: ReaderKeyPair;
let retiree: ReaderKeyPair;
let removed: ReaderKeyPair;
let directory: DirectoryEntry[];
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
  retiree = generateReaderKeys();
  removed = generateReaderKeys();
  db = new DatabaseSync(":memory:");
  db.exec("PRAGMA foreign_keys = ON");
  db.exec(readFileSync(new URL("../db/schema.sql", import.meta.url), "utf8"));
  directory = [
    { keyId: 1, name: "Alice", publicKey: b64(alice.publicKey), status: "active" },
    { keyId: 2, name: "Bob", publicKey: b64(bob.publicKey), status: "active" },
    { keyId: 3, name: "Gone", publicKey: b64(retiree.publicKey), status: "retired" },
    { keyId: 4, name: "Removed", publicKey: b64(removed.publicKey), status: "revoked" },
  ];
  const addKey = db.prepare("INSERT INTO reader_keys (key_id, reader_name, public_key, status) VALUES (?, ?, ?, ?)");
  for (const entry of directory) addKey.run(entry.keyId, entry.name, unb64(entry.publicKey), entry.status);
  server = createApp({ db, inviteCode: INVITE, publicDir, powBits: POW_BITS, secureCookies: false, maxThreadsPerWindow: 3 });
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
    const insert = db.prepare("INSERT INTO messages (thread_id, seq, ciphertext, author) VALUES (?, ?, ?, 'sender')");
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

  it("rejects a wrong answer and won't accept the same answer twice", async () => {
    const start = await call("/api/login/start", { publicKey: b64(alice.publicKey) });
    const bad = await call("/api/login/finish", { challengeId: start.body.challengeId, answer: b64(new Uint8Array(32)) });
    expect(bad.status).toBe(401);
    const right = b64(answerLoginChallenge(unb64(start.body.challenge), alice));
    expect((await call("/api/login/finish", { challengeId: start.body.challengeId, answer: right })).status).toBe(200);
    expect((await call("/api/login/finish", { challengeId: start.body.challengeId, answer: right })).status).toBe(401);
  });

  it("rejects a forged challenge id", async () => {
    const res = await call("/api/login/finish", { challengeId: `1.${Date.now() + 60000}.forged`, answer: b64(new Uint8Array(32)) });
    expect(res.status).toBe(401);
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

describe("hardening", () => {
  it("survives a malformed request target", async () => {
    const port = (server.address() as AddressInfo).port;
    const raw = await new Promise<string>((resolve) => {
      let data = "";
      const socket = connect(port, "127.0.0.1", () => socket.write("GET // HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"));
      socket.on("data", (chunk) => (data += chunk));
      socket.on("close", () => resolve(data));
    });
    expect(raw).toContain("400");
    expect((await fetch(`${base}/`)).status).toBe(200);
  });

  it("only sends the session cookie to inbox routes", async () => {
    const start = await call("/api/login/start", { publicKey: b64(alice.publicKey) });
    const finish = await fetch(`${base}/api/login/finish`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ challengeId: start.body.challengeId, answer: b64(answerLoginChallenge(unb64(start.body.challenge), alice)) }),
    });
    expect(finish.headers.get("set-cookie")).toContain("Path=/api/inbox;");
  });

  it("can't be locked out by requesting many login challenges", async () => {
    for (let i = 0; i < 1100; i++) await call("/api/login/start", { publicKey: b64(alice.publicKey) });
    expect(await login(alice)).toMatch(/^sid=/);
  });

  it("keeps revoked keys out but lets retired keys read old messages", async () => {
    expect((await call("/api/login/start", { publicKey: b64(removed.publicKey) })).status).toBe(404);
    expect(await login(retiree)).toMatch(/^sid=/);
  });

  it("ends the session on lock", async () => {
    const cookie = await login(alice);
    expect((await call("/api/inbox", undefined, cookie)).status).toBe(200);
    await call("/api/inbox/logout", {}, cookie);
    expect((await call("/api/inbox", undefined, cookie)).status).toBe(401);
  });

  it("catches a sender forging a message as the recipient", async () => {
    const chat = await startChat();
    const forged = encryptMessage(chat.threadKey, { threadId: chat.threadId, seq: 2 }, content("I said this", "recipient"));
    await call("/api/sender/messages", { accessToken: b64(chat.accessToken), seq: 2, ciphertext: b64(forged), pow: await pow() });
    const cookie = await login(alice);
    const { messages } = (await call(`/api/inbox/${b64(chat.threadId)}/messages`, undefined, cookie)).body;
    expect(messages[1].author).toBe("sender");
    expect(() => decryptWireMessage(chat.threadKey, chat.threadId, messages[1])).toThrow();
    expect(decryptWireMessage(chat.threadKey, chat.threadId, messages[0]).text).toBe("can we talk?");
  });

  it("pages through a large inbox", async () => {
    const thread = db.prepare("INSERT INTO threads (id, recipient_key_id, sealed_thread_key, status) VALUES (?, 1, ?, 'closed')");
    const message = db.prepare("INSERT INTO messages (thread_id, seq, ciphertext, author) VALUES (?, 1, ?, 'sender')");
    for (let i = 0; i < 105; i++) {
      const id = newThreadId();
      thread.run(id, new Uint8Array(80));
      message.run(id, new Uint8Array(16424));
    }
    const cookie = await login(alice);
    const first = (await call("/api/inbox", undefined, cookie)).body;
    expect(first.threads).toHaveLength(100);
    const second = (await call(`/api/inbox?after=${first.nextAfter}`, undefined, cookie)).body;
    expect(second.threads).toHaveLength(5);
    expect(second.nextAfter).toBeNull();
    const ids = new Set([...first.threads, ...second.threads].map((t: { id: string }) => t.id));
    expect(ids.size).toBe(105);
  });

  it("limits how fast one person can be flooded, without affecting others", async () => {
    for (let i = 0; i < 3; i++) expect((await sendOneWay()).res.status).toBe(200);
    expect((await sendOneWay()).res.status).toBe(429);
    expect((await sendOneWay("x", 2, bob)).res.status).toBe(200);
  });

  it("stops accepting messages when storage is full", async () => {
    const full = createApp({ db, inviteCode: INVITE, publicDir, powBits: POW_BITS, secureCookies: false, maxDatabaseBytes: 1 });
    await new Promise<void>((resolve) => full.listen(0, "127.0.0.1", resolve));
    const original = base;
    base = `http://127.0.0.1:${(full.address() as AddressInfo).port}`;
    const { res } = await sendOneWay();
    base = original;
    full.closeAllConnections();
    await new Promise((resolve) => full.close(resolve));
    expect(res.status).toBe(507);
  });

  const registration = async (overrides: Record<string, unknown> = {}, path = "/api/register") =>
    call(path, { name: "New Person", inviteCode: INVITE, publicKey: b64(generateReaderKeys().publicKey), pow: await pow(), ...overrides });

  it("registers someone who then appears and can log in", async () => {
    const keys = generateReaderKeys();
    expect((await registration({ publicKey: b64(keys.publicKey) })).status).toBe(200);
    const { people } = (await call("/api/directory")).body;
    const added = people.find((p: DirectoryEntry) => p.name === "New Person");
    expect(added.publicKey).toBe(b64(keys.publicKey));
    expect(await login(keys)).toMatch(/^sid=/);
    expect((await sendOneWay("hello", added.keyId, keys)).res.status).toBe(200);
  });

  it("only lists active people", async () => {
    const names = (await call("/api/directory")).body.people.map((p: DirectoryEntry) => p.name);
    expect(names).toEqual(["Alice", "Bob"]);
  });

  it.each(["/api/register", "/api/register/check"])("rejects a wrong invite code at %s", async (path) => {
    expect((await registration({ inviteCode: "wrong" }, path)).status).toBe(403);
  });

  it("requires a spam check", async () => {
    expect((await registration({ pow: undefined })).status).toBe(400);
  });

  it("treats names as taken regardless of case and spacing", async () => {
    expect((await registration({ name: "  aLiCe " })).status).toBe(409);
    expect((await registration({ name: "ALICE" }, "/api/register/check")).status).toBe(409);
  });

  it("frees a name once revoked but not while retired keys are unrelated", async () => {
    expect((await registration({ name: "Removed" })).status).toBe(200);
  });

  it("rejects a key already registered to someone else", async () => {
    expect((await registration({ publicKey: b64(alice.publicKey) })).status).toBe(409);
  });

  it("succeeds on a retry of the same registration", async () => {
    const publicKey = b64(generateReaderKeys().publicKey);
    expect((await registration({ publicKey })).status).toBe(200);
    expect((await registration({ publicKey })).status).toBe(200);
    expect((await call("/api/directory")).body.people.filter((p: DirectoryEntry) => p.name === "New Person")).toHaveLength(1);
  });

  it.each(["", "   ", "x".repeat(61), "bad\u0000name", 7, null])("rejects invalid name %j", async (name) => {
    expect((await registration({ name })).status).toBe(400);
  });

  it("rejects a malformed public key", async () => {
    expect((await registration({ publicKey: "short" })).status).toBe(400);
  });

  it("limits how many people can sign up at once", async () => {
    for (let i = 0; i < 20; i++) expect((await registration({ name: `Person ${i}` })).status).toBe(200);
    expect((await registration({ name: "One Too Many" })).status).toBe(429);
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
