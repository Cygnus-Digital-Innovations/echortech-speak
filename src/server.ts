import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { extname, join } from "node:path";
import type { DatabaseSync } from "node:sqlite";
import { createLoginChallenge } from "./crypto.ts";
import { hasLeadingZeroBits, MAX_MESSAGES_PER_THREAD, type DirectoryEntry, type PowSolution } from "./types.ts";

const MAX_BODY_BYTES = 64 * 1024;
const POW_TTL_MS = 5 * 60 * 1000;
const LOGIN_TTL_MS = 2 * 60 * 1000;
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const MAX_PENDING_LOGINS = 1000;
const CIPHERTEXT_BYTES = 16424;

const SECURITY_HEADERS = {
  "Content-Security-Policy":
    "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; connect-src 'self'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
};

const CONTENT_TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
};

const PAGE_ROUTES: Record<string, string> = {
  "/": "send.html",
  "/chat": "chat.html",
  "/inbox": "inbox.html",
  "/setup": "setup.html",
};

class HttpError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export interface AppOptions {
  db: DatabaseSync;
  directory: DirectoryEntry[];
  publicDir: string;
  powBits: number;
  secureCookies: boolean;
}

type Body = Record<string, unknown>;

function bytes(value: unknown, size: number, field: string): Buffer {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) throw new HttpError(400, `Invalid ${field}`);
  const decoded = Buffer.from(value, "base64url");
  if (decoded.length !== size) throw new HttpError(400, `Invalid ${field}`);
  return decoded;
}

function positiveInt(value: unknown, field: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) throw new HttpError(400, `Invalid ${field}`);
  return value as number;
}

const b64 = (value: Uint8Array) => Buffer.from(value).toString("base64url");
const sha256 = (value: Uint8Array) => createHash("sha256").update(value).digest();

function readBody(req: IncomingMessage): Promise<Body> {
  if (!(req.headers["content-type"] ?? "").startsWith("application/json")) {
    return Promise.reject(new HttpError(415, "Expected JSON"));
  }
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new HttpError(413, "Request too large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("error", reject);
    req.on("end", () => {
      try {
        const parsed: unknown = JSON.parse(Buffer.concat(chunks).toString("utf8"));
        if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) throw new Error();
        resolve(parsed as Body);
      } catch {
        reject(new HttpError(400, "Invalid JSON"));
      }
    });
  });
}

export function seedDirectory(db: DatabaseSync, directory: DirectoryEntry[]): void {
  const upsert = db.prepare(
    "INSERT INTO reader_keys (key_id, reader_name, public_key, status) VALUES (?, ?, ?, ?) " +
      "ON CONFLICT (key_id) DO UPDATE SET reader_name = excluded.reader_name, status = excluded.status",
  );
  for (const entry of directory.filter((e) => e.status === "retired")) {
    upsert.run(entry.keyId, entry.name, Buffer.from(entry.publicKey, "base64url"), entry.status);
  }
  for (const entry of directory.filter((e) => e.status === "active")) {
    upsert.run(entry.keyId, entry.name, Buffer.from(entry.publicKey, "base64url"), entry.status);
  }
}

export function createApp(options: AppOptions): Server {
  const { db, publicDir, powBits, secureCookies } = options;
  const powSecret = randomBytes(32);
  const usedPow = new Map<string, number>();
  const pendingLogins = new Map<string, { expected: Buffer; keyId: number; expires: number }>();
  const sessions = new Map<string, { keyId: number; expires: number }>();

  const staticFiles = new Map<string, { body: Buffer; type: string }>();
  const load = (route: string, file: string) =>
    staticFiles.set(route, {
      body: readFileSync(join(publicDir, file)),
      type: CONTENT_TYPES[extname(file)] ?? "application/octet-stream",
    });
  for (const [route, file] of Object.entries(PAGE_ROUTES)) load(route, file);
  load("/style.css", "style.css");
  for (const file of readdirSync(join(publicDir, "assets"))) load(`/assets/${file}`, `assets/${file}`);

  const sign = (payload: string) => createHmac("sha256", powSecret).update(payload).digest();

  function checkPow(value: unknown): void {
    const pow = value as PowSolution | undefined;
    if (!pow || typeof pow.payload !== "string" || typeof pow.signature !== "string" || !Number.isSafeInteger(pow.counter)) {
      throw new HttpError(400, "Spam check missing");
    }
    const given = Buffer.from(pow.signature, "base64url");
    const expected = sign(pow.payload);
    const expires = Number(pow.payload.split(".")[0]);
    if (given.length !== expected.length || !timingSafeEqual(given, expected) || !(expires > Date.now())) {
      throw new HttpError(400, "Spam check expired, please try again");
    }
    if (usedPow.has(pow.payload)) throw new HttpError(400, "Spam check already used");
    if (!hasLeadingZeroBits(sha256(Buffer.from(`${pow.payload}:${pow.counter}`)), powBits)) {
      throw new HttpError(400, "Spam check failed");
    }
    for (const [key, expiry] of usedPow) if (expiry <= Date.now()) usedPow.delete(key);
    usedPow.set(pow.payload, expires);
  }

  function transaction<T>(work: () => T): T {
    db.exec("BEGIN IMMEDIATE");
    try {
      const result = work();
      db.exec("COMMIT");
      return result;
    } catch (error) {
      db.exec("ROLLBACK");
      throw error;
    }
  }

  const messagesOf = (threadId: Uint8Array) =>
    (db.prepare("SELECT seq, ciphertext FROM messages WHERE thread_id = ? ORDER BY seq").all(threadId) as unknown as { seq: number; ciphertext: Uint8Array }[]).map(
      (m) => ({ seq: m.seq, ciphertext: b64(m.ciphertext) }),
    );

  function appendMessage(threadId: Uint8Array, seq: number, ciphertext: Buffer): void {
    transaction(() => {
      const thread = db.prepare("SELECT status, access_token_hash FROM threads WHERE id = ?").get(threadId) as { status: string; access_token_hash: Uint8Array | null } | undefined;
      if (!thread) throw new HttpError(404, "Conversation not found");
      if (thread.status !== "open" || !thread.access_token_hash) throw new HttpError(403, "This conversation is closed");
      const { last } = db.prepare("SELECT coalesce(max(seq), 0) AS last FROM messages WHERE thread_id = ?").get(threadId) as { last: number };
      if (seq !== last + 1) throw new HttpError(409, "A new message arrived first");
      if (seq > MAX_MESSAGES_PER_THREAD) throw new HttpError(429, "This conversation has reached its limit");
      db.prepare("INSERT INTO messages (thread_id, seq, ciphertext) VALUES (?, ?, ?)").run(threadId, seq, ciphertext);
    });
  }

  function senderThread(token: unknown) {
    const hash = sha256(bytes(token, 32, "code"));
    const thread = db.prepare("SELECT id, status FROM threads WHERE access_token_hash = ?").get(hash) as { id: Uint8Array; status: string } | undefined;
    if (!thread) throw new HttpError(404, "We couldn't find a conversation for that code");
    return thread;
  }

  function session(req: IncomingMessage): number {
    const sid = /(?:^|;\s*)sid=([A-Za-z0-9_-]+)/.exec(req.headers.cookie ?? "")?.[1];
    const current = sid ? sessions.get(sid) : undefined;
    if (!current || current.expires <= Date.now()) throw new HttpError(401, "Please unlock your inbox again");
    return current.keyId;
  }

  function ownedThread(keyId: number, encodedId: string) {
    const id = bytes(encodedId, 16, "conversation");
    const thread = db.prepare("SELECT id, status, access_token_hash, hidden FROM threads WHERE id = ? AND recipient_key_id = ?").get(id, keyId) as { id: Uint8Array; status: string; access_token_hash: Uint8Array | null; hidden: number } | undefined;
    if (!thread) throw new HttpError(404, "Conversation not found");
    return thread;
  }

  async function api(req: IncomingMessage, res: ServerResponse, method: string, path: string): Promise<unknown> {
    if (method === "GET" && path === "/api/pow") {
      const payload = `${Date.now() + POW_TTL_MS}.${randomBytes(16).toString("base64url")}`;
      return { payload, signature: sign(payload).toString("base64url"), bits: powBits };
    }

    if (method === "POST" && path === "/api/threads") {
      const body = await readBody(req);
      checkPow(body.pow);
      const id = bytes(body.id, 16, "conversation");
      const sealed = bytes(body.sealedThreadKey, 80, "key");
      const tokenHash = body.accessTokenHash === null ? null : bytes(body.accessTokenHash, 32, "code");
      const ciphertext = bytes(body.ciphertext, CIPHERTEXT_BYTES, "message");
      const recipient = db.prepare("SELECT key_id FROM reader_keys WHERE key_id = ? AND status = 'active'").get(positiveInt(body.recipientKeyId, "recipient"));
      if (!recipient) throw new HttpError(404, "That person can't receive messages right now");
      transaction(() => {
        db.prepare("INSERT INTO threads (id, recipient_key_id, sealed_thread_key, access_token_hash, status) VALUES (?, ?, ?, ?, ?)").run(id, body.recipientKeyId as number, sealed, tokenHash, tokenHash ? "open" : "closed");
        db.prepare("INSERT INTO messages (thread_id, seq, ciphertext) VALUES (?, 1, ?)").run(id, ciphertext);
      });
      return { ok: true };
    }

    if (method === "POST" && path === "/api/sender/thread") {
      const body = await readBody(req);
      const thread = senderThread(body.accessToken);
      return { id: b64(thread.id), status: thread.status, messages: messagesOf(thread.id) };
    }

    if (method === "POST" && path === "/api/sender/messages") {
      const body = await readBody(req);
      checkPow(body.pow);
      const thread = senderThread(body.accessToken);
      appendMessage(thread.id, positiveInt(body.seq, "message number"), bytes(body.ciphertext, CIPHERTEXT_BYTES, "message"));
      return { ok: true };
    }

    if (method === "POST" && path === "/api/login/start") {
      const body = await readBody(req);
      const publicKey = bytes(body.publicKey, 32, "key");
      const key = db.prepare("SELECT key_id FROM reader_keys WHERE public_key = ?").get(publicKey) as { key_id: number } | undefined;
      if (!key) throw new HttpError(404, "This key isn't on the list yet. Ask your admin to add it");
      const now = Date.now();
      for (const [id, login] of pendingLogins) if (login.expires <= now) pendingLogins.delete(id);
      if (pendingLogins.size >= MAX_PENDING_LOGINS) throw new HttpError(429, "Too many attempts, try again soon");
      const { challenge, expectedAnswer } = createLoginChallenge(publicKey);
      const challengeId = randomBytes(16).toString("base64url");
      pendingLogins.set(challengeId, { expected: Buffer.from(expectedAnswer), keyId: key.key_id, expires: now + LOGIN_TTL_MS });
      return { challengeId, challenge: b64(challenge) };
    }

    if (method === "POST" && path === "/api/login/finish") {
      const body = await readBody(req);
      const pending = typeof body.challengeId === "string" ? pendingLogins.get(body.challengeId) : undefined;
      if (pending) pendingLogins.delete(body.challengeId as string);
      const answer = bytes(body.answer, 32, "answer");
      if (!pending || pending.expires <= Date.now() || !timingSafeEqual(answer, pending.expected)) {
        throw new HttpError(401, "Couldn't verify your key, please try again");
      }
      const sid = randomBytes(32).toString("base64url");
      for (const [id, s] of sessions) if (s.expires <= Date.now()) sessions.delete(id);
      sessions.set(sid, { keyId: pending.keyId, expires: Date.now() + SESSION_TTL_MS });
      res.setHeader("Set-Cookie", `sid=${sid}; Path=/api; HttpOnly; SameSite=Strict; Max-Age=${SESSION_TTL_MS / 1000}${secureCookies ? "; Secure" : ""}`);
      return { ok: true };
    }

    if (method === "GET" && path === "/api/inbox") {
      const keyId = session(req);
      const rows = db
        .prepare(
          "SELECT t.id, t.sealed_thread_key, t.access_token_hash, t.status, t.hidden, t.last_read_seq, m.seq, m.ciphertext " +
            "FROM threads t JOIN messages m ON m.thread_id = t.id AND m.seq = (SELECT max(seq) FROM messages WHERE thread_id = t.id) " +
            "WHERE t.recipient_key_id = ?",
        )
        .all(keyId) as unknown as { id: Uint8Array; sealed_thread_key: Uint8Array; access_token_hash: Uint8Array | null; status: string; hidden: number; last_read_seq: number; seq: number; ciphertext: Uint8Array }[];
      return {
        threads: rows.map((t) => ({
          id: b64(t.id),
          sealedThreadKey: b64(t.sealed_thread_key),
          canReply: t.status === "open" && t.access_token_hash !== null,
          isChat: t.access_token_hash !== null,
          hidden: t.hidden === 1,
          lastReadSeq: t.last_read_seq,
          last: { seq: t.seq, ciphertext: b64(t.ciphertext) },
        })),
      };
    }

    const inboxMatch = /^\/api\/inbox\/([A-Za-z0-9_-]+)\/(messages|read|hide|close)$/.exec(path);
    if (inboxMatch) {
      const keyId = session(req);
      const thread = ownedThread(keyId, inboxMatch[1]!);
      const action = inboxMatch[2];
      if (method === "GET" && action === "messages") return { messages: messagesOf(thread.id) };
      if (method === "POST" && action === "messages") {
        const body = await readBody(req);
        appendMessage(thread.id, positiveInt(body.seq, "message number"), bytes(body.ciphertext, CIPHERTEXT_BYTES, "message"));
        return { ok: true };
      }
      if (method === "POST" && action === "read") {
        const body = await readBody(req);
        db.prepare("UPDATE threads SET last_read_seq = max(last_read_seq, ?) WHERE id = ?").run(positiveInt(body.seq, "message number"), thread.id);
        return { ok: true };
      }
      if (method === "POST" && action === "hide") {
        const body = await readBody(req);
        if (typeof body.hidden !== "boolean") throw new HttpError(400, "Invalid value");
        db.prepare("UPDATE threads SET hidden = ? WHERE id = ?").run(body.hidden ? 1 : 0, thread.id);
        return { ok: true };
      }
      if (method === "POST" && action === "close") {
        db.prepare("UPDATE threads SET status = 'closed' WHERE id = ?").run(thread.id);
        return { ok: true };
      }
    }

    throw new HttpError(404, "Not found");
  }

  return createServer((req, res) => {
    for (const [name, value] of Object.entries(SECURITY_HEADERS)) res.setHeader(name, value);
    if (secureCookies) res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
    const method = req.method ?? "GET";
    const path = new URL(req.url ?? "/", "http://local").pathname;

    if (!path.startsWith("/api/")) {
      const file = staticFiles.get(path);
      if (method !== "GET" || !file) {
        res.writeHead(404, { "Content-Type": "text/plain" }).end("Not found");
        return;
      }
      res.writeHead(200, { "Content-Type": file.type, "Cache-Control": "no-cache" }).end(file.body);
      return;
    }

    res.setHeader("Cache-Control", "no-store");
    const send = (status: number, payload: unknown) => {
      if (res.writableEnded) return;
      res.writeHead(status, { "Content-Type": "application/json" }).end(JSON.stringify(payload));
    };
    api(req, res, method, path).then(
      (payload) => send(200, payload),
      (error: unknown) => {
        if (error instanceof HttpError) send(error.status, { error: error.message });
        else if (error instanceof Error && /constraint|UNIQUE|CHECK/i.test(error.message)) send(400, { error: "That couldn't be saved" });
        else send(500, { error: "Something went wrong on our side" });
      },
    );
  });
}
