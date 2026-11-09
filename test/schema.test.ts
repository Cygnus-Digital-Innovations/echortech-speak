import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { beforeEach, describe, expect, it } from "vitest";

const schema = readFileSync(new URL("../db/schema.sql", import.meta.url), "utf8");
const blob = (size: number) => randomBytes(size);
let db: DatabaseSync;

const addKey = (name: string, status = "active") =>
  db.prepare("INSERT INTO reader_keys (reader_name, public_key, status) VALUES (?, ?, ?)").run(name, blob(32), status)
    .lastInsertRowid;

const addThread = (id: Buffer, overrides: { token?: Buffer | null; status?: string; keyId?: number | bigint; sealed?: Buffer } = {}) =>
  db
    .prepare("INSERT INTO threads (id, recipient_key_id, sealed_thread_key, access_token_hash, status) VALUES (?, ?, ?, ?, ?)")
    .run(id, overrides.keyId ?? 1, overrides.sealed ?? blob(80), overrides.token === undefined ? blob(32) : overrides.token, overrides.status ?? "open");

const addMessage = (threadId: Buffer, seq: number, size = 16424) =>
  db.prepare("INSERT INTO messages (thread_id, seq, ciphertext) VALUES (?, ?, ?)").run(threadId, seq, blob(size));

beforeEach(() => {
  db = new DatabaseSync(":memory:");
  db.exec("PRAGMA foreign_keys = ON");
  db.exec(schema);
  addKey("Reader A");
});

describe("reader_keys", () => {
  it("allows one active key per person, plus retired ones", () => {
    expect(() => addKey("Reader A")).toThrow();
    expect(() => addKey("Reader A", "retired")).not.toThrow();
  });

  it("rejects a key of the wrong size", () => {
    expect(() =>
      db.prepare("INSERT INTO reader_keys (reader_name, public_key) VALUES ('B', ?)").run(blob(31)),
    ).toThrow();
  });

  it("cannot remove a key that threads depend on", () => {
    addThread(blob(16));
    expect(() => db.exec("DELETE FROM reader_keys WHERE key_id = 1")).toThrow();
  });
});

describe("threads", () => {
  it("accepts chats and many one-way messages", () => {
    expect(() => addThread(blob(16))).not.toThrow();
    expect(() => addThread(blob(16), { token: null, status: "closed" })).not.toThrow();
    expect(() => addThread(blob(16), { token: null, status: "closed" })).not.toThrow();
  });

  it("rejects an open thread with no sender token", () => {
    expect(() => addThread(blob(16), { token: null, status: "open" })).toThrow();
  });

  it("rejects an unknown recipient", () => {
    expect(() => addThread(blob(16), { keyId: 999 })).toThrow();
  });

  it("rejects a duplicate sender token", () => {
    const token = blob(32);
    addThread(blob(16), { token });
    expect(() => addThread(blob(16), { token })).toThrow();
  });

  it("rejects a badly sized sealed key", () => {
    expect(() => addThread(blob(16), { sealed: blob(79) })).toThrow();
  });

  it("can be closed, hidden and marked read", () => {
    const id = blob(16);
    addThread(id);
    expect(() => db.prepare("UPDATE threads SET status = 'closed', hidden = 1, last_read_seq = 3 WHERE id = ?").run(id)).not.toThrow();
  });

  it("cannot be deleted", () => {
    const id = blob(16);
    addThread(id);
    expect(() => db.prepare("DELETE FROM threads WHERE id = ?").run(id)).toThrow(/cannot be deleted/);
  });

  it("cannot be moved to another recipient or have its key replaced", () => {
    const id = blob(16);
    addThread(id);
    const other = addKey("Reader B");
    expect(() => db.prepare("UPDATE threads SET recipient_key_id = ? WHERE id = ?").run(other, id)).toThrow(/cannot be changed/);
    expect(() => db.prepare("UPDATE threads SET sealed_thread_key = ? WHERE id = ?").run(blob(80), id)).toThrow(/cannot be changed/);
  });
});

describe("messages", () => {
  it("rejects two messages taking the same place", () => {
    const id = blob(16);
    addThread(id);
    addMessage(id, 1);
    expect(() => addMessage(id, 1)).toThrow();
  });

  it("rejects unpadded messages and unknown threads", () => {
    const id = blob(16);
    addThread(id);
    expect(() => addMessage(id, 1, 100)).toThrow();
    expect(() => addMessage(blob(16), 1)).toThrow();
  });

  it("cannot be deleted or changed once sent", () => {
    const id = blob(16);
    addThread(id);
    addMessage(id, 1);
    expect(() => db.prepare("DELETE FROM messages WHERE thread_id = ?").run(id)).toThrow(/cannot be deleted/);
    expect(() => db.prepare("UPDATE messages SET ciphertext = ? WHERE thread_id = ?").run(blob(16424), id)).toThrow(/cannot be changed/);
  });
});

describe("indexes", () => {
  it("finds a person's inbox through the index", () => {
    const plan = db.prepare("EXPLAIN QUERY PLAN SELECT id FROM threads WHERE recipient_key_id = 1").all();
    expect(JSON.stringify(plan)).toContain("threads_by_recipient");
  });
});
