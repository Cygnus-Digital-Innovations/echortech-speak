-- Run on every connection: PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;
-- Run at startup: PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL;

CREATE TABLE reader_keys (
  key_id      INTEGER PRIMARY KEY,
  reader_name TEXT NOT NULL,
  public_key  BLOB NOT NULL UNIQUE CHECK (length(public_key) = 32),
  status      TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'retired', 'revoked'))
) STRICT;

CREATE UNIQUE INDEX one_active_key_per_reader
  ON reader_keys (reader_name) WHERE status = 'active';

-- One row per conversation or one-way message.
-- access_token_hash is NULL for one-way messages, which are always closed.
CREATE TABLE threads (
  id                BLOB PRIMARY KEY CHECK (length(id) = 16),
  recipient_key_id  INTEGER NOT NULL REFERENCES reader_keys (key_id) ON DELETE RESTRICT,
  sealed_thread_key BLOB NOT NULL CHECK (length(sealed_thread_key) = 80),
  access_token_hash BLOB UNIQUE CHECK (access_token_hash IS NULL OR length(access_token_hash) = 32),
  status            TEXT NOT NULL CHECK (status IN ('open', 'closed')),
  hidden            INTEGER NOT NULL DEFAULT 0 CHECK (hidden IN (0, 1)),
  last_read_seq     INTEGER NOT NULL DEFAULT 0 CHECK (last_read_seq >= 0),
  CHECK (status = 'closed' OR access_token_hash IS NOT NULL)
) STRICT, WITHOUT ROWID;

CREATE INDEX threads_by_recipient ON threads (recipient_key_id);

CREATE TABLE messages (
  thread_id  BLOB NOT NULL REFERENCES threads (id) ON DELETE RESTRICT,
  seq        INTEGER NOT NULL CHECK (seq >= 1),
  ciphertext BLOB NOT NULL CHECK (length(ciphertext) = 16424),
  author     TEXT NOT NULL CHECK (author IN ('sender', 'recipient')),
  PRIMARY KEY (thread_id, seq)
) STRICT, WITHOUT ROWID;

-- Once sent, a message cannot be changed or deleted through the database.
CREATE TRIGGER messages_no_delete BEFORE DELETE ON messages
BEGIN SELECT RAISE(ABORT, 'messages cannot be deleted'); END;

CREATE TRIGGER messages_no_update BEFORE UPDATE ON messages
BEGIN SELECT RAISE(ABORT, 'messages cannot be changed'); END;

CREATE TRIGGER threads_no_delete BEFORE DELETE ON threads
BEGIN SELECT RAISE(ABORT, 'threads cannot be deleted'); END;

CREATE TRIGGER threads_fixed_columns
BEFORE UPDATE OF id, recipient_key_id, sealed_thread_key, access_token_hash ON threads
BEGIN SELECT RAISE(ABORT, 'thread identity cannot be changed'); END;
