import { existsSync, readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { initCrypto } from "./crypto.ts";
import { createApp, seedDirectory } from "./server.ts";
import type { DirectoryEntry } from "./types.ts";

const databasePath = process.env.DATABASE_PATH ?? "speak.db";
const directoryPath = process.env.DIRECTORY_PATH ?? "config/directory.json";
const port = Number(process.env.PORT ?? 3000);

await initCrypto();

const isNew = !existsSync(databasePath);
const db = new DatabaseSync(databasePath);
db.exec("PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000; PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL;");
if (isNew) db.exec(readFileSync("db/schema.sql", "utf8"));

const directory = JSON.parse(readFileSync(directoryPath, "utf8")) as DirectoryEntry[];
seedDirectory(db, directory);

// Binds to localhost: run behind a reverse proxy with access logging turned off.
createApp({
  db,
  directory,
  publicDir: "dist/public",
  powBits: Number(process.env.POW_BITS ?? 18),
  secureCookies: process.env.NODE_ENV === "production",
}).listen(port, process.env.HOST ?? "127.0.0.1");
