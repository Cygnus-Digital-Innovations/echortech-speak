// Admin commands, run inside the container:
//   node src/admin.ts list
//   node src/admin.ts revoke "Their name"
import { DatabaseSync } from "node:sqlite";

const db = new DatabaseSync(process.env.DATABASE_PATH ?? "speak.db");
const [command, name] = process.argv.slice(2);

if (command === "list") {
  for (const row of db.prepare("SELECT key_id, reader_name, status FROM reader_keys ORDER BY key_id").all()) console.log(row);
} else if (command === "revoke" && name) {
  const { changes } = db.prepare("UPDATE reader_keys SET status = 'revoked' WHERE status = 'active' AND lower(reader_name) = lower(?)").run(name);
  console.log(changes ? `Revoked ${name}. Restart the container to end any open session.` : `No active person named ${name}`);
} else {
  console.log('Usage: node src/admin.ts list | revoke "Their name"');
  process.exitCode = 1;
}
