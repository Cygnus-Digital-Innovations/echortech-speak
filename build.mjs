import { cpSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import { build } from "esbuild";
import { validateDirectory } from "./src/types.ts";

const directoryPath = process.env.DIRECTORY_PATH ?? "config/directory.json";
const directory = JSON.parse(readFileSync(directoryPath, "utf8"));
validateDirectory(directory);

rmSync("dist", { recursive: true, force: true });
mkdirSync("dist/public/assets", { recursive: true });
cpSync("public", "dist/public", { recursive: true });

await build({
  entryPoints: ["send", "chat", "inbox", "setup"].map((page) => `src/client/${page}.ts`),
  outdir: "dist/public/assets",
  bundle: true,
  format: "esm",
  platform: "browser",
  target: "es2022",
  minify: true,
  external: ["crypto", "path", "fs"],
  define: { __DIRECTORY__: JSON.stringify(directory) },
});
