import { cpSync, mkdirSync, rmSync } from "node:fs";
import { build } from "esbuild";

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
});
