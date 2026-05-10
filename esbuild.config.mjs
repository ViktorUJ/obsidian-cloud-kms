import esbuild from "esbuild";
import { readFileSync } from "fs";

const prod = process.argv[2] === "production";

const manifest = JSON.parse(readFileSync("manifest.json", "utf8"));

const context = await esbuild.context({
  entryPoints: ["src/main.ts"],
  bundle: true,
  external: [
    "obsidian",
    "electron",
    "@codemirror/autocomplete",
    "@codemirror/collab",
    "@codemirror/commands",
    "@codemirror/language",
    "@codemirror/lint",
    "@codemirror/search",
    "@codemirror/state",
    "@codemirror/view",
    "@lezer/common",
    "@lezer/highlight",
    "@lezer/lr",
    // Node.js built-ins used by AWS SDK credential providers (available in Electron runtime)
    "os",
    "path",
    "fs",
    "http",
    "https",
    "url",
    "buffer",
    "crypto",
    "child_process",
    "util",
    "node:os",
    "node:path",
    "node:fs",
    "node:http",
    "node:https",
    "node:url",
    "node:buffer",
    "node:crypto",
    "node:child_process",
    "node:util",
  ],
  format: "cjs",
  target: "es2021",
  logLevel: "info",
  sourcemap: prod ? false : "inline",
  treeShaking: true,
  outfile: "main.js",
  minify: prod,
  define: {
    "process.env.NODE_ENV": prod ? '"production"' : '"development"',
  },
});

if (prod) {
  await context.rebuild();
  await context.dispose();
} else {
  await context.watch();
}
