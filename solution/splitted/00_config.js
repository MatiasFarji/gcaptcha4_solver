// Shared config + tiny fs helpers used by every step. Nothing here talks to the network.
import { mkdirSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));

// --- the only manual input, per the task: everything else is derived from /load ---
export const CAPTCHA_ID = process.argv[2];

export const CLIENT_TYPE = "web";
export const LANG = "eng"; // matches the real captured /load requests (Accept-Language: en-US)

export const HOSTS = {
  load: "https://gcaptcha4.geetest.com",
  static: "https://static.geetest.com",
};

// Known-good fallback paths (from a real captured /load response), used only when a step
// is run standalone (main()) without a fresh 01_load.json to read from.
export const FALLBACK = {
  js: "/js/gcaptcha4.js",
  staticPath: "/v4/static/v1.9.7-fc2ddc",
  gctPath: "/v4/gct/gct4.5a2e755576738ba0499d714db4f1c9e0.js",
};

// Real browser-like headers, copied from the Caido-captured traffic, so the requests look genuine.
export function browserHeaders(referer = "https://gcaptcha4.geetest.com") {
  return {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
    Accept: "*/*",
    "Accept-Language": "en-US,en;q=0.7",
    Referer: referer,
  };
}

// Requested toggle: for now, the fully-decoded gcaptcha4.js string table is written to disk.
// Flip to false later to keep it in memory only (e.g. once we trust the RSA-key finder enough
// to not need the full table dumped for inspection every run).
export const DECODE_TABLE_TO_FILE = true;

export const OUTPUT_DIR = join(__dirname, "..", "output");
export const SOURCES_DIR = join(__dirname, "..", "..", "sources");

export function ensureOutputDir() {
  mkdirSync(OUTPUT_DIR, { recursive: true });
}

export function writeJSON(name, data) {
  ensureOutputDir();
  writeFileSync(join(OUTPUT_DIR, name), JSON.stringify(data, null, 2));
}

export function readJSON(name) {
  const path = join(OUTPUT_DIR, name);
  if (!existsSync(path)) return null;
  return JSON.parse(readFileSync(path, "utf8"));
}

export function writeText(name, text) {
  ensureOutputDir();
  writeFileSync(join(OUTPUT_DIR, name), text);
}

export function nowUuid() {
  // same template the SDK itself uses for the `challenge` param
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    return (c === "x" ? r : (r & 0x3) | 0x8).toString(16);
  });
}

export function geetestCallback() {
  return "geetest_" + (((10000 * Math.random()) | 0) + Date.now());
}
