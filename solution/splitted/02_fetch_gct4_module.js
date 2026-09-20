// Step 2: fetch the small gct4.<hash>.js module (path comes from step 1's `gct_path`)
// and actually RUN it in a sandboxed VM context to compute `biht`.
//
// We don't hand-port its logic: it's a UMD module that self-hashes its own function
// source (djb2 of djb2.toString()), so re-typing it by hand risks subtly changing the
// exact source text being hashed, which would silently produce the wrong biht. Running
// the real file is the only way to be sure the value matches what the real SDK sends.
import vm from "node:vm";
import { HOSTS, FALLBACK, browserHeaders, readJSON, writeJSON, writeText, SOURCES_DIR } from "./00_config.js";
import { join } from "node:path";

export async function fetchGct4Source(gctPath) {
  const url = `${HOSTS.static}${gctPath}`;
  const res = await fetch(url, { headers: browserHeaders() });
  if (!res.ok) throw new Error(`gct4.js fetch failed: HTTP ${res.status}`);
  return { url, source: await res.text() };
}

// The module is a UMD wrapper: (function(root, factory){ ... root[X] = factory(); }(this, function(){ ... return t; }));
// Give it a minimal CommonJS-ish sandbox so the UMD branch that does `module.exports = factory()` fires,
// and pull the exported function back out.
export function loadGct4Module(source) {
  const sandbox = { module: { exports: {} }, exports: {}, self: undefined, globalThis: undefined };
  sandbox.self = sandbox; // some UMD templates check `typeof self !== "undefined"`
  vm.createContext(sandbox);
  vm.runInContext(source, sandbox, { filename: "gct4.js" });
  const exported = sandbox.module.exports;
  if (typeof exported !== "function") {
    throw new Error("gct4.js did not export a function as expected");
  }
  return exported;
}

// The exported function ignores its argument unless it's a real function (then it also
// tags that function); either way it returns djb2(djb2FnSource.toString()) — a fixed
// value for this exact build. Calling with no argument is enough to get `biht`.
export function computeBiht(gct4Fn) {
  return String(gct4Fn());
}

async function main() {
  const loadOut = readJSON("01_load.json");
  const gctPath = loadOut?.data?.gct_path || FALLBACK.gctPath;
  console.log(`[02] Fetching gct4 module: ${gctPath}`);

  const { url, source } = await fetchGct4Source(gctPath);
  writeText("02_gct4_raw.js", source); // archive the exact bytes we ran, for reproducibility
  console.log(`[02] fetched ${source.length} bytes from ${url}`);

  const fn = loadGct4Module(source);
  const biht = computeBiht(fn);
  console.log("[02] biht =", biht);

  writeJSON("02_gct4.json", { gctPath, biht });
  console.log("[02] saved -> output/02_gct4.json");
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((err) => {
    console.error("[02] FAILED:", err);
    process.exit(1);
  });
}
