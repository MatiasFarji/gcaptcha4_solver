// Step 3: fetch the big gcaptcha4.js SDK and pull two things out of it:
//   1. the lot_number slice-formula table (a plain literal string in the source, no decoding needed)
//   2. the hardcoded RSA public key (buried in the XOR-encoded string table -> needs decoding)
import { HOSTS, FALLBACK, browserHeaders, readJSON, writeJSON, writeText, DECODE_TABLE_TO_FILE } from "./00_config.js";

export async function fetchSdkSource(jsPath, staticPath) {
  const url = `${HOSTS.static}${staticPath}${jsPath}`;
  const res = await fetch(url, { headers: browserHeaders() });
  if (!res.ok) throw new Error(`gcaptcha4.js fetch failed: HTTP ${res.status}`);
  return { url, source: await res.text() };
}

// The lot-number formula KEY is written as a plain, un-obfuscated object-literal key in
// the source — it's a data string, not a "public API name", so the obfuscator's
// string-array pass leaves it alone. The VALUE side, however, turned out to still be
// routed through the decoder (`identifier(60)`) rather than being a plain literal, so we
// capture either shape and resolve the decoder-call case against the decoded table later.
const LOT_FORMULA_RE =
  /"((?:\([^"]*?n\[\d+:\d+\][^"]*?\)(?:\+\.\+)?)+)"\s*:\s*(?:"(n\[\d+:\d+\])"|[^\s"(){}]+\((\d+)\))/;

export function findLotFormula(sdkSource) {
  const match = sdkSource.match(LOT_FORMULA_RE);
  if (!match) throw new Error("Could not locate the lot-number formula table in gcaptcha4.js");
  const [, keyFormula, literalValue, tableIndex] = match;
  return literalValue
    ? { keyFormula, valueFormula: literalValue }
    : { keyFormula, valueFormulaIndex: Number(tableIndex) };
}

// Resolves a findLotFormula() result into concrete {keyFormula, valueFormula} strings,
// pulling valueFormula out of the decoded string table when it wasn't a plain literal.
export function resolveLotFormula(found, table) {
  if (found.valueFormula) return found;
  return { keyFormula: found.keyFormula, valueFormula: table[found.valueFormulaIndex] };
}

// The big XOR-encoded string table: `var $_IBBDL="",$_IBBCv=decodeURI("<blob>");` ... `}}}("<xorKey>")`
// Same structure documented in sources/deobfuscate.py, reimplemented here standalone.
const ENCODED_URI_START = 'var $_IBBDL="",$_IBBCv=decodeURI("';
const ENCODED_URI_END = '");';
const XOR_KEY_RE = /\}\}\}\("([^"]{1,32})"\)/;

export function findStringTableBlob(sdkSource) {
  const start = sdkSource.indexOf(ENCODED_URI_START);
  if (start === -1) throw new Error("Could not find the encoded string-table marker");
  const contentStart = start + ENCODED_URI_START.length;
  const end = sdkSource.indexOf(ENCODED_URI_END, contentStart);
  if (end === -1) throw new Error("Could not find the end of the encoded string-table blob");
  const encodedUri = sdkSource.slice(contentStart, end);

  const keyMatch = sdkSource.slice(end, end + 800).match(XOR_KEY_RE);
  if (!keyMatch) throw new Error("Could not find the XOR key following the encoded blob");

  return { encodedUri, xorKey: keyMatch[1] };
}

export function decodeStringTable(encodedUri, xorKey) {
  const raw = decodeURI(encodedUri);
  const keyLen = xorKey.length;
  let xored = "";
  for (let i = 0; i < raw.length; i++) {
    xored += String.fromCharCode(raw.charCodeAt(i) ^ xorKey.charCodeAt(i % keyLen));
  }
  return xored.split("^");
}

// Heuristic, not hardcoded: RSA modulus is by far the longest pure-hex entry in the table
// (a 1024-bit modulus -> ~256-258 hex chars); the exponent "10001" is a short standalone
// entry elsewhere in the same table. This keeps the finder working even if GeeTest rotates
// the actual key value, as long as they keep shipping it the same way.
export function findRsaKey(table) {
  const hexEntries = table.filter((s) => /^[0-9A-Fa-f]{200,264}$/.test(s));
  if (hexEntries.length === 0) throw new Error("No modulus-shaped hex string found in the table");
  hexEntries.sort((a, b) => b.length - a.length);
  const modulus = hexEntries[0];

  if (!table.includes("10001")) {
    throw new Error("Expected RSA exponent \"10001\" not found in the table (heuristic may need updating)");
  }
  return { modulus, exponent: "10001" };
}

async function main() {
  const loadOut = readJSON("01_load.json");
  const jsPath = loadOut?.data?.js || FALLBACK.js;
  const staticPath = loadOut?.data?.static_path || FALLBACK.staticPath;

  console.log(`[03] Fetching SDK: ${staticPath}${jsPath}`);
  const { url, source } = await fetchSdkSource(jsPath, staticPath);
  writeText("03_gcaptcha4_raw.js", source);
  console.log(`[03] fetched ${Buffer.byteLength(source, "utf8")} bytes from ${url}`);

  const lotFormulaFound = findLotFormula(source);

  const { encodedUri, xorKey } = findStringTableBlob(source);
  console.log(`[03] string table blob found (${encodedUri.length} chars encoded, xor key "${xorKey}")`);

  const table = decodeStringTable(encodedUri, xorKey);
  console.log(`[03] decoded string table: ${table.length} entries`);

  const lotFormula = resolveLotFormula(lotFormulaFound, table);
  console.log("[03] lot formula key   :", lotFormula.keyFormula);
  console.log("[03] lot formula value :", lotFormula.valueFormula);

  if (DECODE_TABLE_TO_FILE) {
    writeJSON("03_string_table.json", table);
    console.log("[03] full decoded table written -> output/03_string_table.json (DECODE_TABLE_TO_FILE=true)");
  } else {
    console.log("[03] DECODE_TABLE_TO_FILE=false, keeping decoded table in memory only");
  }

  const rsaKey = findRsaKey(table);
  console.log("[03] RSA modulus (hex) :", rsaKey.modulus);
  console.log("[03] RSA exponent (hex):", rsaKey.exponent);

  writeJSON("03_sdk.json", { jsPath, staticPath, lotFormula, rsaKey });
  console.log("[03] saved -> output/03_sdk.json");
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((err) => {
    console.error("[03] FAILED:", err);
    process.exit(1);
  });
}
