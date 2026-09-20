#!/usr/bin/env node
// GeeTest v4 (gcaptcha4) captcha solver — joined, standalone, in-memory.
//
// Joined from ../splitted/00_config.js .. 09_send_verify.js, in the same step order, with
// three deliberate differences from the split version:
//
//   1. No disk I/O. Every step's output is passed to the next step as a plain in-memory
//      value (function args/return values) — nothing is ever written to or read from a file.
//      Only the two fields actually needed later (the RSA key and the lot-formula table) are
//      pulled out of the ~1MB SDK source; the rest of that source, and the full ~1900-entry
//      decoded string table, are discarded once used instead of being kept or dumped.
//
//   2. No node:vm. Step 2's gct4 module (a tiny UMD bundle that self-hashes its own function
//      source with djb2) is executed with `new Function(...)` instead of a vm.createContext
//      sandbox. That still runs the exact, unmodified source text — which is the property that
//      matters, since hand-porting risks subtly changing the source being hashed — without the
//      weight of a separate V8 context.
//
//   3. No crypto libraries, not even node:crypto. RSA (PKCS#1 v1.5) is implemented from scratch
//      on native BigInt, AES-128-CBC is implemented from scratch as a plain block cipher (SM4-CBC
//      already was standalone in the split version), and the PoW step's hash (server-selected,
//      "md5" in every build seen so far) is a from-scratch RFC 1321 implementation instead of
//      node:crypto's createHash. Zero imports anywhere in this file.
//
// Every pattern used to pull data out of the obfuscated SDK targets ONLY tokens that survive a
// rebuild: real JS globals (`decodeURI`), plain data-field names the server contract requires
// verbatim (`d4tf`), or plain punctuation shape — never the obfuscator's per-compile identifier
// names (e.g. `$_IBBDL`/`$_IBBCv`, confirmed to change build to build). Each extraction does a
// cheap substring/indexOf scan first to pin down a small candidate window, and only runs a regex
// to validate that window's shape — never a regex scan over the full multi-hundred-KB SDK source.

// ============================================================================================
// [00] config
// ============================================================================================

// Flip to true here for local troubleshooting, or pass --debug on the command line.
let DEBUG = false;

// captcha_id ("cid") is static per site integration — the same value every time for a given
// site/widget placement, not something generated per session — so there's no sensible generic
// default to fall back to. It's mandatory; see the check in main() below.
//
// Minimal, dependency-free flag parsing: `--debug` (boolean) and `--cid <id>` / `--cid=<id>`
// (also accepted positionally, for backwards compatibility with the split scripts' `argv[2]`).
function parseArgs(argv) {
  let debug = false;
  let captchaId;
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--debug") {
      debug = true;
    } else if (arg === "--cid") {
      captchaId = argv[++i];
    } else if (arg.startsWith("--cid=")) {
      captchaId = arg.slice("--cid=".length);
    } else if (!arg.startsWith("--") && captchaId === undefined) {
      captchaId = arg; // positional fallback
    }
  }
  return { debug, captchaId };
}

const CLI = parseArgs(process.argv.slice(2));
if (CLI.debug) DEBUG = true;
const CAPTCHA_ID = CLI.captchaId;

function debugLog(...args) {
  if (DEBUG) console.log("[debug]", ...args);
}

const CLIENT_TYPE = "web";
const LANG = "eng"; // matches real captured /load requests (Accept-Language: en-US)

const HOSTS = {
  load: "https://gcaptcha4.geetest.com",
  static: "https://static.geetest.com",
};

// `cookie`, when given, is sent as-is in the Cookie header — used to echo back the
// `captcha_v4_user` identifier gcaptcha4.geetest.com hands out on /load (see requestLoad).
function browserHeaders(referer = "https://gcaptcha4.geetest.com", cookie) {
  const headers = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
    Accept: "*/*",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Accept-Language": "es-419,es;q=0.9,en;q=0.8,de;q=0.7,zh-CN;q=0.6,zh;q=0.5",
    "Cache-Control": "no-cache",
    Pragma: "no-cache",
    "sec-ch-ua": '"Chromium";v="152", "Not?A_Brand";v="24", "Google Chrome";v="152"',
    "sec-ch-ua-mobile": "?0",
    Referer: referer,
  };
  if (cookie) headers.Cookie = cookie;
  return headers;
}

// Pulls one name=value pair out of a set of Set-Cookie header strings (each string is
// "name=value; attr=...; attr" — only the first segment is the pair, the rest are cookie
// attributes like expires/Path/SameSite, not part of what gets echoed back in a Cookie header).
function extractCookieValue(setCookieHeaders, name) {
  for (const header of setCookieHeaders) {
    const pair = header.split(";", 1)[0];
    const eq = pair.indexOf("=");
    if (eq !== -1 && pair.slice(0, eq).trim() === name) return pair.slice(eq + 1).trim();
  }
  return null;
}

function nowUuid() {
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    return (c === "x" ? r : (r & 0x3) | 0x8).toString(16);
  });
}

function geetestCallback() {
  return "geetest_" + (((10000 * Math.random()) | 0) + Date.now());
}

// Same 4-hex-char generator the SDK itself uses; reused for the PoW nonce (e()+e()+e()+e())
// and for the 16-ASCII-char symmetric key in the encrypt step.
function randHex4() {
  return ((65536 * (1 + Math.random())) | 0).toString(16).slice(1);
}

// ============================================================================================
// [01] GET /load — lot_number, pow_detail, opaque payload/process_token, and the paths to the
// two JS files steps 2 and 3 fetch.
// ============================================================================================
function buildLoadUrl(captchaId, { challenge = nowUuid(), callback = geetestCallback() } = {}) {
  const params = new URLSearchParams({
    captcha_id: captchaId,
    challenge,
    client_type: CLIENT_TYPE,
    lang: LANG,
    callback,
  });
  return { url: `${HOSTS.load}/load?${params.toString()}`, challenge, callback };
}

// GeeTest replies as JSONP: `geetest_169...({"status":"success","data":{...}})`.
function parseJsonp(body, callbackName) {
  const prefix = `${callbackName}(`;
  if (!body.startsWith(prefix) || !body.endsWith(")")) {
    throw new Error(`Unexpected JSONP shape, expected wrapper "${callbackName}(...)": ${body.slice(0, 120)}`);
  }
  return JSON.parse(body.slice(prefix.length, -1));
}

async function requestLoad(captchaId) {
  const { url, callback } = buildLoadUrl(captchaId);
  const res = await fetch(url, { headers: browserHeaders() });
  // A real browser gets a `captcha_v4_user` cookie minted here (Set-Cookie, ~1yr expiry,
  // Path=/, SameSite=None) and auto-attaches it to every later request on this host —
  // including /verify. Captured live and confirmed the server accepts a client-supplied
  // value as-is (doesn't reissue one if the request already carries a plausible cookie), so
  // capturing and re-sending it here reproduces that same round-trip.
  const setCookies = typeof res.headers.getSetCookie === "function" ? res.headers.getSetCookie() : [];
  const userCookie = extractCookieValue(setCookies, "captcha_v4_user");
  const json = parseJsonp(await res.text(), callback);
  if (json.status !== "success") throw new Error(`/load failed: ${JSON.stringify(json)}`);
  return { data: json.data, userCookie };
}

// ============================================================================================
// [02] fetch the small gct4.<hash>.js module and run it (no vm) to compute `biht`.
// ============================================================================================
async function fetchGct4Source(gctPath) {
  const url = `${HOSTS.static}${gctPath}`;
  const res = await fetch(url, { headers: browserHeaders() });
  if (!res.ok) throw new Error(`gct4.js fetch failed: HTTP ${res.status}`);
  return await res.text();
}

// The module is a UMD wrapper whose first branch is:
//   typeof exports === "object" && typeof module !== "undefined" ? module.exports = e() : ...
// Calling it via `new Function("module", "exports", source)` with real object arguments makes
// that branch fire deterministically (both typeof checks read "object"), so `module.exports`
// ends up holding the factory's return value — no vm.createContext sandbox required.
function runGct4Module(source) {
  const module = { exports: {} };
  const factory = new Function("module", "exports", source);
  factory(module, module.exports);
  if (typeof module.exports !== "function") {
    throw new Error("gct4.js did not export a function as expected");
  }
  return module.exports;
}

// The exported function returns djb2(djb2FnSource.toString()) — a fixed value for this exact
// build. Calling it with no argument is enough to get `biht`.
function computeBiht(source) {
  const fn = runGct4Module(source);
  return String(fn());
}

// ============================================================================================
// [03] fetch the big gcaptcha4.js SDK and pull out: the lot-number slice-formula table, and
// the XOR-encoded string table (needed only to recover the hardcoded RSA public key).
// ============================================================================================
async function fetchSdkSource(jsPath, staticPath) {
  const url = `${HOSTS.static}${staticPath}${jsPath}`;
  const res = await fetch(url, { headers: browserHeaders() });
  if (!res.ok) throw new Error(`gcaptcha4.js fetch failed: HTTP ${res.status}`);
  return await res.text();
}

// The lot-formula table's KEY is a plain, un-obfuscated object-literal string (a data string,
// not a public API name, so the obfuscator's string-array pass leaves it alone); its VALUE is
// sometimes routed through the string-table decoder instead. Neither side depends on any
// per-compile identifier name.
//
// String filter first: "+.+(n[" is the one punctuation shape that's unique to this table (only
// the joins between the formula's bracket groups produce it) — an indexOf scan finds it in a
// ~1MB file almost instantly and narrows the search to one small window. The regex then only
// has to parse that window, never the full source.
const LOT_FORMULA_ANCHOR = "+.+(n[";
const LOT_FORMULA_RE =
  /"((?:\([^"]*?n\[\d+:\d+\][^"]*?\)(?:\+\.\+)?)+)"\s*:\s*(?:"(n\[\d+:\d+\])"|[^\s"(){}]+\((\d+)\))/;

function findLotFormula(sdkSource) {
  const anchor = sdkSource.indexOf(LOT_FORMULA_ANCHOR);
  if (anchor === -1) throw new Error("Could not locate the lot-formula anchor in gcaptcha4.js");
  const windowStart = Math.max(0, anchor - 400);
  const windowEnd = Math.min(sdkSource.length, anchor + 400);
  const match = sdkSource.slice(windowStart, windowEnd).match(LOT_FORMULA_RE);
  if (!match) throw new Error("Lot-formula anchor found, but the surrounding shape didn't validate");
  const [, keyFormula, literalValue, tableIndex] = match;
  return literalValue
    ? { keyFormula, valueFormula: literalValue }
    : { keyFormula, valueFormulaIndex: Number(tableIndex) };
}

function resolveLotFormula(found, table) {
  if (found.valueFormula) return found;
  return { keyFormula: found.keyFormula, valueFormula: table[found.valueFormulaIndex] };
}

// The big XOR-encoded string table looks like `<anything>=decodeURI("<blob>")<anything>` in
// every build seen so far, immediately followed (module code in between) by `.split("<sep>")`
// and then an IIFE invocation closing with `(<xorKey>)`. `decodeURI` is a real JS global the
// obfuscator can't rename, so it's the one stable anchor; everything else here is found by
// scanning forward for the next quoted string literal — a plain character scan, not a regex —
// and only validated with a small regex once a candidate is in hand.
const PRINTABLE_RE = /^[\x20-\x7E]+$/; // sanity check: must be plain printable ASCII

function nextQuotedLiteral(source, fromIndex, maxScan = 4000) {
  const limit = Math.min(source.length, fromIndex + maxScan);
  for (let i = fromIndex; i < limit; i++) {
    const quote = source[i];
    if (quote !== '"' && quote !== "'") continue;
    const close = source.indexOf(quote, i + 1);
    if (close === -1) break;
    return { value: source.slice(i + 1, close), end: close + 1 };
  }
  return null;
}

function findStringTableBlob(sdkSource) {
  const anchor = sdkSource.indexOf("decodeURI(");
  if (anchor === -1) throw new Error("Could not find a decodeURI( call in gcaptcha4.js");

  const blob = nextQuotedLiteral(sdkSource, anchor, 200);
  if (!blob) throw new Error("decodeURI( found, but no quoted string literal follows it");
  if (blob.value.length < 1000 || !PRINTABLE_RE.test(blob.value)) {
    throw new Error("decodeURI(...) argument doesn't look like the encoded string-table blob");
  }

  // Next quoted literal after the blob is the split() separator; the one after that is the
  // XOR key fed into the closing IIFE call.
  const separator = nextQuotedLiteral(sdkSource, blob.end);
  if (!separator || !/^[\x21-\x7E]{1,4}$/.test(separator.value)) {
    throw new Error("Could not find the string-table split separator after the encoded blob");
  }
  const xorKey = nextQuotedLiteral(sdkSource, separator.end);
  if (!xorKey || !/^[\x20-\x7E]{1,32}$/.test(xorKey.value)) {
    throw new Error("Could not find the XOR key after the string-table split separator");
  }

  debugLog(`string table blob: ${blob.value.length} chars encoded, separator=${JSON.stringify(separator.value)}, xorKey=${JSON.stringify(xorKey.value)}`);
  return { encodedUri: blob.value, separator: separator.value, xorKey: xorKey.value };
}

function decodeStringTable(encodedUri, xorKey, separator) {
  const raw = decodeURI(encodedUri);
  const keyLen = xorKey.length;
  let xored = "";
  for (let i = 0; i < raw.length; i++) {
    xored += String.fromCharCode(raw.charCodeAt(i) ^ xorKey.charCodeAt(i % keyLen));
  }
  return xored.split(separator);
}

// Heuristic, not hardcoded: RSA modulus is by far the longest pure-hex entry in the table (a
// 1024-bit modulus -> ~256-258 hex chars, sometimes with a leading 00 padding byte); the
// exponent "10001" is a short standalone entry elsewhere. Cheap length filter first (plain
// arithmetic on ~1900 short strings), regex shape-check only on what's left.
function findRsaKey(table) {
  const candidates = table.filter((s) => s.length >= 200 && s.length <= 264);
  const hexEntries = candidates.filter((s) => /^[0-9A-Fa-f]+$/.test(s));
  if (hexEntries.length === 0) throw new Error("No modulus-shaped hex string found in the table");
  hexEntries.sort((a, b) => b.length - a.length);
  const modulus = hexEntries[0];

  if (!table.includes("10001")) {
    throw new Error('Expected RSA exponent "10001" not found in the table (heuristic may need updating)');
  }
  return { modulus, exponent: "10001" };
}

// `d4tf` itself is a plain object-literal key (a server-contract field name the obfuscator's
// string-array pass leaves alone, same reasoning as the lot-formula key), but its VALUE is
// sometimes a decoder-table call instead of a literal — same two-shape situation as the lot
// formula's value, so it's resolved the same way. Generalized so both fields share one finder.
function findDecodableField(sdkSource, fieldName) {
  const anchor = sdkSource.indexOf(fieldName);
  if (anchor === -1) throw new Error(`Could not find the "${fieldName}" field anchor in gcaptcha4.js`);
  const windowStart = Math.max(0, anchor - 20);
  const windowEnd = Math.min(sdkSource.length, anchor + 200);
  const window = sdkSource.slice(windowStart, windowEnd);
  const re = new RegExp(`\\b${fieldName}\\s*:\\s*(?:"([^"]*)"|'([^']*)'|[^\\s,}();"']+\\((\\d+)\\))`);
  const match = window.match(re);
  if (!match) throw new Error(`"${fieldName}" anchor found, but the surrounding shape didn't validate`);
  const [, doubleQuoted, singleQuoted, tableIndex] = match;
  if (doubleQuoted !== undefined) return { literal: doubleQuoted };
  if (singleQuoted !== undefined) return { literal: singleQuoted };
  return { tableIndex: Number(tableIndex) };
}

function resolveDecodableField(found, table) {
  return found.literal !== undefined ? found.literal : table[found.tableIndex];
}

function extractSdkSecrets(sdkSource) {
  const lotFormulaFound = findLotFormula(sdkSource);
  const d4tfFound = findDecodableField(sdkSource, "d4tf");
  const { encodedUri, xorKey, separator } = findStringTableBlob(sdkSource);
  const table = decodeStringTable(encodedUri, xorKey, separator);
  debugLog(`decoded string table: ${table.length} entries`);
  const lotFormula = resolveLotFormula(lotFormulaFound, table);
  const d4tf = resolveDecodableField(d4tfFound, table);
  const rsaKey = findRsaKey(table);
  return { lotFormula, d4tf, rsaKey };
}

// ============================================================================================
// [04] turn the lot formula + the real lot_number into the nested proof object the server
// checks in the payload.
// ============================================================================================
function parseLotFormula(formula) {
  const parseIndices = (bracketContent) => {
    const nums = bracketContent.split(":").map((n) => parseInt(n.trim(), 10));
    const start = nums[0];
    const end = nums.length > 1 ? nums[1] + 1 : nums[0] + 1; // inclusive end in the formula
    return [start, end];
  };
  const parseAtom = (atom) => parseIndices(atom.match(/\[(.*?)\]/)[1]);

  return formula.split("+.+").map((group) => {
    const cleaned = group.replace(/[()]/g, "");
    return cleaned.split("+").map(parseAtom);
  });
}

function applyLotFormula(parsedFormula, lotNumber) {
  return parsedFormula
    .map((group) => group.map(([start, end]) => lotNumber.slice(start, end)).join(""))
    .join(".");
}

function buildLotProof(lotNumber, keyFormula, valueFormula) {
  const keyPath = applyLotFormula(parseLotFormula(keyFormula), lotNumber).split(".");
  const value = applyLotFormula(parseLotFormula(valueFormula), lotNumber);

  const result = {};
  let cursor = result;
  keyPath.forEach((key, i) => {
    if (i === keyPath.length - 1) {
      cursor[key] = value;
    } else {
      cursor[key] = cursor[key] || {};
      cursor = cursor[key];
    }
  });
  return result;
}

// ============================================================================================
// [05] solve the hashcash-style PoW described by `pow_detail`.
// version|bits|hashfunc|datetime|captcha_id|lot_number||nonce -> hash(msg), until it satisfies
// `bits` leading zero bits. Real traffic always shows bits:0, so the first attempt qualifies in
// practice — but the loop is real, not assumed away.
//
// `hashfunc` has only ever been observed as "md5" in captured traffic, so that's the one
// algorithm implemented (from scratch, RFC 1321, no node:crypto) rather than building out a
// generic multi-algorithm dispatcher for hash functions that have never actually shown up.
// ============================================================================================

// ---- MD5 (RFC 1321) — standalone, no crypto library ----
const MD5_S = [
  7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15,
  21,
];
const MD5_K = new Int32Array(64);
for (let i = 0; i < 64; i++) MD5_K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 2 ** 32) | 0;

function md5Hex(messageUtf8) {
  const msg = Buffer.from(messageUtf8, "utf8");
  const leftRotate = (x, c) => ((x << c) | (x >>> (32 - c))) >>> 0;

  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;

  const bitLen = BigInt(msg.length) * 8n;
  const padLen = ((56 - ((msg.length + 1) % 64)) + 64) % 64;
  const padded = Buffer.alloc(msg.length + 1 + padLen + 8);
  msg.copy(padded, 0);
  padded[msg.length] = 0x80;
  padded.writeBigUInt64LE(bitLen, padded.length - 8);

  for (let chunkStart = 0; chunkStart < padded.length; chunkStart += 64) {
    const M = new Uint32Array(16);
    for (let j = 0; j < 16; j++) M[j] = padded.readUInt32LE(chunkStart + j * 4);

    let A = a0, B = b0, C = c0, D = d0;
    for (let i = 0; i < 64; i++) {
      let F, g;
      if (i < 16) {
        F = (B & C) | (~B & D);
        g = i;
      } else if (i < 32) {
        F = (D & B) | (~D & C);
        g = (5 * i + 1) % 16;
      } else if (i < 48) {
        F = B ^ C ^ D;
        g = (3 * i + 5) % 16;
      } else {
        F = C ^ (B | ~D);
        g = (7 * i) % 16;
      }
      F = (F + A + MD5_K[i] + M[g]) | 0;
      A = D;
      D = C;
      C = B;
      B = (B + leftRotate(F, MD5_S[i])) | 0;
    }
    a0 = (a0 + A) | 0;
    b0 = (b0 + B) | 0;
    c0 = (c0 + C) | 0;
    d0 = (d0 + D) | 0;
  }

  const out = Buffer.alloc(16);
  out.writeInt32LE(a0, 0);
  out.writeInt32LE(b0, 4);
  out.writeInt32LE(c0, 8);
  out.writeInt32LE(d0, 12);
  return out.toString("hex");
}

function hash(hashfunc, message) {
  if (hashfunc !== "md5") throw new Error(`Unsupported PoW hashfunc "${hashfunc}" (only "md5" has ever been observed)`);
  return md5Hex(message);
}

function bitsOk(digestHex, zeroNibbles, remBits) {
  for (let i = 0; i < zeroNibbles; i++) {
    if (digestHex[i] !== "0") return false;
  }
  if (remBits === 0) return true;
  const nibble = parseInt(digestHex[zeroNibbles], 16);
  return nibble >> (4 - remBits) === 0;
}

function solvePow({ lotNumber, captchaId, hashfunc, version, bits, datetime }) {
  const zeroNibbles = bits >> 2;
  const remBits = bits & 3;
  const base = [version, bits, hashfunc, datetime, captchaId, lotNumber, "", ""].join("|");

  for (;;) {
    const nonce = randHex4() + randHex4() + randHex4() + randHex4();
    const msg = base + nonce;
    const digest = hash(hashfunc, msg);
    if (bitsOk(digest, zeroNibbles, remBits)) return { pow_msg: msg, pow_sign: digest };
  }
}

// ============================================================================================
// [06] the "em" block — GeeTest's headless/automation-detector fingerprint. Ported from the
// real detector functions in gcaptcha4.js (ph/cp/ek/wd/nt/si/sc). Pure Node run: every browser
// global is guarded, so each check correctly reports "not present".
// ============================================================================================
const hasProp = (key, obj) => obj != null && key in obj;

function computeEm({ win = globalThis, nav = globalThis.navigator, doc = globalThis.document } = {}) {
  return {
    ph: hasProp("_phantom", win) ? 1 : 0,
    cp: (() => {
      if (!hasProp("callPhantom", win)) return 0;
      try {
        void win.callPhantom;
      } catch {
        return 9;
      }
      return 1;
    })(),
    ek: (() => {
      const props = ["line", "column", "lineNumber", "columnNumber", "fileName", "message", "number", "description", "sourceURL", "stack"];
      let err;
      try {
        (5 * Math.random())(); // call a number -> throws
      } catch (e) {
        err = e;
      }
      const bits = props.map((p) => (hasProp(p, err) ? 1 : 0)).join("");
      return parseInt(bits, 2).toString(16);
    })(),
    // Real Chrome/Firefox/Safari always expose `navigator.webdriver` (present, `false` for a
    // normal human session) -> code 1. Node is not a browser, so the honest reading here would
    // be "no navigator at all" (8) — except Node 21+ ships a partial `navigator` polyfill (added
    // for web-API compatibility) that lacks `webdriver` specifically, which instead falls through
    // to 0 ("absent"). Both 8 and 0 describe environment shapes that no real browser in current
    // use has ever produced, unlike 1 — so both are mapped to 1 here to match genuine browser
    // traffic instead of leaking "this is actually Node" through this one signal.
    wd: (() => {
      if (!nav) return 1;
      const key = "webdriver";
      const proto = Object.getPrototypeOf ? Object.getPrototypeOf(nav) : nav.__proto__;
      if (!proto) return 1;
      if (!hasProp(key, proto)) return hasProp(key, nav) ? (nav[key] ? 2 : 1) : 1;
      if (!Object.getOwnPropertyDescriptor) return nav[key] ? 2 : 1;
      const desc = Object.getOwnPropertyDescriptor(proto, key);
      if (typeof desc !== "object") return 9;
      const val = desc.get ? desc.get.call(nav) : desc.value;
      return val ? 2 : 1;
    })(),
    nt: hasProp("__nightmare", win) ? 1 : 0,
    si: hasProp("_webdriver_script_fn", doc) ? 1 : 0,
    sc: hasProp("$cdc_asdjflasutopfhvcZLmcfl_", doc) ? 1 : 0,
  };
}

// ============================================================================================
// [07] assemble the exact JSON object that gets encrypted into `w`.
// Field set/order confirmed against real captured payloads:
//   device_id, lot_number, pow_msg, pow_sign, geetest, lang, ep, biht, d4tf,
//   <lot-proof key>, em
// ============================================================================================
function buildPayload({ lotNumber, powMsg, powSign, biht, d4tf, lotProof, em }) {
  return {
    device_id: "",
    lot_number: lotNumber,
    pow_msg: powMsg,
    pow_sign: powSign,
    geetest: "captcha",
    lang: "zh", // matches real captured payloads; comes from gct4's `n.lang`
    ep: "123", // matches real captured payloads; comes from gct4's `n.ep`
    biht,
    d4tf, // extracted per-build in step 3 (findDecodableField), not hardcoded
    ...lotProof,
    em,
  };
}

// ============================================================================================
// [08] encrypt the payload into the final `w` hex blob.
//   s = guid()   (16-byte symmetric key, SDK's own Math.random()-based generator)
//   u = RSA(s)   PKCS#1 v1.5, using the public key extracted in step 3
//   c = cipher(payload, s), zero IV, PKCS7 padding — AES-128-CBC for pt "1", SM4-CBC for pt "2"
//   w = hex(c) + u
// Both ciphers and the RSA transform are implemented from scratch below — no crypto libraries.
// ============================================================================================

// ---- SM4 (GB/T 32907-2016) — verified against the published test vector ----
const SM4_SBOX = [
  0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05, 0x2b, 0x67, 0x9a,
  0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99, 0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef,
  0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62, 0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80,
  0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6, 0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19,
  0xe6, 0x85, 0x4f, 0xa8, 0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d,
  0x35, 0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87, 0xd4, 0x00,
  0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e, 0xea, 0xbf, 0x8a, 0xd2, 0x40,
  0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1, 0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55,
  0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3, 0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23,
  0xab, 0x0d, 0x53, 0x4e, 0x6f, 0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c,
  0x5b, 0x51, 0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8, 0x0a,
  0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0, 0x89, 0x69, 0x97, 0x4a,
  0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84, 0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d,
  0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
];
const SM4_FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc];
const SM4_CK = Array.from({ length: 32 }, (_, i) => {
  const b = [0, 1, 2, 3].map((j) => ((4 * i + j) * 7) % 256);
  return ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0;
});

const rotl = (x, n) => ((x << n) | (x >>> (32 - n))) >>> 0;
const sm4Tau = (a) =>
  ((SM4_SBOX[(a >>> 24) & 255] << 24) | (SM4_SBOX[(a >>> 16) & 255] << 16) | (SM4_SBOX[(a >>> 8) & 255] << 8) | SM4_SBOX[a & 255]) >>> 0;
const sm4L = (b) => (b ^ rotl(b, 2) ^ rotl(b, 10) ^ rotl(b, 18) ^ rotl(b, 24)) >>> 0;
const sm4Lp = (b) => (b ^ rotl(b, 13) ^ rotl(b, 23)) >>> 0;
const sm4T = (x) => sm4L(sm4Tau(x));
const sm4Tp = (x) => sm4Lp(sm4Tau(x));

function bytesToWords(buf, off) {
  const w = [];
  for (let i = 0; i < 4; i++) {
    w.push(((buf[off + 4 * i] << 24) | (buf[off + 4 * i + 1] << 16) | (buf[off + 4 * i + 2] << 8) | buf[off + 4 * i + 3]) >>> 0);
  }
  return w;
}

function sm4ExpandKey(keyBuf) {
  const MK = bytesToWords(keyBuf, 0);
  const K = [MK[0] ^ SM4_FK[0], MK[1] ^ SM4_FK[1], MK[2] ^ SM4_FK[2], MK[3] ^ SM4_FK[3]];
  const rk = [];
  for (let i = 0; i < 32; i++) {
    const next = (K[i] ^ sm4Tp(K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ SM4_CK[i])) >>> 0;
    K.push(next);
    rk.push(next);
  }
  return rk;
}

function sm4CryptBlock(inBuf, rk) {
  const X = bytesToWords(inBuf, 0);
  for (let i = 0; i < 32; i++) {
    X.push((X[i] ^ sm4T(X[i + 1] ^ X[i + 2] ^ X[i + 3] ^ rk[i])) >>> 0);
  }
  const out = Buffer.alloc(16);
  [X[35], X[34], X[33], X[32]].forEach((w, i) => out.writeUInt32BE(w >>> 0, i * 4));
  return out;
}

function pkcs7Pad(buf, blockSize = 16) {
  const padLen = blockSize - (buf.length % blockSize);
  return Buffer.concat([buf, Buffer.alloc(padLen, padLen)]);
}

function sm4CbcEncrypt(plainBuf, keyBuf, ivBuf) {
  const rk = sm4ExpandKey(keyBuf);
  const padded = pkcs7Pad(plainBuf);
  const out = Buffer.alloc(padded.length);
  let prev = ivBuf;
  for (let off = 0; off < padded.length; off += 16) {
    const block = Buffer.alloc(16);
    for (let i = 0; i < 16; i++) block[i] = padded[off + i] ^ prev[i];
    const enc = sm4CryptBlock(block, rk);
    enc.copy(out, off);
    prev = enc;
  }
  return out;
}

// ---- AES-128-CBC, PKCS7 — plain FIPS-197 block cipher from scratch ----
const AES_SBOX = new Uint8Array([
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9,
  0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f,
  0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07,
  0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3,
  0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58,
  0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3,
  0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f,
  0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
  0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac,
  0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a,
  0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70,
  0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
  0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42,
  0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]);
const AES_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

function aesKeyExpansion(key) {
  const Nk = 4, Nr = 10, Nb = 4;
  const w = new Uint8Array(4 * Nb * (Nr + 1));
  w.set(key, 0);
  const temp = new Uint8Array(4);
  for (let i = Nk; i < Nb * (Nr + 1); i++) {
    temp.set(w.subarray((i - 1) * 4, (i - 1) * 4 + 4));
    if (i % Nk === 0) {
      const t0 = temp[0];
      temp[0] = AES_SBOX[temp[1]] ^ AES_RCON[i / Nk - 1];
      temp[1] = AES_SBOX[temp[2]];
      temp[2] = AES_SBOX[temp[3]];
      temp[3] = AES_SBOX[t0];
    }
    for (let j = 0; j < 4; j++) w[i * 4 + j] = w[(i - Nk) * 4 + j] ^ temp[j];
  }
  return w;
}

function aesMul(a, b) {
  let p = 0;
  for (let i = 0; i < 8; i++) {
    if (b & 1) p ^= a;
    const hi = a & 0x80;
    a = (a << 1) & 0xff;
    if (hi) a ^= 0x1b;
    b >>= 1;
  }
  return p & 0xff;
}

function aesAddRoundKey(state, w, round) {
  for (let c = 0; c < 4; c++) for (let r = 0; r < 4; r++) state[r][c] ^= w[round * 16 + c * 4 + r];
}
function aesSubBytes(state) {
  for (let r = 0; r < 4; r++) for (let c = 0; c < 4; c++) state[r][c] = AES_SBOX[state[r][c]];
}
function aesShiftRows(state) {
  for (let r = 1; r < 4; r++) {
    const row = [state[r][0], state[r][1], state[r][2], state[r][3]];
    for (let c = 0; c < 4; c++) state[r][c] = row[(c + r) % 4];
  }
}
function aesMixColumns(state) {
  for (let c = 0; c < 4; c++) {
    const a0 = state[0][c], a1 = state[1][c], a2 = state[2][c], a3 = state[3][c];
    state[0][c] = aesMul(a0, 2) ^ aesMul(a1, 3) ^ a2 ^ a3;
    state[1][c] = a0 ^ aesMul(a1, 2) ^ aesMul(a2, 3) ^ a3;
    state[2][c] = a0 ^ a1 ^ aesMul(a2, 2) ^ aesMul(a3, 3);
    state[3][c] = aesMul(a0, 3) ^ a1 ^ a2 ^ aesMul(a3, 2);
  }
}

function aesEncryptBlock(inBuf, w) {
  const state = [[0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0]];
  for (let i = 0; i < 16; i++) state[i % 4][(i / 4) | 0] = inBuf[i];
  aesAddRoundKey(state, w, 0);
  for (let round = 1; round < 10; round++) {
    aesSubBytes(state);
    aesShiftRows(state);
    aesMixColumns(state);
    aesAddRoundKey(state, w, round);
  }
  aesSubBytes(state);
  aesShiftRows(state);
  aesAddRoundKey(state, w, 10);
  const out = Buffer.alloc(16);
  for (let i = 0; i < 16; i++) out[i] = state[i % 4][(i / 4) | 0];
  return out;
}

function aes128CbcEncrypt(plainBuf, keyBuf, ivBuf) {
  const w = aesKeyExpansion(keyBuf);
  const padded = pkcs7Pad(plainBuf);
  const out = Buffer.alloc(padded.length);
  let prev = ivBuf;
  for (let off = 0; off < padded.length; off += 16) {
    const block = Buffer.alloc(16);
    for (let i = 0; i < 16; i++) block[i] = padded[off + i] ^ prev[i];
    const enc = aesEncryptBlock(block, w);
    enc.copy(out, off);
    prev = enc;
  }
  return out;
}

// ---- RSA (PKCS#1 v1.5 encryption), on native BigInt — no crypto library ----
function bytesToBigInt(bytes) {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  return n;
}
function bigIntToBytes(n, length) {
  const out = Buffer.alloc(length);
  for (let i = length - 1; i >= 0; i--) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}
function modPow(base, exp, mod) {
  let result = 1n;
  base %= mod;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod;
    exp >>= 1n;
    base = (base * base) % mod;
  }
  return result;
}
function bitLength(n) {
  let bits = 0;
  while (n > 0n) {
    n >>= 1n;
    bits++;
  }
  return bits;
}
function randNonZeroByte() {
  return 1 + ((Math.random() * 255) | 0); // 1..255, never 0 (PKCS#1 v1.5 padding requirement)
}

// EM = 0x00 || 0x02 || PS (k-mLen-3 random non-zero bytes) || 0x00 || M
function rsaPkcs1v15EncryptHex(messageBytes, modulusHex, exponentHex) {
  const n = BigInt("0x" + modulusHex);
  const e = BigInt("0x" + exponentHex);
  const k = Math.ceil(bitLength(n) / 8); // true modulus byte length (ignores any leading 00 in the hex dump)
  if (messageBytes.length > k - 11) throw new Error("RSA message too long for this key size");

  const em = Buffer.alloc(k);
  em[0] = 0x00;
  em[1] = 0x02;
  const psLen = k - messageBytes.length - 3;
  for (let i = 0; i < psLen; i++) em[2 + i] = randNonZeroByte();
  em[2 + psLen] = 0x00;
  Buffer.from(messageBytes).copy(em, 3 + psLen);

  const c = modPow(bytesToBigInt(em), e, n);
  const cBytes = bigIntToBytes(c, k); // fixed-width by construction: always exactly k bytes / 2k hex chars
  return cBytes.toString("hex");
}

const ZERO_IV = Buffer.from("0000000000000000", "ascii"); // 16 ascii '0' chars — shared zero IV

function randomSymmetricKey() {
  return randHex4() + randHex4() + randHex4() + randHex4(); // 16 ASCII chars = 16 bytes
}

function buildW(payloadObj, { modulus, exponent, pt }) {
  const data = Buffer.from(JSON.stringify(payloadObj), "utf8");
  const key = randomSymmetricKey();
  const keyBuf = Buffer.from(key, "ascii");
  const u = rsaPkcs1v15EncryptHex(keyBuf, modulus, exponent);

  const c = pt === "1" ? aes128CbcEncrypt(data, keyBuf, ZERO_IV) : sm4CbcEncrypt(data, keyBuf, ZERO_IV);
  return { w: c.toString("hex") + u, key };
}

// ============================================================================================
// [09] GET /verify — send `w` back and get the pass_token / captcha_output.
// ============================================================================================
function buildVerifyUrl({ captchaId, clientType, lotNumber, payload, processToken, payloadProtocol, pt, w, callback = geetestCallback() }) {
  const params = new URLSearchParams({
    callback,
    captcha_id: captchaId,
    client_type: clientType,
    lot_number: lotNumber,
    payload,
    process_token: processToken,
    payload_protocol: String(payloadProtocol),
    pt,
    w,
  });
  return { url: `${HOSTS.load}/verify?${params.toString()}`, callback };
}

async function requestVerify(args) {
  const { url, callback } = buildVerifyUrl(args);
  const cookie = args.userCookie ? `captcha_v4_user=${args.userCookie}` : undefined;
  const res = await fetch(url, { headers: browserHeaders(undefined, cookie) });
  return parseJsonp(await res.text(), callback);
}

// ============================================================================================
// main — runs all 9 steps in memory, in order, no disk I/O.
// ============================================================================================
async function solveCaptcha(captchaId) {
  debugLog(`[1/9] GET /load (captcha_id=${captchaId})`);
  const { data, userCookie } = await requestLoad(captchaId);
  debugLog(`      lot_number=${data.lot_number} pt=${data.pt}`);
  debugLog("      captcha_v4_user cookie:", userCookie);
  debugLog("/load data:", JSON.stringify(data));

  debugLog(`[2/9] gct4 module -> biht`);
  const gct4Source = await fetchGct4Source(data.gct_path);
  const biht = computeBiht(gct4Source);
  debugLog(`      biht=${biht}`);

  debugLog(`[3/9] SDK -> lot formula + RSA key + d4tf`);
  const sdkSource = await fetchSdkSource(data.js, data.static_path);
  debugLog(`      SDK source: ${sdkSource.length} bytes`);
  const { lotFormula, d4tf, rsaKey } = extractSdkSecrets(sdkSource);
  debugLog(`      lot formula key=${lotFormula.keyFormula} value=${lotFormula.valueFormula}`);
  debugLog(`      RSA modulus (${rsaKey.modulus.length} hex chars), exponent=${rsaKey.exponent}`);
  debugLog(`      d4tf=${d4tf}`);

  debugLog(`[4/9] lot proof`);
  const lotProof = buildLotProof(data.lot_number, lotFormula.keyFormula, lotFormula.valueFormula);
  debugLog(`      ${JSON.stringify(lotProof)}`);

  debugLog(`[5/9] proof-of-work`);
  const { pow_msg, pow_sign } = solvePow({
    lotNumber: data.lot_number,
    captchaId,
    hashfunc: data.pow_detail.hashfunc,
    version: data.pow_detail.version,
    bits: data.pow_detail.bits,
    datetime: data.pow_detail.datetime,
  });
  debugLog(`      pow_sign=${pow_sign}`);

  debugLog(`[6/9] em fingerprint`);
  const em = computeEm();
  debugLog(`      ${JSON.stringify(em)}`);

  debugLog(`[7/9] build payload`);
  const payload = buildPayload({ lotNumber: data.lot_number, powMsg: pow_msg, powSign: pow_sign, biht, d4tf, lotProof, em });
  debugLog("      payload:", JSON.stringify(payload));

  debugLog(`[8/9] encrypt -> w`);
  const { w, key } = buildW(payload, { modulus: rsaKey.modulus, exponent: rsaKey.exponent, pt: data.pt });
  debugLog(`      w length=${w.length}`);
  debugLog("      symmetric key:", key);

  debugLog(`[9/9] GET /verify`);
  const result = await requestVerify({
    captchaId,
    clientType: CLIENT_TYPE,
    lotNumber: data.lot_number,
    payload: data.payload,
    processToken: data.process_token,
    payloadProtocol: data.payload_protocol,
    pt: data.pt,
    w,
    userCookie,
  });
  return result;
}

// The consuming site's own login call (POST /api/cross/identity/ic/v2/auth/signin_init,
// confirmed live via captured traffic) expects a `geetest` object with exactly these five
// fields — which is exactly the shape `/verify` already returns under `data.seccode`.
const GEETEST_FIELDS = ["captcha_id", "lot_number", "pass_token", "gen_time", "captcha_output"];

function extractGeetestFields(result) {
  const seccode = result?.data?.seccode;
  if (result.status !== "success" || !seccode) {
    throw new Error(`Captcha was not solved: ${JSON.stringify(result)}`);
  }
  const geetest = {};
  for (const field of GEETEST_FIELDS) {
    if (!seccode[field]) throw new Error(`/verify succeeded but is missing "${field}" in seccode`);
    geetest[field] = seccode[field];
  }
  return geetest;
}

async function main() {
  if (!CAPTCHA_ID) {
    console.error(
      'Missing required captcha_id. Pass it with --cid <captcha_id> (it\'s static per site integration — the same value every /load call for that site uses, not something generated per run; find it in that site\'s own network traffic).'
    );
    process.exitCode = 1;
    return;
  }
  try {
    const result = await solveCaptcha(CAPTCHA_ID);
    debugLog("full /verify response:", JSON.stringify(result, null, 2));
    const geetest = extractGeetestFields(result);
    // the one output that always prints, debug or not — paste straight into the `geetest` key
    // of the site's own signin_init (or equivalent) request body.
    console.log(JSON.stringify({ geetest }, null, 2));
  } catch (err) {
    console.error(DEBUG ? err : err.message || err);
    process.exitCode = 1;
  }
}

// ============================================================================================
// exports — lets other ESM files `import { solveCaptcha } from "./solve.mjs"` and call it
// directly (e.g. with their own captcha_id) without going through the CLI at all.
// ============================================================================================
export { solveCaptcha, extractSdkSecrets, buildLotProof, solvePow, computeEm, buildPayload, buildW, requestVerify, extractGeetestFields, main };
export default solveCaptcha;

// Only auto-run when this file is the actual entry point (`node solve.mjs ...`), never when
// it's imported by another module. The `./solve` launcher below calls `main()` explicitly for
// the binary-style invocation case, since dynamic import() there means this check reads false.
if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
