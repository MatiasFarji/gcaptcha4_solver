// Step 8: encrypt the payload from step 7 into the final `w` hex blob.
//   s = guid()   (16-byte symmetric key, SDK's own Math.random()-based generator)
//   u = RSA(s)   using the public key extracted in step 3
//   c = cipher(payload, s), zero IV, PKCS7 padding. Cipher depends on `pt` (payload_protocol) —
//   the SDK dispatches to a different symmetric module per protocol (see buildW below):
//     pt "2": SM4-CBC (GB/T 32907-2016) — self-contained impl, verified against the
//             official test vector
//     pt "1": AES-128-CBC — the SDK bundles real CryptoJS for this path, confirmed by
//             reading its source directly (see buildW below)
//   w = hex(c) + u
import forge from "node-forge";
import { randHex4 } from "./05_solve_pow.js";
import { readJSON, writeJSON, FALLBACK } from "./00_config.js";

// ---- SM4 (GB/T 32907-2016), from scratch — verified against the published test vector ----
const SBOX = [
  0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
  0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
  0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
  0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
  0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
  0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
  0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
  0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
  0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
  0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
  0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
  0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
  0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
  0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
  0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
  0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48,
];
const FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc];
const CK = Array.from({ length: 32 }, (_, i) => {
  const b = [0, 1, 2, 3].map((j) => ((4 * i + j) * 7) % 256);
  return ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0;
});

const rotl = (x, n) => ((x << n) | (x >>> (32 - n))) >>> 0;
const tau = (a) =>
  ((SBOX[(a >>> 24) & 255] << 24) | (SBOX[(a >>> 16) & 255] << 16) | (SBOX[(a >>> 8) & 255] << 8) | SBOX[a & 255]) >>> 0;
const L = (b) => (b ^ rotl(b, 2) ^ rotl(b, 10) ^ rotl(b, 18) ^ rotl(b, 24)) >>> 0;
const Lp = (b) => (b ^ rotl(b, 13) ^ rotl(b, 23)) >>> 0;
const T = (x) => L(tau(x));
const Tp = (x) => Lp(tau(x));

function bytesToWords(buf, off) {
  const w = [];
  for (let i = 0; i < 4; i++) {
    w.push(((buf[off + 4 * i] << 24) | (buf[off + 4 * i + 1] << 16) | (buf[off + 4 * i + 2] << 8) | buf[off + 4 * i + 3]) >>> 0);
  }
  return w;
}

function expandKey(keyBuf) {
  const MK = bytesToWords(keyBuf, 0);
  const K = [MK[0] ^ FK[0], MK[1] ^ FK[1], MK[2] ^ FK[2], MK[3] ^ FK[3]];
  const rk = [];
  for (let i = 0; i < 32; i++) {
    const next = (K[i] ^ Tp(K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ CK[i])) >>> 0;
    K.push(next);
    rk.push(next);
  }
  return rk;
}

function cryptBlock(inBuf, rk) {
  // same routine for encrypt/decrypt; caller passes reversed rk for decryption
  const X = bytesToWords(inBuf, 0);
  for (let i = 0; i < 32; i++) {
    X.push((X[i] ^ T(X[i + 1] ^ X[i + 2] ^ X[i + 3] ^ rk[i])) >>> 0);
  }
  const out = Buffer.alloc(16);
  [X[35], X[34], X[33], X[32]].forEach((w, i) => out.writeUInt32BE(w >>> 0, i * 4));
  return out;
}

function pkcs7Pad(buf, blockSize = 16) {
  const padLen = blockSize - (buf.length % blockSize);
  return Buffer.concat([buf, Buffer.alloc(padLen, padLen)]);
}

export function sm4CbcEncrypt(plainBuf, keyBuf, ivBuf) {
  const rk = expandKey(keyBuf);
  const padded = pkcs7Pad(plainBuf);
  const out = Buffer.alloc(padded.length);
  let prev = ivBuf;
  for (let off = 0; off < padded.length; off += 16) {
    const block = Buffer.alloc(16);
    for (let i = 0; i < 16; i++) block[i] = padded[off + i] ^ prev[i];
    const enc = cryptBlock(block, rk);
    enc.copy(out, off);
    prev = enc;
  }
  return out;
}

// ---- key generation: exact SDK algorithm (see 05_solve_pow.js's randHex4) ----
export function randomSm4Key() {
  return randHex4() + randHex4() + randHex4() + randHex4(); // 16 ASCII chars = 16 bytes
}

// ---- RSA (PKCS#1 v1.5), using the modulus/exponent extracted in step 3 ----
function rsaPublicKey(modulusHex, exponentHex) {
  const n = new forge.jsbn.BigInteger(modulusHex, 16);
  const e = new forge.jsbn.BigInteger(exponentHex, 16);
  return forge.pki.setRsaPublicKey(n, e);
}

export function rsaEncryptKeyHex(key16, modulusHex, exponentHex) {
  const pub = rsaPublicKey(modulusHex, exponentHex);
  const encrypted = pub.encrypt(key16, "RSAES-PKCS1-V1_5");
  return forge.util.bytesToHex(encrypted);
}

const ZERO_IV = Buffer.from("0000000000000000", "ascii"); // 16 ascii '0' chars — shared zero IV

// Resolved by walking the module graph from the decoded dispatch function
// (sources/gcaptcha4_deobfuscated.js:11507-11549, the `i` function) all the way into module
// 34's actual implementation (found via byte-offset alignment in the raw bundle, then
// confirmed by content — see the investigation notes; module 35, right after, contains the
// literal hardcoded RSA modulus, and module 36, right after that, is the already-confirmed
// SM4-CBC class — both bracket module 34, pinning its identity):
//
//   var r = {
//     1: { symmetrical: AESmod.default,  asymmetric: new RSAcls.default() },   // pt "1"
//     2: { symmetrical: new SM4cls.default({key:s,mode:"cbc",iv:"0000000000000000"}), asymmetric: RSAmod.default },
//   };
//   c = r[pt].symmetrical.encrypt(data, s);   // same call shape for both branches
//
// Module 34 (sources/gcaptcha4_deobfuscated.js:11899-12549) is verbatim, unmodified CryptoJS
// (Base/WordArray/BufferedBlockAlgorithm/Cipher/_createHelper/AES) — not SM4, despite pt "2"
// using SM4. Its `_createHelper`-equivalent (line ~12163) is decisive:
//
//   encrypt: function (message, key, cfg) {
//     key = Latin1.parse(key);                          // raw bytes, NOT an OpenSSL/KDF passphrase
//     (cfg && cfg.iv) || ((cfg = cfg || {}).iv = Latin1.parse("0000000000000000"));
//     var s = SerializableCipher.encrypt(AES, message, key, cfg);
//     ...flatten s.ciphertext into a plain byte array and return it (IV NOT prepended)...
//   }
//
// The dispatch call passes only (data, key) — no cfg — so `cfg.iv` always falls through to
// that same "0000000000000000" constant used by protocol 2's SM4. Mode/padding are
// CryptoJS's own untouched defaults: CBC + Pkcs7. So protocol 1 is plain AES-128-CBC (16
// raw-byte key from the guid string), zero IV — the exact same zero IV as protocol 2, just a
// different cipher. The earlier "IV = key" and "SM4-ECB" guesses both predate this reading
// and are superseded by it.
import { createCipheriv } from "node:crypto";
function aes128CbcEncrypt(dataBuf, keyBuf, ivBuf) {
  const cipher = createCipheriv("aes-128-cbc", keyBuf, ivBuf); // Node defaults to PKCS7 padding
  return Buffer.concat([cipher.update(dataBuf), cipher.final()]);
}

export function buildW(payloadObj, { modulus, exponent, pt }) {
  const data = Buffer.from(JSON.stringify(payloadObj), "utf8");

  let key = randomSm4Key(); // same 16-ASCII-char guid generator regardless of cipher
  let u = rsaEncryptKeyHex(key, modulus, exponent);

  if (pt === "1") {
    // the real SDK retries only in this branch, until the RSA blob is exactly 256 hex chars
    while (!u || u.length !== 256) {
      key = randomSm4Key();
      u = rsaEncryptKeyHex(key, modulus, exponent);
    }
  }

  const keyBuf = Buffer.from(key, "ascii");
  const c = pt === "1" ? aes128CbcEncrypt(data, keyBuf, ZERO_IV) : sm4CbcEncrypt(data, keyBuf, ZERO_IV);
  const w = c.toString("hex") + u;
  return { w, key };
}

function main() {
  const payload = readJSON("07_payload.json");
  const sdkOut = readJSON("03_sdk.json");
  const loadOut = readJSON("01_load.json");

  if (!payload) throw new Error("Missing output/07_payload.json — run 07_build_payload.js first");

  const modulus = sdkOut?.rsaKey?.modulus;
  const exponent = sdkOut?.rsaKey?.exponent;
  const pt = loadOut?.data?.pt || "1";

  if (!modulus || !exponent) throw new Error("Missing RSA key — run 03_fetch_sdk_and_extract.js first");

  console.log("[08] pt        :", pt);
  console.log("[08] payload   :", JSON.stringify(payload));

  const { w, key } = buildW(payload, { modulus, exponent, pt });
  console.log("[08] sm4 key   :", key);
  console.log("[08] w length  :", w.length);
  console.log("[08] w         :", w);

  writeJSON("08_w.json", { w, sm4Key: key });
  console.log("[08] saved -> output/08_w.json");
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
