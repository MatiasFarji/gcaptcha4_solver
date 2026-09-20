#!/usr/bin/env node
// decrypt_challenge_solve.js — decrypts a `w` blob captured from a REAL browser run of the
// GeeTest widget, to inspect the exact payload JSON it builds (for comparison against what
// solve.mjs produces on its own).
//
// This only works against a `w` produced by ../../sources/gcaptcha4_rekeyed.js -- the REAL,
// still-obfuscated gcaptcha4.js with just its RSA modulus argument swapped (NOT the deobfuscated
// copy: deobfuscate.py turned out to corrupt the module system in a way that's invisible when
// just reading the output, but crashes the widget the moment you try to run it -- see that
// file's own header comment for the full story). It won't work against a real captured `w`
// from the actual site — the real gcaptcha4.js encrypts with GeeTest's own RSA key, whose
// private half nobody outside GeeTest has. The rekeyed file swaps in a keypair generated
// locally so this script can decrypt what the browser sends.
//
// Setup:
//   1. Generate your OWN keypair (don't reuse the one below for anything real):
//        node -e "const c=require('crypto');const{publicKey,privateKey}=c.generateKeyPairSync('rsa',{modulusLength:1024,publicExponent:0x10001});const j=publicKey.export({format:'jwk'});console.log(Buffer.from(j.n,'base64url').toString('hex').toUpperCase());console.log(privateKey.export({type:'pkcs1',format:'pem'}))"
//   2. Paste the printed hex modulus into ../../sources/gcaptcha4_rekeyed.js, replacing the
//      quoted modulus string in its one patched call site (see that file's header for how to
//      find it -- there's no "setPublic" text to search for, it's a real decoder call).
//   3. Paste the printed PEM into PRIVATE_KEY_PEM below (replacing the placeholder one).
//   4. Run `node ../../serve.js`, open isolated-captcha-test-local.html through it, solve the
//      widget for real, and copy the `w` value it sends to /verify (browser devtools network
//      tab) into W_HEX below (or pass it as argv[2]).
//
// Usage: node decrypt_challenge_solve.js <w_hex> [pt]   (pt defaults to "1", AES-128-CBC;
// pass "2" for SM4-CBC — see solve.mjs's buildW for which protocol does which)

import { privateDecrypt, createDecipheriv, constants as cryptoConstants } from "node:crypto";

// Replace with YOUR OWN private key (see step 1-3 above) — this one only matches whatever
// modulus you've actually pasted into gcaptcha4_rekeyed.js.
const PRIVATE_KEY_PEM = `-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDMSZpar/52vaUilv6pILC6nujAy7bH1QgSu6WJrc6G/5AQcKws
MTshvkKFC9rscgrwHHfWMg5d5CT7sNsiGzZqIXN3cDYf/+2ChDM+NsK92KsUEr/f
a6RgEXcrmaCNRBvW4CwfDyTqATcuCM6R1HBcF12sno5Bs0eofCx4x3nT4QIDAQAB
AoGARWMqnmrwz3wSvvDyhpen73tSK0oGR1HAcDx0OZNjds8PK8ZZdJk0MH3jMjWY
on8J4AyLV6Gg55s6RJMJm0gK7t1DYYv5+SNvWXVRJHAy94cDY4w+c8/59SOT/BG0
pE8PWSt3GNGZ48QgMZgoZiyVwwxBL2bjMjuxGmn8Chi5OxECQQD90aGaN8HCWBGr
O02cZYwcn+uag/PIAILHOw3qA5WuTjmYNileDnSqtGFXTvnhl2gHZTHjiomPZXk/
VWVzkyozAkEAzgsCU7jYuiaogIXtXhABo9AnggJq5fRPCOY8EuB5f2d83QyubUvC
OtF9JvbNqtr7Trbign6Tw/o4IGH//4qdmwJAEpAXSokTYZxBRo2iwnJmyd0kRPur
g5AOAHYgMWIru0C7U5d6dQeHnshsag87lTUWhZvwBx0lrFgWgvxC3C4CIwJBALBz
0ylZ6xj4VGPEzjQ45v6gG8WGRn/qSuknKxlLbiGCwfcYjiSBtbPjhhehUx7X7FJL
4w24UtmJ5xksdC0nS7MCQQCW/PvSiKnxJODE4pYvH1tH8ic1BUeUHVS6HZWOgFkO
1BUJeYiD+EZT77+0okJnlj2xF8KEMeGUemm8hrbbgCeQ
-----END RSA PRIVATE KEY-----`;

const RSA_CIPHERTEXT_HEX_LEN = 256; // 1024-bit key -> 128 bytes -> 256 hex chars, fixed by the keypair above

function splitW(wHex) {
  const rsaHex = wHex.slice(-RSA_CIPHERTEXT_HEX_LEN);
  const cipherHex = wHex.slice(0, -RSA_CIPHERTEXT_HEX_LEN);
  return { cipherBuf: Buffer.from(cipherHex, "hex"), rsaBuf: Buffer.from(rsaHex, "hex") };
}

// Recent Node/OpenSSL builds (CVE-2023-46809 mitigation) reject RSA_PKCS1_PADDING for
// *private* decryption outright ("no longer supported... --security-revert=CVE-2023-46809"),
// even though it's the padding this key pair actually uses. Raw (unpadded) private decryption
// is still allowed, so do the RSA transform ourselves and strip the EME-PKCS1-v1_5 padding by
// hand -- the exact inverse of the padding solve.mjs's own rsaPkcs1v15EncryptHex builds.
function rsaDecryptKey(rsaBuf) {
  const em = privateDecrypt({ key: PRIVATE_KEY_PEM, padding: cryptoConstants.RSA_NO_PADDING }, rsaBuf);
  if (em[0] !== 0x00 || em[1] !== 0x02) throw new Error("Invalid PKCS#1 v1.5 padding (bad header bytes) -- wrong private key for this w?");
  let i = 2;
  while (i < em.length && em[i] !== 0x00) i++;
  if (i >= em.length) throw new Error("Invalid PKCS#1 v1.5 padding (no 0x00 separator found)");
  return em.subarray(i + 1);
}

function pkcs7Unpad(buf) {
  const padLen = buf[buf.length - 1];
  return buf.subarray(0, buf.length - padLen);
}

function aes128CbcDecrypt(cipherBuf, keyBuf, ivBuf) {
  const decipher = createDecipheriv("aes-128-cbc", keyBuf, ivBuf);
  decipher.setAutoPadding(false); // unpad ourselves so a malformed decrypt is visible, not swallowed
  return pkcs7Unpad(Buffer.concat([decipher.update(cipherBuf), decipher.final()]));
}

// ---- SM4 decrypt (pt "2"): same round function as encryption, reversed round-key order ----
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
const sm4T = (x) => (sm4Tau(x) ^ rotl(sm4Tau(x), 2) ^ rotl(sm4Tau(x), 10) ^ rotl(sm4Tau(x), 18) ^ rotl(sm4Tau(x), 24)) >>> 0;
const sm4Tp = (x) => (sm4Tau(x) ^ rotl(sm4Tau(x), 13) ^ rotl(sm4Tau(x), 23)) >>> 0;

function bytesToWords(buf, off) {
  const w = [];
  for (let i = 0; i < 4; i++) w.push(buf.readUInt32BE(off + 4 * i));
  return w;
}
function sm4ExpandKey(keyBuf) {
  const MK = bytesToWords(keyBuf, 0);
  const K = [MK[0] ^ SM4_FK[0], MK[1] ^ SM4_FK[1], MK[2] ^ SM4_FK[2], MK[3] ^ SM4_FK[3]];
  const rk = [];
  for (let i = 0; i < 32; i++) {
    K.push((K[i] ^ sm4Tp(K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ SM4_CK[i])) >>> 0);
    rk.push(K[i + 4]);
  }
  return rk;
}
function sm4CryptBlock(inBuf, rk) {
  const X = bytesToWords(inBuf, 0);
  for (let i = 0; i < 32; i++) X.push((X[i] ^ sm4T(X[i + 1] ^ X[i + 2] ^ X[i + 3] ^ rk[i])) >>> 0);
  const out = Buffer.alloc(16);
  [X[35], X[34], X[33], X[32]].forEach((w, i) => out.writeUInt32BE(w >>> 0, i * 4));
  return out;
}
function sm4CbcDecrypt(cipherBuf, keyBuf, ivBuf) {
  const rk = sm4ExpandKey(keyBuf).slice().reverse(); // decryption = same rounds, reversed key order
  const out = Buffer.alloc(cipherBuf.length);
  let prev = ivBuf;
  for (let off = 0; off < cipherBuf.length; off += 16) {
    const block = cipherBuf.subarray(off, off + 16);
    const dec = sm4CryptBlock(block, rk);
    for (let i = 0; i < 16; i++) out[off + i] = dec[i] ^ prev[i];
    prev = block;
  }
  return pkcs7Unpad(out);
}

const ZERO_IV = Buffer.from("0000000000000000", "ascii");

function decryptW(wHex, pt) {
  const { cipherBuf, rsaBuf } = splitW(wHex.trim());
  const keyBuf = rsaDecryptKey(rsaBuf);
  const plainBuf = pt === "2" ? sm4CbcDecrypt(cipherBuf, keyBuf, ZERO_IV) : aes128CbcDecrypt(cipherBuf, keyBuf, ZERO_IV);
  return { symmetricKey: keyBuf.toString("ascii"), payload: JSON.parse(plainBuf.toString("utf8")) };
}

// Paste a captured `w` here as a fallback, or pass it as argv[2] instead.
const W_HEX = "";

function main() {
  const wHex = process.argv[2] || W_HEX;
  const pt = process.argv[3] || "1";
  if (!wHex) {
    console.error("Usage: node decrypt_challenge_solve.js <w_hex> [pt]  (or set W_HEX above)");
    process.exitCode = 1;
    return;
  }
  const { symmetricKey, payload } = decryptW(wHex, pt);
  console.log("symmetric key:", symmetricKey);
  console.log(JSON.stringify(payload, null, 2));
}

main();
