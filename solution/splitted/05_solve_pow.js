// Step 5: solve the hashcash-style PoW described by `pow_detail` from step 1.
// version|bits|hashfunc|datetime|captcha_id|lot_number||nonce -> hash(msg), until it
// satisfies `bits` leading zero bits.
import { createHash } from "node:crypto";
import { CAPTCHA_ID, readJSON, writeJSON } from "./00_config.js";

// Same 4-hex-char generator the SDK itself uses (confirmed from source), reused here for
// the PoW nonce (`e()+e()+e()+e()` -> 16 hex chars) as well as the cipher step's key.
export function randHex4() {
  return ((65536 * (1 + Math.random())) | 0).toString(16).slice(1);
}

function hash(hashfunc, message) {
  return createHash(hashfunc).update(message, "utf8").digest("hex");
}

function bitsOk(digestHex, zeroNibbles, remBits) {
  for (let i = 0; i < zeroNibbles; i++) {
    if (digestHex[i] !== "0") return false;
  }
  if (remBits === 0) return true;
  const nibble = parseInt(digestHex[zeroNibbles], 16);
  return (nibble >> (4 - remBits)) === 0;
}

export function solvePow({ lotNumber, captchaId, hashfunc, version, bits, datetime }) {
  const zeroNibbles = bits >> 2;
  const remBits = bits & 3;
  const base = [version, bits, hashfunc, datetime, captchaId, lotNumber, "", ""].join("|");

  for (;;) {
    const nonce = randHex4() + randHex4() + randHex4() + randHex4();
    const msg = base + nonce;
    const digest = hash(hashfunc, msg);
    if (bitsOk(digest, zeroNibbles, remBits)) {
      return { pow_msg: msg, pow_sign: digest };
    }
  }
}

function main() {
  const loadOut = readJSON("01_load.json");
  const data = loadOut?.data;

  const powDetail = data?.pow_detail || { version: "1", bits: 0, datetime: new Date().toISOString(), hashfunc: "md5" };
  const lotNumber = data?.lot_number || "f48120300ff2434699864373a68e785a";
  const captchaId = data?.pow_detail ? (loadOut.captchaId || CAPTCHA_ID) : CAPTCHA_ID;

  console.log("[05] pow_detail :", powDetail);
  console.log("[05] lot_number :", lotNumber);

  const { pow_msg, pow_sign } = solvePow({
    lotNumber,
    captchaId,
    hashfunc: powDetail.hashfunc,
    version: powDetail.version,
    bits: powDetail.bits,
    datetime: powDetail.datetime,
  });

  console.log("[05] pow_msg  :", pow_msg);
  console.log("[05] pow_sign :", pow_sign);

  writeJSON("05_pow.json", { pow_msg, pow_sign });
  console.log("[05] saved -> output/05_pow.json");
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
