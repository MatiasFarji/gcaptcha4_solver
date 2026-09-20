// Step 7: assemble the exact JSON object that gets SM4/RSA-encrypted into `w`.
// Field set and order confirmed against real captured payloads in Traces.md:
//   device_id, lot_number, pow_msg, pow_sign, geetest, lang, ep, biht, d4tf,
//   <lot-proof key>, em
import { readJSON, writeJSON } from "./00_config.js";

export function buildPayload({ lotNumber, powMsg, powSign, biht, lotProof, em }) {
  return {
    device_id: "",
    lot_number: lotNumber,
    pow_msg: powMsg,
    pow_sign: powSign,
    geetest: "captcha",
    lang: "zh", // matches the real captured payloads; comes from gct4's `n.lang`
    ep: "123", // matches the real captured payloads; comes from gct4's `n.ep`
    biht,
    d4tf: "9342", // hardcoded in gcaptcha4.js's own bootstrap IIFE, see step 3 / NOTES.md
    ...lotProof, // the {[k1]:{[k2]:{[k3]:value}}} proof from step 4, merged at top level
    em,
  };
}

function main() {
  const loadOut = readJSON("01_load.json");
  const powOut = readJSON("05_pow.json");
  const gct4Out = readJSON("02_gct4.json");
  const lotProofOut = readJSON("04_lot_proof.json");
  const emOut = readJSON("06_em.json");

  const lotNumber = loadOut?.data?.lot_number || lotProofOut?.lotNumber || "f48120300ff2434699864373a68e785a";

  const payload = buildPayload({
    lotNumber,
    powMsg: powOut?.pow_msg || "1|0|md5|placeholder||||placeholder",
    powSign: powOut?.pow_sign || "placeholder",
    biht: gct4Out?.biht ?? "0",
    lotProof: lotProofOut?.proof || {},
    em: emOut || { ph: 0, cp: 0, ek: "0", wd: 0, nt: 0, si: 0, sc: 0 },
  });

  console.log("[07] payload =", JSON.stringify(payload));
  writeJSON("07_payload.json", payload);
  console.log("[07] saved -> output/07_payload.json");
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
