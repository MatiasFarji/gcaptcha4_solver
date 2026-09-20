// Step 4: turn the lot formula from step 3 + the real lot_number from step 1 into the
// nested {[k1]: {[k2]: {[k3]: value}}} proof object the server checks in the payload.
import { readJSON, writeJSON, FALLBACK } from "./00_config.js";

export function parseLotFormula(formula) {
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

export function applyLotFormula(parsedFormula, lotNumber) {
  return parsedFormula
    .map((group) => group.map(([start, end]) => lotNumber.slice(start, end)).join(""))
    .join(".");
}

export function buildLotProof(lotNumber, keyFormula, valueFormula) {
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

function main() {
  const loadOut = readJSON("01_load.json");
  const sdkOut = readJSON("03_sdk.json");

  const lotNumber = loadOut?.data?.lot_number || "f48120300ff2434699864373a68e785a"; // sample fallback
  const { keyFormula, valueFormula } =
    sdkOut?.lotFormula || {
      keyFormula: "(n[16:19])+.+(n[2:5]+n[20:23])+.+(n[28:28]+n[18:18]+n[9:9]+n[13:13])",
      valueFormula: "n[22:25]",
    };

  console.log("[04] lot_number   :", lotNumber);
  console.log("[04] key formula  :", keyFormula);
  console.log("[04] value formula:", valueFormula);

  const proof = buildLotProof(lotNumber, keyFormula, valueFormula);
  console.log("[04] proof        :", JSON.stringify(proof));

  writeJSON("04_lot_proof.json", { lotNumber, proof });
  console.log("[04] saved -> output/04_lot_proof.json");
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
