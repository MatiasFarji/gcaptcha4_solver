// Step 9: GET https://gcaptcha4.geetest.com/verify
// Query shape confirmed against real captured traffic (Caido request ids 211/3089):
//   callback, captcha_id, client_type, lot_number, payload, process_token,
//   payload_protocol, pt, w (+ optional td/GeeToken, not reproduced here — td's
//   gzip+base64 encoding was out of scope for this pass, see NOTES.md)
import { CLIENT_TYPE, HOSTS, browserHeaders, geetestCallback, readJSON, writeJSON } from "./00_config.js";
import { parseJsonp } from "./01_load_challenge.js";

export function buildVerifyUrl({ captchaId, clientType, lotNumber, payload, processToken, payloadProtocol, pt, w, callback = geetestCallback() }) {
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

export async function requestVerify(args) {
  const { url, callback } = buildVerifyUrl(args);
  const res = await fetch(url, { headers: browserHeaders() });
  const body = await res.text();
  return parseJsonp(body, callback);
}

async function main() {
  const loadOut = readJSON("01_load.json");
  const wOut = readJSON("08_w.json");

  if (!loadOut || !wOut) {
    throw new Error("Missing output/01_load.json or output/08_w.json — run the earlier steps first");
  }

  const { data } = loadOut;
  const args = {
    captchaId: loadOut.captchaId,
    clientType: CLIENT_TYPE,
    lotNumber: data.lot_number,
    payload: data.payload,
    processToken: data.process_token,
    payloadProtocol: data.payload_protocol,
    pt: data.pt,
    w: wOut.w,
  };

  console.log("[09] Sending /verify with lot_number =", args.lotNumber);
  const result = await requestVerify(args);
  console.log("[09] response:", JSON.stringify(result, null, 2));

  writeJSON("09_verify_result.json", result);
  console.log("[09] saved -> output/09_verify_result.json");
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((err) => {
    console.error("[09] FAILED:", err);
    process.exit(1);
  });
}
