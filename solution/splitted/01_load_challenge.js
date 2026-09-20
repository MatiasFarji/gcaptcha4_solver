// Step 1: GET https://gcaptcha4.geetest.com/load
// Kicks off the flow: gives us lot_number, pow_detail, the opaque `payload`/process_token,
// and — critically — the paths to the two JS files the next two steps fetch.
import { CAPTCHA_ID, CLIENT_TYPE, LANG, HOSTS, browserHeaders, nowUuid, geetestCallback, writeJSON } from "./00_config.js";

export function buildLoadUrl(captchaId, { challenge = nowUuid(), callback = geetestCallback() } = {}) {
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
// Strip the `callback(` / `)` wrapper and JSON.parse the inside.
export function parseJsonp(body, callbackName) {
  const prefix = `${callbackName}(`;
  if (!body.startsWith(prefix) || !body.endsWith(")")) {
    throw new Error(`Unexpected JSONP shape, expected wrapper "${callbackName}(...)": ${body.slice(0, 120)}`);
  }
  return JSON.parse(body.slice(prefix.length, -1));
}

export async function requestLoad(captchaId) {
  const { url, challenge, callback } = buildLoadUrl(captchaId);
  const res = await fetch(url, { headers: browserHeaders() });
  const body = await res.text();
  const json = parseJsonp(body, callback);
  if (json.status !== "success") {
    throw new Error(`/load failed: ${JSON.stringify(json)}`);
  }
  return { challenge, data: json.data };
}

async function main() {
  console.log(`[01] Requesting /load for captcha_id=${CAPTCHA_ID}`);
  const { challenge, data } = await requestLoad(CAPTCHA_ID);
  console.log("[01] lot_number       :", data.lot_number);
  console.log("[01] pow_detail       :", data.pow_detail);
  console.log("[01] gct_path         :", data.gct_path);
  console.log("[01] js / static_path :", data.js, data.static_path);
  console.log("[01] pt / protocol    :", data.pt, data.payload_protocol);

  writeJSON("01_load.json", { captchaId: CAPTCHA_ID, challenge, data });
  console.log("[01] saved -> output/01_load.json");
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((err) => {
    console.error("[01] FAILED:", err);
    process.exit(1);
  });
}
