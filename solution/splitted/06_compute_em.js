// Step 6: the "em" block — GeeTest's headless/automation-detector fingerprint.
// Ported from the real detector functions found in gcaptcha4.js (ph/cp/ek/wd/nt/si/sc).
// This is a pure Node script (no window/navigator/document), so every browser global is
// guarded — on a normal Node run every check correctly reports "not present".
import { writeJSON } from "./00_config.js";

const hasProp = (key, obj) => obj != null && key in obj;

export function computeEm({ win = globalThis, nav = globalThis.navigator, doc = globalThis.document } = {}) {
  return {
    // "_phantom" in window -> PhantomJS. 0 = absent, 1 = present
    ph: hasProp("_phantom", win) ? 1 : 0,

    // "callPhantom" in window, then try reading it -> PhantomJS (older builds)
    // 0 = absent, 1 = present & readable, 9 = present but throws on access
    cp: (() => {
      if (!hasProp("callPhantom", win)) return 0;
      try {
        void win.callPhantom;
      } catch {
        return 9;
      }
      return 1;
    })(),

    // Engine/error-shape fingerprint: which props exist on a thrown TypeError differs by
    // JS engine. Value = 10-bit presence mask, hex-encoded.
    ek: (() => {
      const props = [
        "line", "column", "lineNumber", "columnNumber",
        "fileName", "message", "number", "description",
        "sourceURL", "stack",
      ];
      let err;
      try {
        (5 * Math.random())(); // call a number -> throws
      } catch (e) {
        err = e;
      }
      const bits = props.map((p) => (hasProp(p, err) ? 1 : 0)).join("");
      return parseInt(bits, 2).toString(16);
    })(),

    // navigator.webdriver, walking the prototype chain instead of a naive truthy check.
    // 0 = absent, 1 = present & false, 2 = present & true,
    // 8 = no descriptor owner found, 9 = descriptor exists but isn't a plain object
    wd: (() => {
      if (!nav) return 8; // no navigator at all (plain Node) -> no owner found
      const key = "webdriver";
      const proto = Object.getPrototypeOf ? Object.getPrototypeOf(nav) : nav.__proto__;
      if (!proto) return 8;
      if (!hasProp(key, proto)) {
        return hasProp(key, nav) ? (nav[key] ? 2 : 1) : 0;
      }
      if (!Object.getOwnPropertyDescriptor) {
        return nav[key] ? 2 : 1;
      }
      const desc = Object.getOwnPropertyDescriptor(proto, key);
      if (typeof desc !== "object") return 9;
      const val = desc.get ? desc.get.call(nav) : desc.value;
      return val ? 2 : 1;
    })(),

    // "__nightmare" in window -> Nightmare.js headless browser. 0 = absent, 1 = present
    nt: hasProp("__nightmare", win) ? 1 : 0,

    // "_webdriver_script_fn" in document -> Selenium-injected DOM property
    si: hasProp("_webdriver_script_fn", doc) ? 1 : 0,

    // "$cdc_asdjflasutopfhvcZLmcfl_" in document -> ChromeDriver's randomized CDC marker
    sc: hasProp("$cdc_asdjflasutopfhvcZLmcfl_", doc) ? 1 : 0,
  };
}

function main() {
  const em = computeEm();
  console.log("[06] em =", em);
  writeJSON("06_em.json", em);
  console.log("[06] saved -> output/06_em.json");
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
