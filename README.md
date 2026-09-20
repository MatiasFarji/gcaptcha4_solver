# gcaptcha4_solver

If you want to understand my flow of deobfuscation, you can try to read [Traces.md](./Traces.md), but I can't promise you'll get out alive.

## What this is

A single standalone script (`solve.mjs`) that solves a GeeTest v4 (`gcaptcha4`) captcha end-to-end: fetches the challenge, pulls the RSA key and formulas out of the live obfuscated SDK, solves the proof-of-work, builds and encrypts the payload, and submits it — all in memory, zero dependencies (RSA, AES, SM4, and MD5 are all implemented from scratch in the file).

## Usage

```bash
./solve                                          # uses the default captcha_id baked in
./solve --cid <captcha_id>                       # solve a specific captcha_id
./solve --debug --cid <captcha_id>                # print every step's intermediate values

# equivalent, if you'd rather call node directly:
node ./solution/joined/solve.mjs --cid <captcha_id> --debug
```

By default only the final `/verify` JSON response is printed. Pass `--debug` to see each of the 9 steps as it runs (fetched sizes, extracted RSA key/formulas, PoW, payload, etc.).

## Use it from another script

```js
import solveCaptcha from "./solution/joined/solve.mjs";

const result = await solveCaptcha("<captcha_id>");
console.log(result.data.seccode.pass_token);
```
