"""
deobfuscate.py
==============
Reads gcaptcha4.js and gcaptcha4_decoder.js from the same directory,
replaces every decoder call with the decoded string literal, and writes
the result to gcaptcha4_deobfuscated.js.

HOW TO USE
----------
  python3 deobfuscate.py

All three files must live in the same directory as this script.

PATTERN CONSTANT
----------------
DECODER_CANONICAL is the exact fully-qualified name of the decoder function
as it appears in the source.  The script uses this to locate the XOR key and
the encoded URI string inside gcaptcha4.js.  Update it if the captcha vendor
renames it in a future build.

The alias detection works independently of this name (it relies on the
structural pattern of how $_Cr is aliased per scope), but the canonical name
is used as the anchor to find the encoded payload and the XOR key.
"""

import re
import sys
import os
from urllib.parse import unquote

# ---------------------------------------------------------------------------
# ❶  CANONICAL DECODER NAME — update this when the vendor renames it
# ---------------------------------------------------------------------------
DECODER_CANONICAL = "_ᕺᖄᖃᖚ.$_Ai.$_IBAIg"


# ---------------------------------------------------------------------------
# ❷  Locate source files relative to this script
# ---------------------------------------------------------------------------
SCRIPT_DIR       = os.path.dirname(os.path.abspath(__file__))
SOURCE_FILE      = os.path.join(SCRIPT_DIR, "gcaptcha4.js")
DECODER_FILE     = os.path.join(SCRIPT_DIR, "gcaptcha4_decoder.js")
OUTPUT_FILE      = os.path.join(SCRIPT_DIR, "gcaptcha4_deobfuscated.js")


# ---------------------------------------------------------------------------
# ❸  Build the lookup table by re-running the same algorithm as the JS
# ---------------------------------------------------------------------------
def build_table(source: str) -> list[str]:
    """
    Extracts the encoded URI payload and XOR key from gcaptcha4.js and
    returns the decoded string table (a list of ~1900 strings).

    The JS logic being replicated:
        var $_IBBCv = decodeURI("<ENCODED_URI>");
        // XOR each char of $_IBBCv with the repeating key
        // split the result on "^"
        // return function(n) { return table[n]; }
    """
    # --- locate encoded URI string ---
    marker = 'var $_IBBDL="",$_IBBCv=decodeURI("'
    start  = source.find(marker)
    if start == -1:
        sys.exit("[ERROR] Could not find encoded URI marker in gcaptcha4.js.\n"
                 f"        Expected: {marker!r}")

    end_marker = '");_ᖂᖀᖈᕷ=1'
    end = source.find(end_marker, start)
    if end == -1:
        sys.exit("[ERROR] Could not find end of encoded URI string.")

    encoded_uri = source[start + len(marker) : end]

    # --- locate XOR key (IIFE argument at the very end of the $_IBAIg block) ---
    # Pattern: }}}("KEY")  — appears a few hundred chars after the end of the URI string,
    # after the return-function and closing braces of the state machine.
    key_match = re.search(r'\}\}\}\("([^"]{1,32})"\)', source[end:end + 800])
    if not key_match:
        sys.exit("[ERROR] Could not find XOR key after the encoded URI block.")

    xor_key = key_match.group(1)

    # --- decode ---
    raw    = unquote(encoded_uri)
    key_len = len(xor_key)
    xored  = "".join(
        chr(ord(raw[i]) ^ ord(xor_key[i % key_len]))
        for i in range(len(raw))
    )
    table = xored.split("^")

    print(f"[+] Encoded URI length : {len(encoded_uri):,} chars")
    print(f"[+] XOR key            : {xor_key!r}")
    print(f"[+] Table size         : {len(table):,} entries")
    return table


# ---------------------------------------------------------------------------
# ❹  Discover all alias variable names that delegate to the decoder
# ---------------------------------------------------------------------------
def find_alias_names(source: str) -> list[str]:
    """
    Every function scope sets up decoder aliases with this pattern:

        var A = _ᕺᖄᖃᖚ.$_Cr,
            B = ["$_SENTINEL"].concat(A),
            C = B[1];
        B.shift();
        var D = B[0];

    A, C and D are all aliases for the decoder (B is the temporary array).
    We collect the unique set of alias names.

    The pattern is anchored on $_Cr (the public wrapper of $_IBAIg) which
    is always referenced literally — aliases only exist for local scopes.
    """
    # Unicode range covers the Unified Canadian Aboriginal Syllabics block
    # used for all obfuscated identifiers in this file.
    ID = r'_[ᕴ-ᖚ]+'

    pattern = re.compile(
        rf'var ({ID})=_ᕺᖄᖃᖚ\.\$_Cr,'
        rf'({ID})=\["[^"]+"\]\.concat\(\1\),'
        rf'({ID})=\2\[1\];\2\.shift\(\);'
        rf'var ({ID})=\2\[0\]'
    )

    alias_names: set[str] = set()
    for m in pattern.finditer(source):
        a, _b, c, d = m.group(1), m.group(2), m.group(3), m.group(4)
        alias_names.update([a, c, d])   # _b is the temp array, not a decoder alias

    if not alias_names:
        sys.exit("[ERROR] No alias declarations found.  "
                 "The obfuscation pattern may have changed.")

    print(f"[+] Alias names found  : {sorted(alias_names)}")
    return sorted(alias_names)


# ---------------------------------------------------------------------------
# ❺  Replace every alias(integer) call with the decoded string literal
# ---------------------------------------------------------------------------
def deobfuscate(source: str, table: list[str], alias_names: list[str]) -> tuple[str, int]:
    """
    Replaces every occurrence of  aliasName(digits)  with  "decoded_value"
    using JSON-style escaping so the result is valid JS.

    Returns (deobfuscated_source, replacement_count).
    """
    alias_pat = "|".join(re.escape(n) for n in alias_names)
    call_re   = re.compile(rf'(?:{alias_pat})\((\d+)\)')

    count = 0
    out_of_bounds: list[int] = []

    def replace(m: re.Match) -> str:
        nonlocal count
        idx = int(m.group(1))
        if idx >= len(table):
            out_of_bounds.append(idx)
            return m.group(0)          # leave untouched
        count += 1
        value = table[idx]
        # Produce a JS string literal: escape backslashes, double-quotes, newlines
        escaped = (value
                   .replace("\\", "\\\\")
                   .replace('"',  '\\"')
                   .replace("\n", "\\n")
                   .replace("\r", "\\r"))
        return f'"{escaped}"'

    result = call_re.sub(replace, source)

    if out_of_bounds:
        print(f"[!] Out-of-bounds indices (left as-is): {sorted(set(out_of_bounds))}")

    return result, count


# ---------------------------------------------------------------------------
# ❻  Main
# ---------------------------------------------------------------------------
def main() -> None:
    print("=" * 60)
    print(f"  gcaptcha4 deobfuscator")
    print(f"  Canonical decoder : {DECODER_CANONICAL}")
    print("=" * 60)

    # Read source
    if not os.path.exists(SOURCE_FILE):
        sys.exit(f"[ERROR] Source file not found: {SOURCE_FILE}")
    with open(SOURCE_FILE, "r", encoding="utf-8") as fh:
        source = fh.read()
    print(f"[+] Read source        : {SOURCE_FILE}  ({len(source):,} bytes)")

    # Optional: acknowledge the decoder file exists (not strictly needed since
    # we re-derive the table directly from the source)
    if os.path.exists(DECODER_FILE):
        print(f"[+] Decoder file       : {DECODER_FILE}  (present — table re-derived from source)")
    else:
        print(f"[~] Decoder file       : not found (not required — table derived from source)")

    # Build table
    table = build_table(source)

    # Discover aliases
    alias_names = find_alias_names(source)

    # Replace
    deobfuscated, count = deobfuscate(source, table, alias_names)
    print(f"[+] Replacements made  : {count:,}")

    # Write output
    header = (
        f"// gcaptcha4_deobfuscated.js\n"
        f"// Generated by deobfuscate.py\n"
        f"// Canonical decoder anchor: {DECODER_CANONICAL}\n"
        f"// Replacements: {count:,}  |  Table entries: {len(table):,}\n\n"
    )
    with open(OUTPUT_FILE, "w", encoding="utf-8") as fh:
        fh.write(header + deobfuscated)

    out_size = os.path.getsize(OUTPUT_FILE)
    print(f"[+] Written            : {OUTPUT_FILE}  ({out_size:,} bytes)")
    print("=" * 60)
    print("Done.")


if __name__ == "__main__":
    main()
