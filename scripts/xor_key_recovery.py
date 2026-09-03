#!/usr/bin/env python3
"""
xor_key_recovery.py

Recover a repeating-key XOR key from ciphertext using a known-plaintext
crib (a substring you know exists somewhere in the decrypted data).

Typical use case: you've extracted an encrypted blob (config file, string
table, embedded resource) from a binary, and you know or can guess a
fragment of the plaintext (e.g. a magic header, a known field name, or a
predictable value). This script XORs the crib against the ciphertext at
every possible offset to recover key bytes, then assembles the full key
from repeated key-length candidates.

Usage:
    python3 xor_key_recovery.py --file blob.bin --crib "known_plaintext"
    python3 xor_key_recovery.py --file blob.bin --crib "known_plaintext" --key-length 16
    python3 xor_key_recovery.py --hex "1b2c3d..." --crib "known_plaintext"

If --key-length is omitted, the script tries every offset in the
ciphertext and reports candidate keys of increasing length, letting you
pick the one that repeats cleanly (a strong signal you've found the
correct key length).
"""

import argparse
import sys
from itertools import cycle, islice


def xor_bytes(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ k for b, k in zip(data, cycle(key)))


def recover_key_at_offset(ciphertext: bytes, crib: bytes, offset: int) -> bytes:
    """XOR the crib against the ciphertext starting at `offset` to recover
    that many key bytes (aligned to the crib's position in the plaintext)."""
    segment = ciphertext[offset:offset + len(crib)]
    if len(segment) != len(crib):
        return b""
    return xor_bytes(segment, crib)


def find_repeating_period(key_material: bytes, max_period: int) -> int | None:
    """Given a run of recovered key bytes, check whether it looks like a
    short repeating key by testing candidate periods."""
    for period in range(1, min(max_period, len(key_material)) + 1):
        candidate = key_material[:period]
        rebuilt = bytes(islice(cycle(candidate), len(key_material)))
        if rebuilt == key_material:
            return period
    return None


def scan_all_offsets(ciphertext: bytes, crib: bytes, max_key_len: int):
    """Slide the crib across the whole ciphertext. At each offset, recover
    the key-bytes-at-that-position and check if they repeat with a short
    period -- a repeating period is strong evidence of the real key."""
    results = []
    for offset in range(0, max(1, len(ciphertext) - len(crib) + 1)):
        recovered = recover_key_at_offset(ciphertext, crib, offset)
        if not recovered:
            continue
        period = find_repeating_period(recovered, max_key_len)
        if period:
            key = recovered[:period]
            results.append((offset, key))
    return results


def main():
    parser = argparse.ArgumentParser(
        description="Recover a repeating-key XOR key via known-plaintext crib."
    )
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--file", help="Path to file containing the ciphertext")
    src.add_argument("--hex", help="Ciphertext as a hex string")

    parser.add_argument(
        "--crib", required=True,
        help="Known plaintext fragment expected somewhere in the decrypted data"
    )
    parser.add_argument(
        "--key-length", type=int, default=None,
        help="If you already know the key length, recover it directly "
             "(crib must be placed at the correct offset with --offset)"
    )
    parser.add_argument(
        "--offset", type=int, default=0,
        help="Byte offset of the crib within the ciphertext (used with --key-length)"
    )
    parser.add_argument(
        "--max-key-len", type=int, default=64,
        help="Upper bound on key length to test when scanning (default: 64)"
    )
    parser.add_argument(
        "--decrypt-with", default=None,
        help="Hex-encoded key: skip recovery and just decrypt --file/--hex with this key"
    )

    args = parser.parse_args()

    if args.file:
        with open(args.file, "rb") as f:
            ciphertext = f.read()
    else:
        ciphertext = bytes.fromhex(args.hex.strip())

    crib = args.crib.encode()

    if args.decrypt_with:
        key = bytes.fromhex(args.decrypt_with)
        plaintext = xor_bytes(ciphertext, key)
        sys.stdout.buffer.write(plaintext)
        return

    if args.key_length:
        recovered = recover_key_at_offset(ciphertext, crib, args.offset)
        if len(recovered) < args.key_length:
            print(f"[!] Crib too short to recover a {args.key_length}-byte key "
                  f"at this offset; provide a longer crib.", file=sys.stderr)
            sys.exit(1)
        key = recovered[:args.key_length]
        print(f"[+] Candidate key (hex): {key.hex()}")
        print(f"[+] Candidate key (raw): {key!r}")
        preview = xor_bytes(ciphertext, key)[:120]
        print(f"[+] Decryption preview: {preview!r}")
        return

    print("[*] No key length given -- scanning all offsets for a repeating key...")
    results = scan_all_offsets(ciphertext, crib, args.max_key_len)

    if not results:
        print("[!] No repeating key pattern found. Try a different/longer crib, "
              "or supply --key-length if you know it.", file=sys.stderr)
        sys.exit(1)

    seen = set()
    for offset, key in sorted(results, key=lambda r: len(r[1])):
        if key in seen:
            continue
        seen.add(key)
        preview = xor_bytes(ciphertext, key)[:80]
        print(f"[+] offset={offset:<6} key_len={len(key):<3} "
              f"key_hex={key.hex():<40} preview={preview!r}")

    print("\n[*] Inspect the previews above -- the correct key produces "
          "readable plaintext across the whole blob, not just at the crib.")


if __name__ == "__main__":
    main()
