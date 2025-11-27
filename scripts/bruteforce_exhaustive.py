#!/usr/bin/env python3
"""
Exhaustive brute-force helper for vaultdb XOR-obfuscated databases.
Generates candidate keys within a length range and charset presets.
For testing and educational use only.
"""

import argparse
import itertools
import multiprocessing as mp
import string
import sys
from pathlib import Path

EXPECTED_HEADER = b"id,description,user,password,url,comment,tags,createdate,updatedate,status"


def build_charset(preset: str, custom_special: str | None) -> str:
    specials_default = ";.,#-_%&$+'"
    specials = custom_special if custom_special is not None else specials_default
    match preset:
        case "digits":
            return string.digits
        case "letters":
            return string.ascii_letters
        case "alnum":
            return string.ascii_letters + string.digits
        case "special":
            return specials
        case "digits-special":
            return string.digits + specials
        case "letters-special":
            return string.ascii_letters + specials
        case "alnum-special":
            return string.ascii_letters + string.digits + specials
    raise ValueError(f"Unknown charset preset: {preset}")


def header_matches(cipher_prefix: bytes, key: bytes) -> bool:
    key_len = len(key)
    if key_len == 0:
        return False
    for i, c in enumerate(cipher_prefix):
        plain = c ^ key[i % key_len]
        if plain != EXPECTED_HEADER[i]:
            return False
    return True


def worker(
    worker_id: int,
    workers: int,
    cipher_prefix: bytes,
    lengths: range,
    charset: str,
    stop: mp.Event,
    found_queue: mp.Queue,
) -> None:
    for length in lengths:
        products = itertools.product(charset, repeat=length)
        for idx, combo in enumerate(products):
            if stop.is_set():
                return
            if idx % workers != worker_id:
                continue
            candidate_str = "".join(combo)
            candidate_bytes = candidate_str.encode("utf-8", "ignore")
            if header_matches(cipher_prefix, candidate_bytes):
                found_queue.put(candidate_str)
                stop.set()
                return


def main() -> int:
    parser = argparse.ArgumentParser(description="Exhaustive brute-force vaultdb master password (testing only).")
    parser.add_argument("--db", default="~/.vault.db", help="Path to vault database (default: ~/.vault.db)")
    parser.add_argument("--min-len", type=int, required=True, help="Minimum key length to try")
    parser.add_argument("--max-len", type=int, required=True, help="Maximum key length to try")
    parser.add_argument(
        "--charset",
        choices=[
            "digits",
            "letters",
            "alnum",
            "special",
            "digits-special",
            "letters-special",
            "alnum-special",
        ],
        default="alnum",
        help="Character set preset to use",
    )
    parser.add_argument(
        "--special",
        help="Override special characters for presets including specials (e.g. \"~!@#%$\")",
    )
    parser.add_argument("--workers", type=int, default=mp.cpu_count(), help="Number of parallel workers")
    args = parser.parse_args()

    if args.min_len <= 0 or args.max_len < args.min_len:
        print("Invalid length range.", file=sys.stderr)
        return 1

    db_path = Path(args.db).expanduser()
    if not db_path.exists():
        print(f"Database not found: {db_path}", file=sys.stderr)
        return 1

    charset = build_charset(args.charset, args.special)
    cipher = db_path.read_bytes()
    if len(cipher) < len(EXPECTED_HEADER):
        print("Ciphertext shorter than expected header; aborting.", file=sys.stderr)
        return 1
    cipher_prefix = cipher[: len(EXPECTED_HEADER)]

    lengths = range(args.min_len, args.max_len + 1)
    stop = mp.Event()
    found_queue: mp.Queue[str] = mp.Queue()
    workers = max(1, args.workers)

    procs = [
        mp.Process(
            target=worker,
            args=(i, workers, cipher_prefix, lengths, charset, stop, found_queue),
            daemon=True,
        )
        for i in range(workers)
    ]

    for p in procs:
        p.start()

    found: str | None = None
    try:
        while any(p.is_alive() for p in procs):
            try:
                found = found_queue.get(timeout=0.5)
                stop.set()
                break
            except Exception:
                continue
    finally:
        stop.set()
        for p in procs:
            p.join()

    if found:
        print(f"Possible master password: {found}")
        return 0

    print("No matching key found in searched space.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
