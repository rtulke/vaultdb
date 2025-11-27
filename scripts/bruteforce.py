#!/usr/bin/env python3
"""
Brute-force helpers for vaultdb XOR-obfuscated databases.
Supports wordlist-based and exhaustive generation modes.
For testing and educational use only.
"""

import argparse
import itertools
import multiprocessing as mp
import string
import sys
import time
from pathlib import Path
from typing import Optional

EXPECTED_HEADER = b"id,description,user,password,url,comment,tags,createdate,updatedate,status"


def header_matches(cipher_prefix: bytes, key: bytes) -> bool:
    key_len = len(key)
    if key_len == 0:
        return False
    for i, c in enumerate(cipher_prefix):
        plain = c ^ key[i % key_len]
        if plain != EXPECTED_HEADER[i]:
            return False
    return True


def brute_force_wordlist(db_path: Path, wordlist_path: Path) -> Optional[str]:
    cipher = db_path.read_bytes()
    prefix = cipher[: len(EXPECTED_HEADER)]
    with wordlist_path.open("rb") as wl:
        for idx, line in enumerate(wl, 1):
            candidate = line.rstrip(b"\r\n")
            if not candidate:
                continue
            if header_matches(prefix, candidate):
                return candidate.decode("utf-8", errors="replace")
            if idx % 100000 == 0:
                print(f"Checked {idx} candidates...", file=sys.stderr)
    return None


def build_charset(preset: str, custom_special: Optional[str], custom_chars: Optional[str] = None) -> str:
    specials_default = ";.,#-_%&$+'"
    specials = custom_special if custom_special is not None else specials_default
    if preset == "digits":
        return string.digits
    if preset == "letters":
        return string.ascii_letters
    if preset == "alnum":
        return string.ascii_letters + string.digits
    if preset == "special":
        return specials
    if preset == "digits-special":
        return string.digits + specials
    if preset == "letters-special":
        return string.ascii_letters + specials
    if preset == "alnum-special":
        return string.ascii_letters + string.digits + specials
    if preset == "common-special":
        return string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{};:'\",.<>/?`~"
    if preset == "custom":
        if not custom_chars:
            raise ValueError("Custom charset requires --chars")
        return custom_chars
    raise ValueError(f"Unknown charset preset: {preset}")


def exhaustive_worker(
    worker_id: int,
    workers: int,
    cipher_prefix: bytes,
    lengths: range,
    charset: str,
    stop: mp.Event,
    found_queue: mp.Queue,
    attempts: mp.Value,
    max_tries: Optional[int],
    time_limit: Optional[float],
    started: float,
    max_matches: int,
) -> None:
    chars = list(charset)
    subset = chars[worker_id::workers] or chars
    batch = 0
    for length in lengths:
        if stop.is_set():
            return
        if length == 1:
            products = ((c,) for c in subset)
        else:
            products = ((c,) + tail for c in subset for tail in itertools.product(chars, repeat=length - 1))
        for combo in products:
            if stop.is_set():
                return
            candidate_str = "".join(combo)
            candidate_bytes = candidate_str.encode("utf-8", "ignore")
            if header_matches(cipher_prefix, candidate_bytes):
                found_queue.put(candidate_str)
                stop.set()
                return
            batch += 1
            if batch >= 1000:
                with attempts.get_lock():
                    attempts.value += batch
                    current_attempts = attempts.value
                batch = 0
                if max_tries and current_attempts >= max_tries:
                    stop.set()
                    return
                if time_limit and (time.monotonic() - started) >= time_limit:
                    stop.set()
                    return
    if batch:
        with attempts.get_lock():
            attempts.value += batch


def brute_force_exhaustive(
    db_path: Path,
    min_len: int,
    max_len: int,
    charset: str,
    workers: int,
    custom_special: Optional[str],
) -> Optional[str]:
    cipher = db_path.read_bytes()
    if len(cipher) < len(EXPECTED_HEADER):
        return None
    prefix = cipher[: len(EXPECTED_HEADER)]
    lengths = range(min_len, max_len + 1)
    charset_str = build_charset(charset, custom_special)
    stop = mp.Event()
    found_queue: mp.Queue[str] = mp.Queue()
    worker_count = max(1, workers)

    procs = [
        mp.Process(
            target=exhaustive_worker,
            args=(i, worker_count, prefix, lengths, charset_str, stop, found_queue),
            daemon=True,
        )
        for i in range(worker_count)
    ]
    for p in procs:
        p.start()

    found: Optional[str] = None
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
    return found


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Brute-force vaultdb master password (testing only).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    sub = parser.add_subparsers(dest="mode", required=True)
    subparsers = {}

    p_wordlist = sub.add_parser(
        "wordlist",
        help="Try passwords from a wordlist file",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    subparsers["wordlist"] = p_wordlist
    p_wordlist.add_argument("--db", default="~/.vault.db", help="Path to vault database")
    p_wordlist.add_argument("--wordlist", required=True, help="Path to wordlist file (one password per line)")
    p_wordlist.add_argument("--max-tries", type=int, help="Abort after this many candidates")
    p_wordlist.add_argument("--time-limit", type=float, help="Abort after this many seconds")
    p_wordlist.add_argument("--progress-every", type=int, default=100000, help="Print status every N candidates")
    p_wordlist.add_argument("--max-matches", type=int, default=1, help="Stop after finding this many matches")
    p_wordlist.add_argument("--quiet", action="store_true", help="Suppress progress output")

    p_exhaust = sub.add_parser(
        "exhaustive",
        help="Generate and try all combinations in a length range",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    subparsers["exhaustive"] = p_exhaust
    p_exhaust.add_argument("--db", default="~/.vault.db", help="Path to vault database")
    p_exhaust.add_argument("--min-len", type=int, required=True, help="Minimum key length to try")
    p_exhaust.add_argument("--max-len", type=int, required=True, help="Maximum key length to try")
    p_exhaust.add_argument(
        "--charset",
        choices=[
            "digits",
            "letters",
            "alnum",
            "special",
            "digits-special",
            "letters-special",
            "alnum-special",
            "common-special",
            "custom",
        ],
        default="alnum",
        help="Character set preset to use",
    )
    p_exhaust.add_argument(
        "--special",
        help="Override special characters for presets that include specials (e.g. \"~!@#$%%^&\")",
    )
    p_exhaust.add_argument(
        "--workers",
        type=int,
        help="Number of parallel workers (default: detected CPU cores)",
    )
    p_exhaust.add_argument(
        "--chars",
        help="Custom character set when using --charset custom",
    )
    p_exhaust.add_argument("--max-tries", type=int, help="Abort after this many candidates")
    p_exhaust.add_argument("--time-limit", type=float, help="Abort after this many seconds")
    p_exhaust.add_argument("--progress-every", type=int, default=50000, help="Print status every N candidates")
    p_exhaust.add_argument("--max-matches", type=int, default=1, help="Stop after finding this many matches")
    p_exhaust.add_argument("--quiet", action="store_true", help="Suppress progress output")

    # If only top-level help was requested, show detailed help for subcommands too.
    if len(sys.argv) == 1 or "-h" in sys.argv or "--help" in sys.argv:
        parser.print_help()
        print("\nSubcommand details:\n")
        for name, sp in subparsers.items():
            print(sp.format_help())
        return 0

    args = parser.parse_args()

    db_path = Path(args.db).expanduser()
    if not db_path.exists():
        print(f"Database not found: {db_path}", file=sys.stderr)
        return 1

    if args.mode == "wordlist":
        wl_path = Path(args.wordlist).expanduser()
        if not wl_path.exists():
            print(f"Wordlist not found: {wl_path}", file=sys.stderr)
            return 1
        print(f"Brute-forcing {db_path} with {wl_path} (wordlist; testing only)...")
        cipher = db_path.read_bytes()
        prefix = cipher[: len(EXPECTED_HEADER)]
        attempts = 0
        found = []
        start = time.monotonic()
        with wl_path.open("rb") as wl:
            for idx, line in enumerate(wl, 1):
                candidate = line.rstrip(b"\r\n")
                if not candidate:
                    continue
                attempts += 1
                if args.max_tries and attempts > args.max_tries:
                    print("Reached max tries; stopping.", file=sys.stderr)
                    break
                if args.time_limit and (time.monotonic() - start) >= args.time_limit:
                    print("Reached time limit; stopping.", file=sys.stderr)
                    break
                if header_matches(prefix, candidate):
                    found.append(candidate.decode("utf-8", errors="replace"))
                    if len(found) >= args.max_matches:
                        break
                if not args.quiet and attempts % args.progress_every == 0:
                    elapsed = time.monotonic() - start
                    rate = attempts / elapsed if elapsed > 0 else 0
                    print(f"Checked {attempts} candidates | {rate:.1f} attempts/sec", file=sys.stderr)
    else:
        if args.min_len <= 0 or args.max_len < args.min_len:
            print("Invalid length range.", file=sys.stderr)
            return 1
        workers = args.workers if args.workers is not None else mp.cpu_count() or 1
        workers = max(1, workers)
        print(
            f"Brute-forcing {db_path} exhaustively (len {args.min_len}-{args.max_len}, charset {args.charset}, "
            f"workers {workers}; testing only)..."
        )
        cipher = db_path.read_bytes()
        if len(cipher) < len(EXPECTED_HEADER):
            print("Ciphertext shorter than header; aborting.", file=sys.stderr)
            return 1
        prefix = cipher[: len(EXPECTED_HEADER)]
        charset = build_charset(args.charset, args.special, args.chars)
        lengths = range(args.min_len, args.max_len + 1)
        stop = mp.Event()
        found_queue: mp.Queue[str] = mp.Queue()
        attempts = mp.Value("L", 0)
        start = time.monotonic()
        procs = [
            mp.Process(
                target=exhaustive_worker,
                args=(
                    i,
                    workers,
                    prefix,
                    lengths,
                    charset,
                    stop,
                    found_queue,
                    attempts,
                    args.max_tries,
                    args.time_limit,
                    start,
                    args.max_matches,
                ),
                daemon=True,
            )
            for i in range(workers)
        ]
        for p in procs:
            p.start()

        found = []
        last_progress = start
        try:
            while any(p.is_alive() for p in procs):
                if not found_queue.empty():
                    try:
                        candidate = found_queue.get_nowait()
                        found.append(candidate)
                        if len(found) >= args.max_matches:
                            stop.set()
                            break
                    except Exception:
                        pass
                if args.time_limit and (time.monotonic() - start) >= args.time_limit:
                    stop.set()
                    print("Reached time limit; stopping.", file=sys.stderr)
                    break
                if args.max_tries and attempts.value >= args.max_tries:
                    stop.set()
                    print("Reached max tries; stopping.", file=sys.stderr)
                    break
                if not args.quiet and (attempts.value >= args.progress_every and (time.monotonic() - last_progress) >= 1):
                    elapsed = time.monotonic() - start
                    rate = attempts.value / elapsed if elapsed > 0 else 0
                    print(f"Checked {attempts.value} candidates | {rate:.1f} attempts/sec", file=sys.stderr)
                    last_progress = time.monotonic()
                time.sleep(0.1)
        finally:
            stop.set()
            for p in procs:
                p.join()

    if not found:
        print("No matching key found.")
        return 2
    for f in found:
        print(f"Possible master password: {f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
