# vaultdb

Simple terminal-based password vault built with ncurses. It stores entries in a CSV-like file that is lightly obfuscated. Intended for learning and experimentation, **not** for protecting real secrets.


login                                  |  help
:-------------------------------------:|:-----------------------------------:
![vaultdb login](demo/login.png)       | ![vaultdb help](demo/help.png) 
show all                               | show id
![vaultdb show_all](demo/show_all.png) | ![vaultdb show_id](demo/show_id.png)    


## Platform Support
- Built and run on macOS (Darwin, ncurses).
- Expected to work on Linux and BSD variants with a C11 compiler and `ncurses` installed.
- Windows support is not verified; use WSL or a curses layer such as PDCurses/WinLibc if attempting a native build.

## Security Notice
- Data is only XOR-obfuscated with the master password; this is not cryptographically secure.
- Use the program for testing and practice only; do not store sensitive credentials.
- The master password gates access but should be considered easily brute-forced if the DB is obtained.

**How XOR obfuscation works (toy example):**
Let `P` be a plaintext byte and `K` the matching byte of the key. The stored byte is `C = P ⊕ K`. To read, compute `P = C ⊕ K`. Example: `P = 0x41 ('A')`, `K = 0x2B`, then `C = 0x41 ⊕ 0x2B = 0x6A`; recovering: `0x6A ⊕ 0x2B = 0x41`.

## Installation
Prerequisites: C11-compatible compiler and `ncurses` development headers.

Clone from GitHub
```sh
# Prepare the dev directory, change it if it differs from yours ;-):
mkdir ~/dev/
cd ~/dev/
git clone https://github.com/rtulke/vaultdb.git
```
Build locally:
```sh
make
```

Install the binary (defaults to `/usr/bin/vault`, override with `BINDIR=/custom/bin`):
```sh
make install
```

Uninstall (prompts before deleting the database):
```sh
make uninstall
```
## Installation System-wide
Prerequisites: C11-compatible compiler and `ncurses` development headers and sudo.

Clone from GitHub
```sh
# Prepare the dev directory, change it if it differs from yours ;-):
mkdir ~/dev/
cd ~/dev/
git clone https://github.com/rtulke/vaultdb.git
```
Build locally:
```sh
make
```

Install the binary (defaults to `/usr/bin/vault`, override with `BINDIR=/custom/bin`):
```sh
sudo make install
```

Uninstall (prompts before deleting the database):
```sh
sudo make uninstall
```

### Root vs. regular user
- Running as root stores the database at `/var/lib/vaultdb/vault.db` and the log at `/var/log/vault.log`.
- Running as a regular user stores the database at `~/.vault.db` and the log at `~/.vault.log`.

## What the tool does
Interactive vault for keeping test credentials: add, view, edit, delete entries with fields such as description, user, password, URL, tags, dates, and status. Provides a basic wizard, command logging, and tab completion in the TUI.

## Commands
| Command | Description |
| :--- | :--- |
| `help` | Show available commands. |
| `show all` | List all entries in a table. |
| `show tag <t1> [t2...]` | List entries matching any of the given tags. |
| `show <id>` | Show details for entry by ID. |
| `show user <name>` | List entries for a user. |
| `show url <url>` | List entries whose URL contains the value. |
| `show date <dd.mm.yyyy>` | List entries created or updated on that date (prefix match). |
| `show status <value>` | List entries with a given status. |
| `show find <t1> [t2...]` | Search terms across description/user/url/tags/comment/status (all terms must match). |
| `add pw` | Add a new entry via wizard. |
| `change <id>` | Edit an entry via wizard. |
| `change pw <user>` | Replace all passwords for a user (optionally generate). |
| `change master-pw` | Set a new master password. |
| `rm pw <id1> [id2...]` | Delete entries by ID after confirmation. |
| `copy <id>` | Copy password to clipboard (auto-clears after 10s). |
| `lock` | Save, lock the vault, and require master password to unlock. |
| `history` | Show command history log. |
| `history clear` | Clear command history log. |
| `clear` | Clear the screen. |
| `version` | Show version/author info. |
| `quit` / `exit` / `q` | Save and exit. |

### Keyboard shortcuts
| Shortcut | Action |
| :--- | :--- |
| `Ctrl+C` | Cancel current input (does not exit the app). |
| `Ctrl+D` | End input (prompts return empty/exit current prompt). |
| `Ctrl+A` | Move cursor to start of line. |
| `Ctrl+E` | Move cursor to end of line. |
| `Ctrl+K` | Delete from cursor to end of line. |
| `Ctrl+U` | Delete from start of line to cursor. |
| `Ctrl+W` | Delete previous word. |
| `Ctrl+L` | Clear screen and redraw prompt. |
| `Arrow Up/Down` | Browse session command history and recall previous inputs. |
| `Tab` / double `Tab` | Trigger command completion and show suggestions. |

## Features
- ncurses TUI with colorized header/body and centered dialogs.
- Auto-lock after 5 minutes of inactivity.
- Tab completion for commands, IDs, users, tags, and statuses.
- Cross-field search via `show find` (description/user/url/tags/comment/status).
- Copy password to clipboard for 10s via `copy <id>` (pbcopy/xclip/xsel/wl-copy/clip).
- Passwords are masked in table views; view details or copy to clipboard to reveal.
- Obfuscated CSV database persisted to `~/.vault.db` (or system locations when root).
- Command history logging to `~/.vault.log`.
- Action logging with timestamps for add/change/delete/password ops and lock/unlock events.
- Wizard-driven entry creation and edits, including optional password generation.

## TODO / Ideas
- Strong encryption: replace XOR with AES-GCM plus Argon2id/PBKDF2 key derivation and auth tag checks.
- Export/Import: CSV/JSON export/import; optional encrypted export; warn on plaintext exports.
- Master password policies: length/complexity checks and weak-password warnings.
- Backups: automatic, encrypted rolling backups on save.
- Advanced search: fuzzy matching, combined filters (tag+user+status), sortable lists.
- Clipboard options: configurable timeout; copy user/URL/OTP if present.
- Config file/flags: defaults for DB path, auto-lock, clipboard timeout, colors, readonly mode.
- Entry extras: TOTP field and generator, expiry/reminder field, favorites, templates (web/API/SSH).
- Audit toggles: allow disabling or reducing log verbosity.
- Tests: automated tests for parsing/save/load/encryption and basic TUI flows; fuzz CSV parser.
## Brute-force testing helpers
Purpose-built for demonstrations to highlight the weak XOR obfuscation. Do not use for unauthorized access.

### Wordlist mode

Reads candidates from the wordlist until the CSV header decrypts.
```sh
python3 scripts/bruteforce.py wordlist --db ~/.vault.db --wordlist /path/to/wordlist.txt
```

### Exhaustive mode

```sh
python3 scripts/bruteforce.py exhaustive --db ~/.vault.db --min-len 4 --max-len 6 --charset alnum-special --special "%$#-+." --workers 4
```
Enumerates every combination in the length range using charset presets:
 - `digits`, `letters`, `alnum`, `special`, `digits-special`, `letters-special`, `alnum-special`
 - `--special` overrides the special-character set for presets that include specials.
- `--workers` sets parallel processes (default: detected CPU cores). Note that search space grows exponentially with length; keep ranges small for tests.
- Common special-character sets in real-world passwords often include symbols like `!@#$%^&*()-_=+[]{};:'",.<>/?\`~`. Use `--special` to reflect the set you want to test.

### Parameter reference (bruteforce.py)

| Parameter | Subcommand | Description |
| :--- | :--- | :--- |
| `--db PATH` | both | Path to database (default: `~/.vault.db`). |
| `--wordlist PATH` | wordlist | Wordlist file, one candidate per line (required). |
| `--min-len N` / `--max-len N` | exhaustive | Minimum / maximum key length (required). |
| `--charset {digits,letters,alnum,special,digits-special,letters-special,alnum-special,common-special,custom}` | exhaustive | Charset preset for generator. |
| `--special CHARS` | exhaustive | Override special characters for presets that include specials (`special`, `digits-special`, `letters-special`, `alnum-special`, `common-special`); default specials: `!@#$%^&*()-_=+[]{};:'",.<>/?\`~`. |
| `--chars CHARS` | exhaustive | Custom charset when using `--charset custom`. |
| `--workers N` | exhaustive | Parallel processes (default: detected CPU cores if omitted; e.g., `--workers 4` forces 4 workers even if more cores are available). |
| `--max-tries N` | both | Abort after N candidates. |
| `--time-limit SECONDS` | both | Abort after N seconds. |
| `--progress-every N` | both | Print progress every N attempts (defaults: 100000 wordlist, 50000 exhaustive). |
| `--max-matches N` | both | Stop after N matches (default: 1). |
| `--quiet` | both | Suppress progress output. |
| Charset presets | exhaustive | Available presets: `digits`, `letters`, `alnum`, `special`, `digits-special`, `letters-special`, `alnum-special`, `common-special`, `custom` (`--chars` required). |

Example runs:

On an Apple M4 MacBook Pro (10 performance/efficiency cores visible), omitting `--workers` uses all detected cores. Specifying `--workers N` caps parallelism (e.g., `--workers 4` uses 4 workers even if 10 are available).

```sh
# Minimal wordlist run with default DB — runtime depends on list size; a few million entries finish in seconds.
python3 scripts/bruteforce.py wordlist --wordlist /tmp/rockyou.txt
```

```sh
# Wordlist run with caps and quieter progress — 500k tries cap stays well under 10s at tens of millions checks/sec.
python3 scripts/bruteforce.py wordlist --db ~/.vault.db --wordlist ./small.txt --max-tries 500000 --time-limit 10 --progress-every 20000
```

```sh
# Stop after first two matches from wordlist — duration depends on where matches appear.
python3 scripts/bruteforce.py wordlist --wordlist ./candidates.txt --max-matches 2
```

```sh
# Exhaustive: digits only, 4–6 chars, 4 workers — ~1.1 million combos; sub-second at ~50M+ checks/sec.
python3 scripts/bruteforce.py exhaustive --min-len 4 --max-len 6 --charset digits --workers 4
```

```sh
# Exhaustive: alnum+special with custom specials, 4–5 chars, 6 workers — ~85 billion combos; hours to a day+ if fully searched (use limits).
python3 scripts/bruteforce.py exhaustive --min-len 4 --max-len 5 --charset alnum-special --special "%$#-+." --time-limit 15 --workers 6
```

```sh
# Exhaustive: common-special preset, length 4, stop after 100k — full space ~14 billion combos; capped run completes quickly, full run would take minutes to hours.
python3 scripts/bruteforce.py exhaustive --min-len 4 --max-len 4 --charset common-special --max-tries 100000
```

```sh
# Exhaustive: custom charset, very small space — 7^3=343 combos; instant.
python3 scripts/bruteforce.py exhaustive --min-len 3 --max-len 3 --charset custom --chars "abc123!" --progress-every 5000
```

```sh
# Exhaustive: run quietly (no progress logs) — letters len 4 => 26^4≈456k combos; sub-second to a couple seconds.
python3 scripts/bruteforce.py exhaustive --min-len 4 --max-len 4 --charset letters --quiet
```

```sh
# Exhaustive: common-special, len 4–8, auto-workers (~10 on an M4) — search space ~5×10^15 combos; even at ~100M/s aggregate this would take ~1.6 years, so use smaller ranges or wordlists instead.
python3 scripts/bruteforce.py exhaustive --min-len 4 --max-len 8 --charset common-special
```

### Wordlist sources for testing
Use only for legal testing/education; these lists can be very large.
- https://github.com/danielmiessler/SecLists (Passwords/Leaked-Databases, Passwords/Common-Credentials)
- https://github.com/berzerk0/Probable-Wordlists
- https://github.com/jeanphorn/wordlist
- https://github.com/kkrypt0nn/Wordlists
- https://github.com/kaonashi-passwords/Kaonashi
- https://crackstation.net/crackstation-human-only.txt.gz
- https://download.weakpass.com/wordlists/ (multiple mega/gigabyte dumps)
- https://haveibeenpwned.com/Passwords (Pwned Passwords download/API; SHA-1 hashes)
- https://github.com/PrinceDhaliwal/WordList-Collection
- https://https://github.com/topics/wordlist (GitHub Collection with Tags "wordlist")
- https://github.com/insidetrust/statistically-likely-usernames (usernames, sometimes paired with small password sets)
