# qq-nt-export

English | [简体中文](README.md)

**NTQQ (QQ 9.x / QQNT) local chat history decryption & export tool for Windows** — purely external and read-only: extracts the SQLCipher key via memory scanning, decrypts the message database, and exports readable TXT plus structured JSON. No DLL injection, no hooking, no modification of any QQ files.

> ⚠️ **For learning, research, and personal data backup only.** Do NOT use it to access other people's chat history. Any legal liability arising from misuse belongs to the user.

---

## Features

- **Key extraction**: externally scans QQ process memory (read-only) for the credential pattern, cross-validates against the salt stored in the target database file header (prevents picking up credentials of the wrong database). One scan recovers credentials for **every database** under `nt_db`.
- **Database decryption**: handles NTQQ's 1024-byte custom header + SQLCipher (`cipher_page_size=4096`, `kdf_iter=4000`, `HMAC_SHA1`, `PBKDF2-HMAC-SHA512`); probes multiple key variants and remembers the working one; produces a standard plaintext SQLite via `sqlcipher_export` with full `integrity_check`.
- **Auxiliary-database nickname backfill**: optionally decrypts `group_info.db` (group members / cards / group names) and `profile_info.db` (friend nicknames) to replace raw uids / bare QQ numbers with readable names.
- **Full or targeted export**: export every session, or select sessions by **QQ number / group number / uid** (multiple values allowed).
- **Readable file naming**: output files are named `name_QQnumber` (groups: `groupName_groupNumber`, direct chats: `nickname_peerQQ`), with Chinese and emoji preserved; duplicates get an automatic `(2)`, `(3)`... suffix.
- **Message parsing**: built-in minimal Protobuf wire decoder (no protobuf dependency) covering text / image / video / file / reply / forward / contact card / call / rich-text mixed messages; unknown types degrade gracefully instead of aborting.
- **Engineering trio**: `selftest.py` (fast + deep self-check, exit code = number of failures), pitfalls log, and changelog for quick diagnosis when the environment changes.

## How It Works

```
QQ.exe process memory ──(read-only scan)──► key + salt (salt cross-checked with file header)
                                                │
nt_msg.db (+wal) ──backup──► strip 1024-byte custom header ──► SQLCipher decrypt (variant probing)
                                                │
                                 sqlcipher_export → plaintext SQLite (integrity_check=ok)
                                                │
group_info.db / profile_info.db ─┴─► parse & export ──► json/*.json + txt/*.txt + sessions_index.json
```

Key facts verified on QQ 9.9.35 (may change with updates):

1. `nt_msg.db` has a **1024-byte non-standard header** before the SQLCipher data area, which must be stripped first;
2. While logged in, credentials live in the QQ main process memory as `x'<64-hex key><32-hex salt>'`;
3. The working key variant is **raw 32-byte hex + salt concatenated**, and `cipher_hmac_algorithm = HMAC_SHA1` must be set explicitly (the default SHA512 fails);
4. Message tables are `c2c_msg_table` / `group_msg_table` with numeric column names (`40001`=msg_id, `40050`=timestamp, `40800`=protobuf body, etc.);
5. The newest messages may still sit un-checkpointed in `-wal` — **always back up the `-wal` together with the main db**.

## Requirements

- Windows 10/11 (Win32 API memory scanning)
- Python 3.10+ (tested on 3.13)
- Dependencies: `sqlcipher3-wheels`, `pycryptodome`, `zstandard`
- QQ (NTQQ) logged in and running (needed for key scanning only; decryption/export work on copies)

```bash
pip install sqlcipher3-wheels pycryptodome zstandard
```

> If `pip` fails to install `sqlcipher3-wheels` due to network issues, download the matching `.whl` directly from a mirror index page and install locally.

## Quick Start

1. Copy `config.example.json` to `config.json` and fill in the database path (key/salt can stay empty);
2. Run the pipeline:

```bash
# 0) Extract the key (QQ must be logged in and running; config.json is updated automatically)
python scripts/ntqq_key_scan.py

# 1) Decrypt the main database (source is read-only; artifacts go to work_dir)
python scripts/ntqq_decrypt.py

# 1.5) (recommended) Decrypt auxiliary databases for better nickname/group-name coverage
python scripts/ntqq_aux_decrypt.py

# 2) Export all sessions
python scripts/ntqq_export.py

# 3) Verify the export
python scripts/ntqq_verify.py

# 4) Self-check
python selftest.py            # fast
python selftest.py --deep     # includes plaintext DB & export artifacts
```

### Targeted export

```bash
python scripts/ntqq_export.py --only 123456789             # direct chat: peer QQ number
python scripts/ntqq_export.py --only 987654321             # group: group number
python scripts/ntqq_export.py --only 987654321 123456789   # multiple, mixed
```

- Numbers are auto-resolved to group numbers and/or peer QQ numbers (if both match, both are exported); `u_`-prefixed values are treated as direct-chat uids;
- Without an explicit output directory, results go to `output/filter_<criteria>/` and never overwrite the full export;
- If nothing matches, the tool errors out with exit code 1 and produces no partial artifacts.

## Output Layout

```
output/
├─ json/                          # structured messages (one file per session)
│   ├─ groupName_groupNumber.json
│   └─ nickname_peerQQ.json
├─ txt/                           # readable transcripts (one file per session)
├─ sessions_index.json            # session list: counts / time range / filename mapping / backfill stats
├─ verify_report.json             # verification report
└─ nt_msg_plain_schema.sql        # plaintext DB schema snapshot
```

- Each message carries `msg_id / time / direction / sender_uid / sender_qq / sender_name (with backfill source sender_name_src) / msg_type / content_type / text / content`;
- `content` is a unified structure: `text / image / video / file / reply / forward / contact / call / mixed / ...`; media entries include filename, size, md5, etc. (metadata only — media files are not downloaded);
- Sample message:

```json
{
  "msg_id": 7637455716438164227,
  "time": "2026-05-08 17:14:26",
  "direction": 0,
  "sender_name": "Someone",
  "sender_name_src": "member_nick",
  "content_type": "text",
  "text": "hello",
  "content": {"type": "text", "text": "hello"}
}
```

## Configuration (config.json)

| Field | Description |
|---|---|
| `db_path` / `db_path_candidates` | Path candidates for `nt_msg.db` (auto-probed) |
| `data_key` / `salt` | Key and salt (**sensitive**, auto-written by `ntqq_key_scan.py`) |
| `key_variant` | The verified key variant, tried first on subsequent runs |
| `work_dir` | Working directory for copies / plaintext DB |
| `output_dir` | Export output directory |
| `self_uid` / `self_qq` | Your own identity (used for chat-direction detection; optional) |

## Security & Legal Notes

- `config.json`, `work_dir`, and `output_dir` contain **plaintext keys and private chat content** — never commit or share them (a `.gitignore` is included as a safety net);
- The whole pipeline is **read-only** against QQ data: decryption happens on copies, the source DB is never written;
- Only back up data on **your own** device; other uses may violate local laws and regulations.

## Known Limitations

- Speakers who left a group and never appeared with a nickname in any message still show as uid/QQ number (~20% of messages);
- Media files export metadata only, no file bodies;
- A tiny fraction of `unknown` types keep only the type number;
- Major QQ updates may change key variants or column semantics — re-run `ntqq_key_scan.py` and follow self-check hints.

## Acknowledgments

- [NapNeko/qq_dump_db](https://github.com/NapNeko/qq_dump_db) — public description of the in-memory credential pattern
- [QQBackup/nt_msg_db_util](https://github.com/QQBackup/nt_msg_db_util) — decryption parameters and schema reference
- The engineering paradigm (self-check / pitfalls log / changelog) follows an internal WeChat 4.x export skill

## License

[MIT](LICENSE)
