# -*- coding: utf-8 -*-
"""
NTQQ nt_msg.db 解密（源库只读，全部操作在副本上进行）

流程：
  1) backup  源库三件套拷贝到 <work>/backup（只读打开源库，绝不写源库）
  2) strip   剥掉前 1024 字节自定义头 -> <work>/nt_msg_clear.db（SQLCipher 数据区）
  3) probe   多候选密钥形态探测（SQLCipher 参数见 config.json / 本文件 VARIANTS）
  4) export  sqlcipher_export -> <work>/nt_msg_plain.db（标准明文 SQLite）
  5) verify  integrity_check + 表结构/行数概览

用法:
  python ntqq_decrypt.py [--src-db PATH] [--key HEX] [--salt HEX] [--work-dir DIR] [--no-wal] [--json-out PATH]

退出码: 0 成功 / 1 失败
"""
import argparse
import json
import os
import shutil
import sqlite3
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL_DIR = os.path.dirname(HERE)
CONFIG_PATH = os.path.join(SKILL_DIR, "config.json")

DEFAULT_HEADER_SIZE = 1024
DEFAULT_PAGE_SIZE = 4096

VARIANTS = [
    ("A_raw_hex_key_plus_salt", lambda k, s: 'PRAGMA key = "x\'%s%s\'"' % (k, s), []),
    ("B_raw_hex_key_only", lambda k, s: 'PRAGMA key = "x\'%s\'"' % k, []),
    ("C_passphrase_sqlcipher3_params", lambda k, s: "PRAGMA key = '%s'" % k,
     ["PRAGMA kdf_iter = 4000", "PRAGMA cipher_hmac_algorithm = HMAC_SHA1",
      "PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA512"]),
    ("D_raw_hex_key_plus_salt_hmac_sha1", lambda k, s: 'PRAGMA key = "x\'%s%s\'"' % (k, s),
     ["PRAGMA cipher_hmac_algorithm = HMAC_SHA1"]),
]


def load_config():
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def resolve_db_path(cfg, override=None):
    cands, seen = [], set()
    for p in [override, cfg.get("db_path")] + list(cfg.get("db_path_candidates") or []):
        if p and p not in seen:
            seen.add(p)
            cands.append(p)
    for p in cands:
        if p and os.path.isfile(p):
            return p
    return None


def backup_db(db_path, work, with_wal=True):
    """拷贝源库（+WAL）到工作目录副本。不拷 -shm，让 SQLite 自行重建。"""
    bk_dir = os.path.join(work, "backup")
    os.makedirs(bk_dir, exist_ok=True)
    dst = os.path.join(bk_dir, os.path.basename(db_path))
    if os.path.exists(dst):
        os.remove(dst)
    shutil.copy2(db_path, dst)
    for suf in ("-wal", "-shm"):
        src, d = db_path + suf, dst + suf
        if suf == "-wal" and with_wal and os.path.exists(src):
            shutil.copy2(src, d)
        elif os.path.exists(d):
            os.remove(d)
    return dst


def strip_header(bk_db, clear_db, header_size=DEFAULT_HEADER_SIZE):
    """剥掉 1024 字节自定义头；并同步副本 WAL（无 WAL 时清掉上次残留）。"""
    with open(bk_db, "rb") as fi, open(clear_db, "wb") as fo:
        fi.seek(header_size)
        while True:
            b = fi.read(8 << 20)
            if not b:
                break
            fo.write(b)
    wal_src = bk_db + "-wal"
    for suf in ("-wal", "-shm"):
        d = clear_db + suf
        if suf == "-wal" and os.path.exists(wal_src):
            shutil.copy2(wal_src, d)
        elif os.path.exists(d):
            os.remove(d)
    return clear_db


def probe_key(clear_db, key_hex, salt_hex, page_size=DEFAULT_PAGE_SIZE, preferred=None):
    """依次尝试候选密钥形态；命中条件是 integrity_check == ok。
    preferred 为 config.json 里记录的命中形态（tag），优先尝试以便日常运行安静快速。"""
    import sqlcipher3.dbapi2 as sqlcipher
    errors = []
    order = sorted(VARIANTS, key=lambda v: 0 if v[0] == preferred else 1)
    for tag, key_stmt, extras in order:
        con = sqlcipher.connect(clear_db)
        try:
            cur = con.cursor()
            cur.execute("PRAGMA cipher_page_size = %d" % page_size)
            cur.execute(key_stmt(key_hex, salt_hex))
            for e in extras:
                cur.execute(e)
            n = cur.execute("SELECT count(*) FROM sqlite_master").fetchone()[0]
            ic = cur.execute("PRAGMA integrity_check").fetchone()[0]
            if ic == "ok":
                print("[OK ] %s -> sqlite_master=%d integrity_check=ok" % (tag, n))
                return tag, con, errors
            errors.append("%s: integrity=%s" % (tag, ic))
            print("[FAIL] %s -> integrity=%s" % (tag, ic))
            con.close()
        except Exception as e:
            errors.append("%s: %s: %s" % (tag, type(e).__name__, str(e)[:120]))
            print("[FAIL] %s -> %s: %s" % (tag, type(e).__name__, str(e)[:120]))
            try:
                con.close()
            except Exception:
                pass
    return None, None, errors


def export_plain(con, plain_db):
    if os.path.exists(plain_db):
        os.remove(plain_db)
    cur = con.cursor()
    cur.execute("ATTACH DATABASE ? AS plaintext KEY ''", (plain_db,))
    cur.execute("SELECT sqlcipher_export('plaintext')")
    cur.execute("DETACH DATABASE plaintext")
    print("[*] 明文导出完成 -> %s (%d B)" % (plain_db, os.path.getsize(plain_db)))
    return plain_db


def verify_plain(plain_db):
    con = sqlite3.connect("file:%s?mode=ro" % plain_db.replace("\\", "/"), uri=True)
    ic = con.execute("PRAGMA integrity_check").fetchone()[0]
    tables = [r[0] for r in con.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
    counts = {}
    for t in tables:
        try:
            counts[t] = con.execute('SELECT COUNT(*) FROM "%s"' % t).fetchone()[0]
        except Exception as e:
            counts[t] = "ERR:%s" % e
    con.close()
    return {"integrity_check": ic, "tables": len(tables), "table_counts": counts}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src-db", default=None, help="nt_msg.db 路径（默认取 config.json）")
    ap.add_argument("--key", default=None, help="64 位 hex 密钥（默认取 config.json data_key）")
    ap.add_argument("--salt", default=None, help="32 位 hex 盐（默认取 config.json salt）")
    ap.add_argument("--work-dir", default=None)
    ap.add_argument("--no-wal", action="store_true", help="不带 WAL 副本（只读主库旧数据）")
    ap.add_argument("--page-size", type=int, default=DEFAULT_PAGE_SIZE)
    args = ap.parse_args()

    t0 = time.time()
    cfg = load_config()
    db_path = resolve_db_path(cfg, args.src_db)
    key = (args.key or cfg.get("data_key") or "").strip()
    salt = (args.salt or cfg.get("salt") or "").strip()
    work = args.work_dir or cfg.get("work_dir") or os.path.join(SKILL_DIR, ".work")
    os.makedirs(work, exist_ok=True)

    if not db_path:
        print("[X] 找不到 nt_msg.db（检查 config.json db_path / db_path_candidates）")
        print("[RESULT] %s" % json.dumps({"ok": False, "error": "db_path not found"}, ensure_ascii=False))
        return 1
    if len(key) != 64 or len(salt) != 32:
        print("[X] key/salt 形态不对（key 应 64 hex，salt 应 32 hex）；请先跑 ntqq_key_scan.py")
        print("[RESULT] %s" % json.dumps({"ok": False, "error": "bad key/salt format"}, ensure_ascii=False))
        return 1

    print("[*] 源库: %s (%d B)" % (db_path, os.path.getsize(db_path)))
    print("[*] 工作目录: %s  WAL=%s" % (work, not args.no_wal))

    bk = backup_db(db_path, work, with_wal=not args.no_wal)
    print("[*] 副本: %s (%d B)" % (bk, os.path.getsize(bk)))
    clear_db = strip_header(bk, os.path.join(work, "nt_msg_clear.db"),
                           cfg.get("header_size", DEFAULT_HEADER_SIZE))
    print("[*] 剥头完成 -> %s (%d B)" % (clear_db, os.path.getsize(clear_db)))

    tag, con, errors = probe_key(clear_db, key, salt, page_size=args.page_size,
                                 preferred=cfg.get("key_variant"))
    if con is None:
        print("[X] 所有密钥候选均失败：检查密钥/盐是否正确、WAL 是否与主库配套")
        print("[RESULT] %s" % json.dumps({"ok": False, "error": "all key variants failed",
                                         "details": errors[:6]}, ensure_ascii=False))
        return 1

    plain_db = export_plain(con, os.path.join(work, "nt_msg_plain.db"))
    con.close()
    info = verify_plain(plain_db)
    print("[VERIFY] integrity=%s tables=%d" % (info["integrity_check"], info["tables"]))
    for t in ("c2c_msg_table", "group_msg_table"):
        print("   %-18s %s" % (t, info["table_counts"].get(t)))
    print("[*] 用时 %.1fs" % (time.time() - t0))

    result = {
        "ok": info["integrity_check"] == "ok",
        "variant": tag,
        "plain_db": os.path.abspath(plain_db),
        "plain_size": os.path.getsize(plain_db),
        "backup": os.path.abspath(bk),
        "with_wal": not args.no_wal,
        "integrity_check": info["integrity_check"],
        "tables": info["tables"],
        "c2c_rows": info["table_counts"].get("c2c_msg_table"),
        "group_rows": info["table_counts"].get("group_msg_table"),
        "seconds": round(time.time() - t0, 1),
    }
    json_out = os.path.join(work, "decrypt_report.json")
    with open(json_out, "w", encoding="utf-8") as f:
        json.dump({"result": result, "table_counts": info["table_counts"]}, f,
                  ensure_ascii=False, indent=2)
    print("[RESULT] %s" % json.dumps(result, ensure_ascii=False))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
