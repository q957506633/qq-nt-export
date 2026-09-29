# -*- coding: utf-8 -*-
"""
NTQQ 辅助库解密（group_info.db / profile_info.db 等，源库只读）

用途：nt_msg.db 只有消息行内偶发的昵称字段；group_info.db（群资料/群成员）
与 profile_info.db（好友资料）里保存了稳定的昵称/群名片映射，
解密后供 ntqq_export.py 做发送者昵称回填，消除导出中的 uid/裸 QQ 号。

凭据来源：<work_dir>/ntqq_db_key.json（由 ntqq_key_scan.py 内存扫描产出，
含 nt_db 全部库的 key+salt；每个库用自己的文件头盐值交叉匹配凭据）。

流程（每个库）：
  1) backup  源库(+WAL) 拷到 <work>/backup/
  2) strip   剥前 1024 字节自定义头
  3) probe   按 config.json key_variant 优先探测（凭据按盐值从 key json 匹配）
  4) export  sqlcipher_export -> <work>/<库名>_plain.db
  5) verify  integrity_check + 表行数概览

用法:
  python ntqq_aux_decrypt.py [--names group_info.db,profile_info.db] [--no-wal]

退出码: 0 全部成功 / 1 有失败
"""
import argparse
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL_DIR = os.path.dirname(HERE)
CONFIG_PATH = os.path.join(SKILL_DIR, "config.json")
sys.path.insert(0, HERE)
from ntqq_decrypt import (  # noqa: E402
    load_config, backup_db, strip_header, probe_key, export_plain, verify_plain,
    DEFAULT_HEADER_SIZE,
)


def read_salt_hex(db_path, header_size=DEFAULT_HEADER_SIZE):
    with open(db_path, "rb") as f:
        f.seek(header_size)
        return f.read(16).hex()


def resolve_nt_db_dir(cfg):
    p = cfg.get("db_path") or ""
    return os.path.dirname(p) if p else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--names", default="group_info.db,profile_info.db",
                    help="要解密的辅助库名（逗号分隔，默认 group_info.db,profile_info.db）")
    ap.add_argument("--keys-json", default=None,
                    help="凭据 JSON 路径（默认 <work_dir>/ntqq_db_key.json）")
    ap.add_argument("--work-dir", default=None)
    ap.add_argument("--no-wal", action="store_true")
    args = ap.parse_args()

    t0 = time.time()
    cfg = load_config()
    work = args.work_dir or cfg.get("work_dir") or os.path.join(SKILL_DIR, ".work")
    os.makedirs(work, exist_ok=True)
    keys_path = args.keys_json or os.path.join(work, "ntqq_db_key.json")
    if not os.path.isfile(keys_path):
        print("[X] 找不到凭据 JSON: %s（先跑 ntqq_key_scan.py 并保留全量命中）" % keys_path)
        print("[RESULT] %s" % json.dumps({"ok": False, "error": "keys json not found"}, ensure_ascii=False))
        return 1
    with open(keys_path, "r", encoding="utf-8") as f:
        keydoc = json.load(f)
    creds = keydoc.get("all_nt_db_keys") or []
    if not creds:
        print("[X] 凭据 JSON 里没有 all_nt_db_keys 条目")
        print("[RESULT] %s" % json.dumps({"ok": False, "error": "no aux creds"}, ensure_ascii=False))
        return 1

    db_dir = resolve_nt_db_dir(cfg)
    if not db_dir or not os.path.isdir(db_dir):
        print("[X] nt_db 目录不存在: %s" % db_dir)
        print("[RESULT] %s" % json.dumps({"ok": False, "error": "nt_db dir not found"}, ensure_ascii=False))
        return 1

    names = [n.strip() for n in args.names.split(",") if n.strip()]
    results = []
    for name in names:
        src = os.path.join(db_dir, name)
        if not os.path.isfile(src):
            print("[X] 库不存在: %s" % src)
            results.append({"db": name, "ok": False, "error": "not found"})
            continue
        salt_hex = read_salt_hex(src, cfg.get("header_size", DEFAULT_HEADER_SIZE))
        cred = next((c for c in creds if (c.get("salt_hex") or "").lower() == salt_hex
                     and c.get("key_hex")), None)
        if not cred:
            print("[X] %s：文件头盐值 %s 在凭据 JSON 中无匹配（QQ 更新后需重跑 ntqq_key_scan.py）"
                  % (name, salt_hex))
            results.append({"db": name, "ok": False, "error": "no cred for salt"})
            continue
        print("[*] %s：盐值匹配成功（pid=%s）" % (name, cred.get("pid")))
        bk = backup_db(src, work, with_wal=not args.no_wal)
        clear_db = strip_header(bk, os.path.join(work, name + ".clear"),
                                cfg.get("header_size", DEFAULT_HEADER_SIZE))
        tag, con, errors = probe_key(clear_db, cred["key_hex"], salt_hex,
                                     page_size=cfg.get("page_size", 4096),
                                     preferred=cfg.get("key_variant"))
        if con is None:
            print("[X] %s：全部密钥形态失败" % name)
            results.append({"db": name, "ok": False, "error": "all variants failed",
                            "details": errors[:4]})
            continue
        plain_db = export_plain(con, os.path.join(work, name.replace(".db", "") + "_plain.db"))
        con.close()
        info = verify_plain(plain_db)
        print("[VERIFY] %s integrity=%s tables=%d" % (name, info["integrity_check"], info["tables"]))
        top = sorted(((t, c) for t, c in info["table_counts"].items() if isinstance(c, int)),
                     key=lambda x: -x[1])[:8]
        for t, c in top:
            print("   %-32s %s" % (t, c))
        results.append({"db": name, "ok": info["integrity_check"] == "ok",
                        "variant": tag, "plain_db": os.path.abspath(plain_db),
                        "integrity_check": info["integrity_check"],
                        "tables": info["tables"], "table_counts": info["table_counts"]})

    ok = all(r.get("ok") for r in results)
    out = {"ok": ok, "results": results, "seconds": round(time.time() - t0, 1),
           "generated_at": time.strftime("%Y-%m-%d %H:%M:%S")}
    with open(os.path.join(work, "aux_decrypt_report.json"), "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print("[RESULT] %s" % json.dumps(
        {"ok": ok, "dbs": [{"db": r["db"], "ok": r.get("ok")} for r in results],
         "seconds": out["seconds"]}, ensure_ascii=False))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
