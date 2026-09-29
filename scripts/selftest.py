# -*- coding: utf-8 -*-
"""
qq-nt-export 自检

用法:
  python selftest.py            # 只跑快速检查（环境/配置/依赖/源库）
  python selftest.py --deep     # 追加解密产物与导出结果检查（需已跑过 decrypt/export）
  python selftest.py --json     # 机器可读输出

退出码 = 失败项数（0 表示全通过）
"""
import argparse
import json
import os
import sqlite3
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(HERE, "config.json")


def log(ok, name, detail=""):
    print("[%s] %-22s %s" % ("PASS" if ok else "FAIL", name, detail))
    return ok


def load_config():
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def check_python(cfg):
    v = sys.version_info
    return log(v >= (3, 8), "python", "%d.%d.%d (%s)" % (v[0], v[1], v[2], sys.executable))


def check_config(cfg):
    need = ["db_path", "work_dir", "output_dir", "python"]
    miss = [k for k in need if not cfg.get(k)]
    return log(not miss, "config", "缺失字段: %s" % miss if miss else os.path.relpath(CONFIG_PATH, HERE))


def check_data_key(cfg):
    k, s = (cfg.get("data_key") or "").strip(), (cfg.get("salt") or "").strip()
    ok = len(k) == 64 and len(s) == 32
    try:
        int(k, 16)
        int(s, 16)
    except ValueError:
        ok = False
    return log(ok, "data_key", "key %d hex / salt %d hex%s" % (
        len(k), len(s), "" if ok else " (需重跑 ntqq_key_scan.py)"))


def check_deps(cfg):
    pkg = cfg.get("pkg_path")
    if pkg and os.path.isdir(pkg) and pkg not in sys.path:
        sys.path.insert(0, pkg)
    mods = {"sqlcipher3": "sqlcipher3.dbapi2", "Crypto": "Crypto.Cipher.AES", "zstandard": "zstandard"}
    bad = []
    for name, imp in mods.items():
        try:
            __import__(imp)
        except Exception as e:
            bad.append("%s(%s)" % (name, type(e).__name__))
    return log(not bad, "deps", "缺失: %s" % bad if bad else ", ".join(mods))


def check_db_storage(cfg):
    cands = [cfg.get("db_path")] + list(cfg.get("db_path_candidates") or [])
    hit = [p for p in cands if p and os.path.isfile(p)]
    if not hit:
        return log(False, "db_storage", "未找到 nt_msg.db；候选: %s" % cands[:3])
    p = hit[0]
    wal = os.path.isfile(p + "-wal")
    return log(True, "db_storage", "%s (%.1f MB, WAL=%s)" % (
        p, os.path.getsize(p) / 1048576, wal))


def check_work_dir(cfg):
    d = cfg.get("work_dir")
    try:
        os.makedirs(d, exist_ok=True)
        f = os.path.join(d, ".selftest_write")
        open(f, "w").write("ok")
        os.remove(f)
        return log(True, "work_dir", d)
    except Exception as e:
        return log(False, "work_dir", "%s: %s" % (d, e))


def check_output_dir(cfg):
    d = cfg.get("output_dir")
    try:
        os.makedirs(d, exist_ok=True)
        return log(True, "output_dir", d)
    except Exception as e:
        return log(False, "output_dir", "%s: %s" % (d, e))


def check_plain_db(cfg):
    p = os.path.join(cfg["work_dir"], "nt_msg_plain.db")
    if not os.path.isfile(p):
        return log(False, "plain_db", "不存在 %s（需先跑 ntqq_decrypt.py）" % p)
    try:
        con = sqlite3.connect("file:%s?mode=ro" % p.replace("\\", "/"), uri=True)
        ic = con.execute("PRAGMA integrity_check").fetchone()[0]
        counts = {}
        for t in ("c2c_msg_table", "group_msg_table"):
            try:
                counts[t] = con.execute('SELECT COUNT(*) FROM "%s"' % t).fetchone()[0]
            except Exception:
                counts[t] = -1
        con.close()
        ok = ic == "ok"
        return log(ok, "plain_db", "integrity=%s c2c=%s group=%s" % (
            ic, counts["c2c_msg_table"], counts["group_msg_table"]))
    except Exception as e:
        return log(False, "plain_db", "%s: %s" % (type(e).__name__, e))


def check_export(cfg):
    out = cfg["output_dir"]
    idx_p = os.path.join(out, "sessions_index.json")
    if not os.path.isfile(idx_p):
        return log(False, "export", "不存在 %s（需先跑 ntqq_export.py）" % idx_p)
    idx = json.load(open(idx_p, encoding="utf-8"))
    ok_files, bad = 0, []
    total = 0
    for s in idx["sessions"]:
        try:
            data = json.load(open(os.path.join(out, "json", s["json_file"]), encoding="utf-8"))
            ok_files += 1
            total += len(data)
        except Exception as e:
            bad.append("%s:%s" % (s["json_file"], type(e).__name__))
    ok = not bad and total == idx.get("total_messages")
    return log(ok, "export", "会话=%d json_ok=%d 消息=%d (index=%s)%s" % (
        idx.get("total_sessions"), ok_files, total, idx.get("total_messages"),
        " 异常: %s" % bad[:3] if bad else ""))


def check_verify_report(cfg):
    p = os.path.join(cfg["output_dir"], "verify_report.json")
    if not os.path.isfile(p):
        return log(False, "verify_report", "不存在 %s（需先跑 ntqq_verify.py）" % p)
    r = json.load(open(p, encoding="utf-8"))
    return log(bool(r.get("ok")), "verify_report", "problems=%d time_range=%s" % (
        len(r.get("problems") or []), r.get("time_range")))


def check_aux_maps(cfg):
    """辅助昵称库（可选增强）：存在则必须可读且含关键表；不存在只提示不判失败。"""
    wd = cfg.get("work_dir")
    gi = os.path.join(wd, "group_info_plain.db")
    pi = os.path.join(wd, "profile_info_plain.db")
    if not (os.path.isfile(gi) and os.path.isfile(pi)):
        return log(True, "aux_maps", "未解密（可选，跑 ntqq_aux_decrypt.py 可提升昵称覆盖率）")
    bad = []
    n1 = n2 = "?"
    try:
        con = sqlite3.connect("file:%s?mode=ro" % gi.replace("\\", "/"), uri=True)
        n1 = con.execute('SELECT COUNT(*) FROM "group_member3"').fetchone()[0]
        con.close()
        con = sqlite3.connect("file:%s?mode=ro" % pi.replace("\\", "/"), uri=True)
        n2 = con.execute('SELECT COUNT(*) FROM "profile_info_v6"').fetchone()[0]
        con.close()
        if n1 <= 0:
            bad.append("group_member3 空")
        if n2 <= 0:
            bad.append("profile_info_v6 空")
    except Exception as e:
        bad.append("%s: %s" % (type(e).__name__, e))
    return log(not bad, "aux_maps", "群成员=%s 资料=%s%s" % (
        n1, n2, " 异常: %s" % bad if bad else ""))


FAST_CHECKS = [check_python, check_config, check_data_key, check_deps,
               check_db_storage, check_work_dir, check_output_dir, check_aux_maps]
DEEP_CHECKS = [check_plain_db, check_export, check_verify_report]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--deep", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    cfg = load_config()
    checks = FAST_CHECKS + (DEEP_CHECKS if args.deep else [])
    fails = 0
    for fn in checks:
        try:
            ok = fn(cfg)
        except Exception as e:
            ok = log(False, fn.__name__, "%s: %s" % (type(e).__name__, e))
        if not ok:
            fails += 1
    mode = "deep" if args.deep else "fast"
    print("\n%s: %d/%d 通过，失败 %d 项" % (mode, len(checks) - fails, len(checks), fails))
    if args.json:
        print("[RESULT] %s" % json.dumps({"mode": mode, "total": len(checks), "failed": fails},
                                         ensure_ascii=False))
    return fails


if __name__ == "__main__":
    sys.exit(main())
