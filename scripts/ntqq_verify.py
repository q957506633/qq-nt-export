# -*- coding: utf-8 -*-
"""
导出结果校验：JSON 可解析性 / 条数一致性 / 时间范围 / 内容类型分布 / 样例 / 表结构快照

用法:
  python ntqq_verify.py [--outdir DIR] [--src <明文库>] [--report PATH]

产出：<outdir>/nt_msg_plain_schema.sql（明文库表结构快照）+ <outdir>/verify_report.json
退出码: 0 全通过 / 1 有问题项
"""
import argparse
import json
import os
import sqlite3
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL_DIR = os.path.dirname(HERE)
CONFIG_PATH = os.path.join(SKILL_DIR, "config.json")


def load_config():
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--outdir", default=None, help="导出目录（默认 config.json output_dir）")
    ap.add_argument("--src", default=None, help="明文库（默认 <work_dir>/nt_msg_plain.db）")
    ap.add_argument("--report", default=None, help="报告 JSON 路径（默认 <outdir>/verify_report.json）")
    args = ap.parse_args()

    cfg = load_config()
    outdir = args.outdir or cfg.get("output_dir")
    plain = args.src or os.path.join(cfg.get("work_dir") or os.path.join(SKILL_DIR, ".work"),
                                     "nt_msg_plain.db")
    idx_path = os.path.join(outdir, "sessions_index.json")
    if not os.path.isfile(idx_path):
        print("[X] 找不到 %s（先跑 ntqq_export.py）" % idx_path)
        print("[RESULT] %s" % json.dumps({"ok": False, "error": "sessions_index.json not found"},
                                         ensure_ascii=False))
        return 1

    idx = json.load(open(idx_path, encoding="utf-8"))
    ok = bad = total = 0
    tmin = tmax = None
    problems, type_counter, samples = [], {}, []
    want = ["text", "image", "file", "sticker", "reply", "forward", "legacy_forward",
            "call", "contact", "video", "mixed", "media_placeholder"]

    for s in idx["sessions"]:
        p = os.path.join(outdir, "json", s["json_file"])
        try:
            data = json.load(open(p, encoding="utf-8"))
        except Exception as exc:
            bad += 1
            problems.append("%s: %s" % (s["json_file"], exc))
            continue
        ok += 1
        total += len(data)
        if len(data) != s["count"]:
            problems.append("%s 条数不一致 index=%d json=%d" % (s["json_file"], s["count"], len(data)))
        for m in data:
            ts = m.get("timestamp")
            if ts:
                tmin = ts if tmin is None else min(tmin, ts)
                tmax = ts if tmax is None else max(tmax, ts)
            ct = (m.get("content") or {}).get("type") or "none"
            type_counter[ct] = type_counter.get(ct, 0) + 1
            if ct in want and len(samples) < 12:
                samples.append({
                    "session": s["session_id"], "chat_type": s["chat_type"], "time": m["time"],
                    "sender": m.get("sender_name") or m.get("sender_uid")
                    or (str(m.get("sender_qq")) if m.get("sender_qq") not in (None, 0, "0", "") else "?"),
                    "direction": m.get("direction"), "content_type": ct,
                    "text": (m.get("text") or "")[:120],
                    "content": json.dumps(m.get("content"), ensure_ascii=False)[:220],
                })
                want.remove(ct)

    schema_file = None
    schema_info = {}
    if os.path.isfile(plain):
        con = sqlite3.connect("file:%s?mode=ro" % plain.replace("\\", "/"), uri=True)
        lines = []
        tables = [r[0] for r in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
        for t in tables:
            cnt = con.execute('SELECT COUNT(*) FROM "%s"' % t).fetchone()[0]
            cols = con.execute('PRAGMA table_info("%s")' % t).fetchall()
            lines.append('CREATE TABLE "%s" (-- 行数 %d' % (t, cnt))
            lines.append("  " + ", ".join("%s %s" % (c[1], c[2]) for c in cols) + ");")
            lines.append("")
        schema_info = {"integrity_check": con.execute("PRAGMA integrity_check").fetchone()[0],
                       "tables": len(tables)}
        con.close()
        schema_file = os.path.join(outdir, "nt_msg_plain_schema.sql")
        open(schema_file, "w", encoding="utf-8").write("\n".join(lines))
    else:
        problems.append("明文库不存在，跳过表结构快照: %s" % plain)

    report = {
        "ok": bad == 0 and not [p for p in problems if "条数不一致" in p],
        "outdir": os.path.abspath(outdir),
        "json_files_ok": ok, "json_files_bad": bad,
        "messages_in_json": total, "messages_in_index": idx.get("total_messages"),
        "count_match": total == idx.get("total_messages"),
        "time_range": [time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(tmin)) if tmin else None,
                       time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(tmax)) if tmax else None],
        "content_type_distribution": dict(sorted(type_counter.items(), key=lambda kv: -kv[1])),
        "plain_db": {"integrity_check": schema_info.get("integrity_check"),
                     "tables": schema_info.get("tables"),
                     "schema_snapshot": schema_file},
        "top_sessions": [{k: s[k] for k in ("chat_type", "session_id", "count", "first_time", "last_time")}
                         for s in idx["sessions"][:8]],
        "samples": samples,
        "problems": problems[:20],
    }
    report_path = args.report or os.path.join(outdir, "verify_report.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print("[RESULT] %s" % json.dumps({
        "ok": report["ok"], "json_files_ok": ok, "json_files_bad": bad,
        "messages_in_json": total, "messages_in_index": idx.get("total_messages"),
        "time_range": report["time_range"], "problems": len(problems),
        "verify_report": os.path.abspath(report_path),
    }, ensure_ascii=False))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
