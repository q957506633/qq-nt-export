# -*- coding: utf-8 -*-
"""
NTQQ 明文库 -> 结构化消息导出（JSON / TXT / 索引）

- 输入：ntqq_decrypt.py 产出的明文 SQLite（只读打开，绝不写入）
        +（可选）ntqq_aux_decrypt.py 产出的 group_info_plain.db / profile_info_plain.db
- 输出：<outdir>/json/<session>.json（结构化）+ <outdir>/txt/<session>.txt（可读转录）
        + <outdir>/sessions_index.json（会话清单与统计）

昵称回填优先级（v1.1.0）：
  群聊：行内名片(40090) → 行内昵称(40093) → 群成员表名片(group_member3.64003)
        → 群成员表昵称(20002) → 消息库 uid 映射 → 个人资料昵称(profile_info_v6.20002)
        → QQ 号 → uid
  单聊：行内昵称 → 消息库 uid 映射 → 个人资料昵称 → 对方

指定会话导出（v1.2.0）：
  --only 100001000000         # 单聊：对方 QQ 号（示例）
  --only 123456789            # 群聊：群号
  --only u_AbCdEfGhIjKlMnOpQ  # 单聊：对方 uid（u_ 开头）
  --only 123456789 100001000000 # 可多个；同一数字既命中群号又命中 QQ 号时两者都导
  未指定 --outdir 时，筛选结果写入 <output_dir>/filter_<条件>/，不覆盖全量导出。

文件命名（v1.3.0）：`名称_QQ号`——群聊 `群名_群号`、单聊 `昵称_对方QQ号`；
中文/emoji 保留（safe_display_name 仅过滤 Windows 非法字符），重名自动加 (2)(3)...，
取不到名称或 QQ 号时退回 c2c_<uid> / group_<群号> 旧形式。

用法:
  python ntqq_export.py [--src <明文库>] [--outdir DIR] [--limit N] [--only QQ号|群号|uid ...]

退出码: 0 成功 / 1 失败
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
sys.path.insert(0, HERE)
from ntqq_msg_parser import (  # noqa: E402
    parse_40800, build_content, content_preview, safe_name, safe_display_name, fmt_ts,
)

SELECT_C2C = """\
SELECT "40001" AS msg_id, "40050" AS ts, "40013" AS direction, "40020" AS sender_uid,
       "40033" AS sender_qq, "40021" AS peer_uid, "40030" AS peer_qq, "40011" AS msg_type,
       "40012" AS subtype, "40090" AS card, "40093" AS nick, "40800" AS blob
FROM c2c_msg_table ORDER BY "40021", CASE WHEN "40050" IS NULL OR "40050" <= 0 THEN 1 ELSE 0 END, "40050", "40001"
"""

SELECT_GROUP = """\
SELECT "40001" AS msg_id, "40050" AS ts, "40013" AS direction, "40020" AS sender_uid,
       "40033" AS sender_qq, "40021" AS group_id, "40030" AS group_qq, "40011" AS msg_type,
       "40012" AS subtype, "40090" AS card, "40093" AS nick, "40800" AS blob
FROM group_msg_table ORDER BY "40021", CASE WHEN "40050" IS NULL OR "40050" <= 0 THEN 1 ELSE 0 END, "40050", "40001"
"""


def load_config():
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def _clean(v):
    """None / 空串 / 纯空白 → None；其余去首尾空白。"""
    if v is None:
        return None
    s = str(v).strip()
    return s or None


def build_uid_nick_map(cur):
    """uid -> 昵称 回填表：同一 uid 在任意会话带过 40093 昵称，即可用于其它缺昵称的消息。"""
    uid_nick = {}
    for t in ("c2c_msg_table", "group_msg_table"):
        for r in cur.execute(
                'SELECT "40020" u,"40093" n FROM "%s" '
                'WHERE "40093" IS NOT NULL AND "40093"<>"" AND "40020" IS NOT NULL AND "40020"<>""' % t):
            u, n = _clean(r["u"]), _clean(r["n"])
            if u and n and u not in uid_nick:
                uid_nick[u] = n
    return uid_nick


def load_aux_maps(work_dir):
    """从辅助明文库（ntqq_aux_decrypt.py 产出）加载昵称/群名映射。缺失时静默降级。"""
    maps = {"member": {}, "profile_nick": {}, "group_names": {}, "loaded": []}
    if not work_dir:
        return maps
    gi = os.path.join(work_dir, "group_info_plain.db")
    pi = os.path.join(work_dir, "profile_info_plain.db")
    if os.path.isfile(gi):
        try:
            con = sqlite3.connect("file:%s?mode=ro" % gi.replace("\\", "/"), uri=True)
            con.row_factory = sqlite3.Row
            for r in con.execute('SELECT "60001" gid, "1000" uid, "64003" card, "20002" nick '
                                 'FROM "group_member3"'):
                gid = str(r["gid"] or "")
                uid = (r["uid"] or "").strip()
                if not gid or not uid:
                    continue
                card, nick = _clean(r["card"]), _clean(r["nick"])
                if card or nick:
                    maps["member"][(gid, uid)] = (card, nick)
            for r in con.execute('SELECT "60001" gid, "60007" name FROM "group_list"'):
                name = _clean(r["name"])
                if name:
                    maps["group_names"][str(r["gid"])] = name
            con.close()
            maps["loaded"].append("group_info")
        except Exception as e:
            print("[!] group_info_plain.db 读取失败（降级为无辅助映射）: %s" % e)
    if os.path.isfile(pi):
        try:
            con = sqlite3.connect("file:%s?mode=ro" % pi.replace("\\", "/"), uri=True)
            con.row_factory = sqlite3.Row
            for r in con.execute('SELECT "1000" uid, "20002" nick FROM "profile_info_v6"'):
                uid = (r["uid"] or "").strip()
                nick = _clean(r["nick"])
                if uid and nick and uid not in maps["profile_nick"]:
                    maps["profile_nick"][uid] = nick
            con.close()
            maps["loaded"].append("profile_info")
        except Exception as e:
            print("[!] profile_info_plain.db 读取失败（降级为无辅助映射）: %s" % e)
    return maps


def resolve_sender(row, chat_type, uid_nick, aux, stats):
    """返回 (sender_name, name_src)。name_src: row/member_card/member_nick/uid_map/profile/None。"""
    uid = (row["sender_uid"] or "").strip()
    name = _clean(row["card"]) or _clean(row["nick"])
    if name:
        stats["row"] = stats.get("row", 0) + 1
        return name, "row"
    if chat_type == "group":
        mem = aux["member"].get((str(row["group_id"] or ""), uid))
        if mem:
            if mem[0]:  # 群名片
                stats["member_card"] = stats.get("member_card", 0) + 1
                return mem[0], "member_card"
            if mem[1]:  # 群昵称
                stats["member_nick"] = stats.get("member_nick", 0) + 1
                return mem[1], "member_nick"
    if uid and uid in uid_nick:
        stats["uid_map"] = stats.get("uid_map", 0) + 1
        return uid_nick[uid], "uid_map"
    if uid and uid in aux["profile_nick"]:
        stats["profile"] = stats.get("profile", 0) + 1
        return aux["profile_nick"][uid], "profile"
    stats["none"] = stats.get("none", 0) + 1
    return None, None


def resolve_only_targets(cur, only):
    """把 --only 条件解析为 {groups:set, c2c_uids:set}。
    数字 → 群号（group_msg_table 中存在）和/或单聊对方 QQ（c2c_msg_table.40030）；
    u_ 开头 → 单聊对方 uid。返回 (targets, notes)；notes 记录未命中的条件。"""
    targets = {"groups": set(), "c2c_uids": set()}
    notes = []
    gids = set()
    for r in cur.execute('SELECT DISTINCT "40021" g FROM group_msg_table'):
        if r["g"]:
            gids.add(str(r["g"]))
    peer_pairs = set()
    for r in cur.execute('SELECT DISTINCT "40021" u, "40030" q FROM c2c_msg_table'):
        u = (r["u"] or "").strip()
        q = str(r["q"] or "")
        if u:
            peer_pairs.add((u, q))
    for t in only:
        t = t.strip()
        if not t:
            continue
        if t.startswith("u_"):
            if any(u == t for u, _ in peer_pairs):
                targets["c2c_uids"].add(t)
            else:
                notes.append("%s: 未在单聊会话中命中" % t)
        elif t.isdigit():
            hit = False
            if t in gids:
                targets["groups"].add(t)
                hit = True
            uids = [u for u, q in peer_pairs if q == t]
            if uids:
                targets["c2c_uids"].update(uids)
                hit = True
            if not hit:
                notes.append("%s: 既不是群号也不是单聊 QQ" % t)
        else:
            notes.append("%s: 无法识别（数字=QQ/群号，u_开头=uid）" % t)
    return targets, notes


def unique_base(base, used_names):
    """会话文件基础名查重：重名自动加 (2)(3)...。"""
    candidate, k = base, 1
    while candidate in used_names:
        k += 1
        candidate = "%s(%d)" % (base, k)
    used_names.add(candidate)
    return candidate


def export(src, outdir, limit=0, self_uid=None, self_qq=None, only=None):
    json_dir = os.path.join(outdir, "json")
    txt_dir = os.path.join(outdir, "txt")
    os.makedirs(json_dir, exist_ok=True)
    os.makedirs(txt_dir, exist_ok=True)

    con = sqlite3.connect("file:%s?mode=ro" % src.replace("\\", "/"), uri=True)
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    uid_nick = build_uid_nick_map(cur)
    aux = load_aux_maps(os.path.dirname(os.path.abspath(src)))
    if aux["loaded"]:
        print("[*] 辅助映射已加载: %s（群成员 %d / 群名 %d / 资料昵称 %d）" % (
            "+".join(aux["loaded"]), len(aux["member"]), len(aux["group_names"]),
            len(aux["profile_nick"])))
    name_stats = {}
    used_names = set()
    targets, only_notes = (None, [])
    if only:
        targets, only_notes = resolve_only_targets(cur, only)
        print("[*] 筛选条件: 群 %s / 单聊 uid %s" % (
            sorted(targets["groups"]) or "-", len(targets["c2c_uids"])))
        for n in only_notes:
            print("[!] %s" % n)
        if not targets["groups"] and not targets["c2c_uids"]:
            print("[X] 筛选条件均未命中任何会话")
            con.close()
            return None

    sessions, total_msgs, parse_fail = [], 0, 0

    for chat_type, sql, sess_col in (("c2c", SELECT_C2C, "peer_uid"),
                                     ("group", SELECT_GROUP, "group_id")):
        if targets is not None:
            allowed = targets["c2c_uids"] if chat_type == "c2c" else targets["groups"]
            if not allowed:
                continue
        cur.execute(sql)
        state = {"sess": None, "n": 0, "rec": None, "fh_json": None, "fh_txt": None, "first": True}

        def close():
            if state["fh_json"]:
                state["fh_json"].write("\n]\n")
                state["fh_json"].close()
            if state["fh_txt"]:
                if state["rec"]:
                    state["fh_txt"].write("\n# 共 %d 条消息，时间范围 %s ~ %s\n" % (
                        state["n"], state["rec"]["first_time"] or "-", state["rec"]["last_time"] or "-"))
                state["fh_txt"].close()
            if state["rec"]:
                state["rec"]["count"] = state["n"]
                sessions.append(state["rec"])
            state.update({"fh_json": None, "fh_txt": None})

        for row in cur:
            sess = row[sess_col] or "unknown"
            if targets is not None and sess not in allowed:
                continue
            if sess != state["sess"]:
                close()
                state["sess"] = sess
                state["n"] = 0
                if chat_type == "group":
                    nick = aux["group_names"].get(str(row["group_id"] or ""))
                    num = str(row["group_id"] or "")
                    disp = nick
                else:
                    nick = aux["profile_nick"].get((row["peer_uid"] or "").strip())
                    num = str(row["peer_qq"] or "")
                    disp = "%s（QQ %s）" % (nick, num) if (nick and num) else (
                        nick or ("QQ %s" % num if num else None))
                # 文件名 = 名称_QQ号（群聊为 群名_群号）；无名称退回旧编号形式
                if nick and num:
                    base = unique_base("%s_%s" % (safe_display_name(nick), num), used_names)
                elif num:
                    base = unique_base("%s_%s" % (chat_type, safe_name(sess)), used_names)
                else:
                    base = unique_base("%s_%s" % (chat_type, safe_name(sess)), used_names)
                state["fh_json"] = open(os.path.join(json_dir, base + ".json"), "w", encoding="utf-8")
                state["fh_txt"] = open(os.path.join(txt_dir, base + ".txt"), "w", encoding="utf-8")
                state["fh_json"].write("[\n")
                state["fh_txt"].write("# %s 会话 %s%s\n\n" % (
                    chat_type.upper(), sess, ("（%s）" % disp) if disp else ""))
                state["rec"] = {"chat_type": chat_type, "session_id": sess,
                                "session_name": disp,
                                "peer_qq": str(row["peer_qq"] or "") if chat_type == "c2c" else None,
                                "json_file": base + ".json", "txt_file": base + ".txt",
                                "count": 0, "first_ts": None, "last_ts": None,
                                "first_time": None, "last_time": None, "parse_errors": 0}
                state["first"] = True
            if limit and state["n"] >= limit:
                continue

            state["n"] += 1
            total_msgs += 1
            segs, err = parse_40800(row["blob"]) if row["blob"] else ([], None)
            if err:
                state["rec"]["parse_errors"] += 1
                parse_fail += 1
            text = "\n".join(s["text"] for s in segs if s["text"]) or None
            content = build_content(row["msg_type"] or 0, segs)

            sender_name, name_src = resolve_sender(row, chat_type, uid_nick, aux, name_stats)
            if chat_type == "group":
                sender = sender_name or str(row["sender_qq"] or row["sender_uid"] or "?")
            else:
                who = "我" if (row["direction"] or 0) in (1, 2) else (sender_name or "对方")
                sender = "%s(%s)" % (who, row["sender_qq"]) if row["sender_qq"] else who

            m = {
                "msg_id": row["msg_id"], "timestamp": row["ts"], "time": fmt_ts(row["ts"]),
                "direction": row["direction"], "sender_uid": row["sender_uid"],
                "sender_qq": row["sender_qq"], "sender_name": sender_name,
                "sender_name_src": name_src, "msg_type": row["msg_type"], "subtype": row["subtype"],
                "content_type": segs[0]["content_type"] if segs else None,
                "text": text, "content": content,
            }
            if chat_type == "c2c":
                m["peer_uid"], m["peer_qq"] = row["peer_uid"], row["peer_qq"]
            else:
                m["group_id"], m["group_qq"] = row["group_id"], row["group_qq"]

            if not state["first"]:
                state["fh_json"].write(",\n")
            state["first"] = False
            state["fh_json"].write(json.dumps(m, ensure_ascii=False))

            preview = content_preview(content) or "<无内容>"
            state["fh_txt"].write("[%s] %s: %s\n" % (m["time"], sender, preview.replace("\n", " ⏎ ")))

            if row["ts"] and row["ts"] > 0:
                if state["rec"]["first_ts"] is None:
                    state["rec"]["first_ts"] = row["ts"]
                    state["rec"]["first_time"] = m["time"]
                state["rec"]["last_ts"] = row["ts"]
                state["rec"]["last_time"] = m["time"]
            state["rec"]["count"] = state["n"]
        close()

    con.close()
    index = {
        "source_db": src,
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "self_uid": self_uid, "self_qq": self_qq, "limit_per_session": limit,
        "filter": None if targets is None else {
            "only": list(only or []),
            "groups": sorted(targets["groups"]),
            "c2c_uids": sorted(targets["c2c_uids"]),
            "unmatched": only_notes,
        },
        "aux_maps_loaded": aux["loaded"],
        "sender_name_stats": name_stats,
        "c2c_sessions": sum(1 for s in sessions if s["chat_type"] == "c2c"),
        "group_sessions": sum(1 for s in sessions if s["chat_type"] == "group"),
        "total_sessions": len(sessions),
        "total_messages": total_msgs,
        "parse_error_messages": parse_fail,
        "sessions": sorted(sessions, key=lambda s: -s["count"]),
    }
    with open(os.path.join(outdir, "sessions_index.json"), "w", encoding="utf-8") as f:
        json.dump(index, f, ensure_ascii=False, indent=2)
    return index


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default=None, help="明文 SQLite 路径（默认 <work_dir>/nt_msg_plain.db）")
    ap.add_argument("--outdir", default=None, help="输出目录（默认 config.json output_dir；用 --only 时默认 <output_dir>/filter_<条件>）")
    ap.add_argument("--limit", type=int, default=0, help="每个会话最多导出多少条（0=全部）")
    ap.add_argument("--only", nargs="+", default=None,
                    help="只导指定会话：QQ号 / 群号 / u_开头的uid，可多个")
    args = ap.parse_args()

    cfg = load_config()
    src = args.src or os.path.join(cfg.get("work_dir") or os.path.join(SKILL_DIR, ".work"),
                                   "nt_msg_plain.db")
    base_out = cfg.get("output_dir")
    if args.outdir:
        outdir = args.outdir
    elif args.only:
        tag = safe_name("_".join(args.only))[:80]
        outdir = os.path.join(base_out, "filter_%s" % tag)
    else:
        outdir = base_out
    if not src or not os.path.isfile(src):
        print("[X] 找不到明文库: %s（先跑 ntqq_decrypt.py）" % src)
        print("[RESULT] %s" % json.dumps({"ok": False, "error": "plain db not found"}, ensure_ascii=False))
        return 1
    os.makedirs(outdir, exist_ok=True)
    print("[*] 明文库: %s" % src)
    print("[*] 输出目录: %s" % outdir)

    t0 = time.time()
    index = export(src, outdir, limit=args.limit,
                   self_uid=cfg.get("self_uid"), self_qq=cfg.get("self_qq"),
                   only=args.only)
    if index is None:
        print("[RESULT] %s" % json.dumps({"ok": False, "error": "no session matched"}, ensure_ascii=False))
        return 1
    print("[*] 会话 %d（私聊 %d / 群聊 %d） 消息 %d 条 解析异常 %d 条  用时 %.1fs" % (
        index["total_sessions"], index["c2c_sessions"], index["group_sessions"],
        index["total_messages"], index["parse_error_messages"], time.time() - t0))
    print("[*] 发送者名回填统计: %s" % json.dumps(index["sender_name_stats"], ensure_ascii=False))
    for s in index["sessions"][:5]:
        print("   %-6s %-40s %6d 条  %s ~ %s" % (
            s["chat_type"], (s.get("session_name") or s["session_id"])[:40],
            s["count"], s["first_time"], s["last_time"]))
    print("[RESULT] %s" % json.dumps({
        "ok": True, "outdir": os.path.abspath(outdir),
        "total_sessions": index["total_sessions"], "c2c_sessions": index["c2c_sessions"],
        "group_sessions": index["group_sessions"], "total_messages": index["total_messages"],
        "parse_error_messages": index["parse_error_messages"],
        "sender_name_stats": index["sender_name_stats"],
        "index_file": os.path.join(os.path.abspath(outdir), "sessions_index.json"),
        "seconds": round(time.time() - t0, 1),
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
