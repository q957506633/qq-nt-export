"""
NTQQ 消息解析核心（被 qq_nt_export.py 导入，不单独运行）

- SQLCipher 明文库中的 c2c_msg_table / group_msg_table（列名为数字字符串）-> 结构化消息
- 不依赖 protobuf 运行库：内置极简 protobuf wire 解码器，按 c2c_40800.proto 字段号取值
- 字段语义：40001 msg_id / 40050 时间戳 / 40013 方向 / 40011 主类型 / 40012 子类型 /
  40020 sender uid / 40033 sender QQ / 40021 会话 id / 40030 会话 QQ / 40090 名片 /
  40093 群昵称 / 40800 正文 blob
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import sys
import time

# ─────────────────────────── 极简 protobuf wire 解码 ───────────────────────────


def _read_varint(buf, i):
    result = 0
    shift = 0
    while True:
        b = buf[i]
        i += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, i
        shift += 7
        if shift > 70:
            raise ValueError("varint too long")


def decode_fields(buf):
    """返回 {field_no: [(wire_type, value), ...]}；wire 0/1/5 → int/bytes/bytes，2 → bytes。"""
    out = {}
    i, n = 0, len(buf)
    while i < n:
        key, i = _read_varint(buf, i)
        fn, wt = key >> 3, key & 7
        if wt == 0:
            v, i = _read_varint(buf, i)
            if v >= 1 << 63:
                v -= 1 << 64
        elif wt == 1:
            v = buf[i:i + 8]
            i += 8
        elif wt == 2:
            ln, i = _read_varint(buf, i)
            v = buf[i:i + ln]
            i += ln
        elif wt == 5:
            v = buf[i:i + 4]
            i += 4
        else:
            raise ValueError("unsupported wire type %d" % wt)
        out.setdefault(fn, []).append((wt, v))
    return out


def _i(fields, no, default=None):
    for wt, v in fields.get(no, ()):
        if wt == 0:
            return v
    return default


def _s(fields, no, default=None):
    for wt, v in fields.get(no, ()):
        if wt == 2:
            return v.decode("utf-8", errors="replace")
    return default


def _b(fields, no, default=None):
    for wt, v in fields.get(no, ()):
        if wt == 2:
            return v
    return default


def _bs(fields, no):
    return [v for wt, v in fields.get(no, ()) if wt == 2]


# ─────────────────────────── 40800 = MsgBody{repeated MsgContent} ───────────────────────────

_MD5 = "md5"
_HEX = "md5_hex"


def parse_content(raw):
    """解析单段 MsgContent。"""
    f = decode_fields(raw)
    c = {
        "msg_id": _i(f, 45001),
        "content_type": _i(f, 45002, 0),
        "media_sub": _i(f, 45003),
        "sender_uid": _s(f, 40020),
        "text": _s(f, 45101),
        "text_attr": _i(f, 45102),
        "f45105": _s(f, 45105),
        "filename": _s(f, 45402),
        "filepath": _s(f, 45403),
        "filesize": _i(f, 45405),
        "md5_hex": (_b(f, 45406) or b"").hex() or None,
        "thumbnail_len": len(_b(f, 45408) or b""),
        "img_width": _i(f, 45411),
        "img_height": _i(f, 45412),
        "f45415": _i(f, 45415),
        "file_ext": _s(f, 45419),
        "file_uuid": _s(f, 45503),
        "cdn_path": (_b(f, 45504) or b"").decode("utf-8", errors="replace") or None,
        "sticker_hex": (_b(f, 45600) or b"").hex() or None,
        "cdn_url": _s(f, 45802) or _s(f, 45803) or _s(f, 45804),
        "local_path": _s(f, 45812),
        "ntos_path": _s(f, 45814),
        "text_fallback": [v.decode("utf-8", errors="replace") for v in _bs(f, 45815)],
        "loc_type": _i(f, 45851),
        "reply_msg_id": _i(f, 47401),
        "reply_msg_seq": _i(f, 47402),
        "reply_msg_time": _i(f, 47403),
        "reply_summary": _s(f, 47413),
        "nc_uid_1": _s(f, 47703),
        "nc_nickname_1": _s(f, 47705),
        "nc_remark_1": _s(f, 47706),
        "nc_nickname_2": _s(f, 47707),
        "nc_remark_2": _s(f, 47716),
        "nc_uid_2": _s(f, 47704),
        "nc_extra_text": _s(f, 47713),
        "video_flag": _i(f, 47601),
        "video_text": _s(f, 47602),
        "fwd_meta": _s(f, 47901),
        "fwd_token": _s(f, 47902),
        "fwd_uuid": _s(f, 47904),
        "call_type": _i(f, 48151, 0),
        "call_duration": _i(f, 48152, 0),
        "call_desc": _s(f, 48153),
        "legacy_fwd_resid": _s(f, 48601),
        "legacy_fwd_xml": _s(f, 48602),
        "legacy_fwd_uuid": _s(f, 48603),
        "proto_ver": _s(f, 49154),
        "inner_ts": _i(f, 49155),
        "sys_f80810": _i(f, 80810),
        "sys_content": _s(f, 80900),
        "rich_text": _s(f, 48705),
        "rich_markdown": _s(f, 48701),
    }
    ref = _b(f, 47710)
    c["ref_msg"] = parse_content(ref) if ref else None
    return c


def parse_40800(blob):
    """解析 40800 消息体，返回 (contents, error)。"""
    try:
        fields = decode_fields(blob)
    except Exception as exc:  # 损坏/非 protobuf
        return [], str(exc)
    segs = [parse_content(v) for wt, v in fields.get(40800, ()) if wt == 2]
    return segs, None


# ─────────────────────────── 段 -> 类型化 content ───────────────────────────


def _clip(d):
    return {k: v for k, v in d.items() if v not in (None, "", 0, [], False)}


def _seg_image(c):
    return _clip({
        "type": "image",
        "filename": c["filename"],
        "width": c["img_width"],
        "height": c["img_height"],
        "filesize": c["filesize"],
        "md5_hex": c["md5_hex"],
        "cdn_url": c["cdn_url"],
        "local_path": c["local_path"],
        "text_fallback": (c["text_fallback"] or [None])[0],
    })


def _seg_video(c):
    return _clip({
        "type": "video",
        "filename": c["filename"],
        "filesize": c["filesize"],
        "md5_hex": c["md5_hex"],
        "duration": c["f45415"],
        "cdn_url": c["cdn_url"],
        "local_path": c["local_path"],
        "video_text": c["video_text"],
    })


def _seg_file(c):
    return _clip({
        "type": "file",
        "filename": c["filename"],
        "filesize": c["filesize"],
        "md5_hex": c["md5_hex"],
        "ext": c["file_ext"],
        "file_uuid": c["file_uuid"],
        "cdn_path": c["cdn_path"],
    })


def _seg_sticker(c):
    return _clip({
        "type": "sticker",
        "md5_hex": c["sticker_hex"],
        "text_fallback": (c["text_fallback"] or [None])[0],
    })


def _seg_text(c):
    return {"type": "text", "text": c["text"] or ""}


def _seg_contact(c):
    # 名片类消息：47705=昵称，47707=备用昵称，47706/47716=备注，47713=互动文案（非昵称，如"并坏笑了一下。"）
    # 注：QQ 部分名片消息体未写入昵称（实测约 1/3），此时只给出 uid，不臆造昵称
    return _clip({
        "type": "contact",
        "uid": c["nc_uid_1"],
        "nickname": c["nc_nickname_1"] or c.get("nc_nickname_2"),
        "remark": c["nc_remark_1"] or c.get("nc_remark_2"),
        "uid_alt": c.get("nc_uid_2"),
        "action_text": c.get("nc_extra_text"),
    })


def _seg_reply(c):
    ref = c["ref_msg"] or {}
    return _clip({
        "type": "reply",
        "text": c["text"],
        "ref_msg_id": c["reply_msg_id"],
        "ref_summary": c["reply_summary"] or c["f45105"],
        "ref_nickname": ref.get("nc_nickname_1") or c["nc_nickname_1"],
        "ref_text": ref.get("text"),
    })


def _seg_forward(c):
    meta = {}
    if c["fwd_meta"]:
        try:
            meta = json.loads(c["fwd_meta"])
        except Exception:
            meta = {"raw": c["fwd_meta"]}
    return _clip({"type": "forward", "meta": meta, "uuid": c["fwd_uuid"], "token": c["fwd_token"]})


def _seg_legacy_forward(c):
    return _clip({
        "type": "legacy_forward",
        "resid": c["legacy_fwd_resid"],
        "uuid": c["legacy_fwd_uuid"],
        "xml": c["legacy_fwd_xml"],
    })


def _seg_call(c):
    return _clip({
        "type": "call",
        "call_type": c["call_type"],
        "duration": c["call_duration"],
        "desc": c["call_desc"],
    })


def _seg_sys(c):
    return _clip({"type": "sys", "sub_type": c["sys_f80810"], "text": c["sys_content"]})


def segment_of(c):
    ct = c["content_type"]
    if ct == 7 and (c["reply_msg_seq"] or c["reply_msg_id"]):
        return _clip({"type": "reply_ref", "ref_msg_seq": c["reply_msg_seq"],
                      "ref_msg_id": c["reply_msg_id"], "ref_msg_time": c["reply_msg_time"]})
    if ct == 1 and (c["text"] or "") != "":
        return _seg_text(c)
    if ct == 2:
        if (c["img_width"] or 0) > 0 or (c["img_height"] or 0) > 0:
            return _seg_image(c)
        if (c["f45415"] or 0) > 0 or (c["video_flag"] or 0) > 0:
            return _seg_video(c)
        if c["sticker_hex"]:
            return _seg_sticker(c)
        return _seg_text(c)
    if ct == 3:
        return _seg_file(c)
    if ct == 6 or ct == 8:
        # 仅携带 media_sub / video_flag 的媒体占位（无文件名与 CDN 信息）
        return _clip({"type": "media_placeholder", "content_type": ct,
                      "media_sub": c["media_sub"], "video_flag": c["video_flag"]})
    if ct == 5 or c["sticker_hex"]:
        return _seg_sticker(c)
    if ct == 9:
        return _seg_video(c)
    if ct == 16:
        return _seg_legacy_forward(c)
    if c["text"]:
        return _seg_text(c)
    return _clip({"type": "unknown", "content_type": ct})


def build_content(msg_type, contents):
    if not contents:
        return None
    c0 = contents[0]
    if msg_type == 2:
        if len(contents) == 1:
            return segment_of(c0)
        segs = [segment_of(c) for c in contents]
        return {"type": "mixed", "segments": segs}
    if msg_type == 9:
        # 引用/@ 提醒型：首段为被引用消息定位，其余为正文文本段
        ref = next((c for c in contents if c["content_type"] == 7), None)
        text = "".join(c["text"] for c in contents if c["text"]) or None
        return _clip({
            "type": "reply",
            "text": text,
            "ref_msg_seq": ref["reply_msg_seq"] if ref else None,
            "ref_msg_time": ref["reply_msg_time"] if ref else None,
        })
    if msg_type == 3:
        return _seg_file(c0)
    if msg_type == 5:
        if c0["ref_msg"] or c0["reply_msg_id"]:
            return _seg_reply(c0)
        if c0["nc_uid_1"]:
            return _seg_contact(c0)
        return _seg_sticker(c0) if c0["sticker_hex"] else _clip({"type": "unknown", "content_type": 5})
    if msg_type == 6:
        return _seg_contact(c0)
    if msg_type == 7:
        return _seg_video(c0)
    if msg_type == 8:
        return _seg_legacy_forward(c0)
    if msg_type == 11:
        return _seg_forward(c0)
    if msg_type == 17:
        return _seg_sys(c0)
    if msg_type == 19:
        return _seg_call(c0)
    if msg_type == 31 or c0["rich_text"]:
        return _clip({"type": "rich_media", "text": c0["rich_text"], "markdown": c0["rich_markdown"]})
    if c0["text"]:
        return _seg_text(c0)
    return _clip({"type": "unknown", "msg_type": msg_type, "content_type": c0["content_type"]})


def content_preview(content):
    """TXT 展示用的单行摘要。"""
    if not content:
        return ""
    t = content.get("type")
    if t == "text":
        return content.get("text", "")
    if t == "image":
        return "[图片] %s" % (content.get("filename") or content.get("text_fallback") or "")
    if t == "video":
        return "[视频] %s" % (content.get("filename") or "")
    if t == "file":
        return "[文件] %s (%s)" % (content.get("filename") or "", content.get("filesize") or 0)
    if t == "sticker":
        return "[表情] %s" % (content.get("text_fallback") or "")
    if t == "reply":
        return "[引用] %s" % (content.get("text") or content.get("ref_summary") or "")
    if t == "reply_ref":
        return "[引用定位] seq=%s" % content.get("ref_msg_seq")
    if t == "forward":
        return "[合并转发]"
    if t == "legacy_forward":
        return "[转发消息]"
    if t == "call":
        return "[通话] %s" % (content.get("desc") or "")
    if t == "contact":
        name = content.get("nickname") or content.get("remark")
        return "[名片] %s" % (name or content.get("uid") or "未知")
    if t == "sys":
        return "[系统] %s" % (content.get("text") or "")
    if t == "media_placeholder":
        return "[媒体占位] content_type=%s media_sub=%s video_flag=%s" % (
            content.get("content_type"), content.get("media_sub"), content.get("video_flag"))
    if t == "rich_media":
        return "[富媒体] %s" % (content.get("text") or "")
    if t == "mixed":
        return " | ".join(content_preview(s) for s in content.get("segments", []))
    return "[%s]" % t


# ─────────────────────────── 文件名/时间 辅助 ───────────────────────────

SAFE = re.compile(r"[^0-9A-Za-z_.\-]")
UNSAFE_FS = re.compile(r'[\\/:*?"<>|\x00-\x1f]')


def safe_name(s):
    """会话 id -> 合法文件名（保留字母数字 _ . - ，其余替换为 _ ，最长 80 字符）。"""
    return SAFE.sub("_", str(s))[:80]


def safe_display_name(s, max_len=80):
    """昵称/群名 -> 合法文件名：仅替换 Windows 非法字符与控制符，保留中文/emoji/空格。"""
    s = UNSAFE_FS.sub("_", str(s)).strip().rstrip(". ")
    return s[:max_len]


def fmt_ts(ts):
    """unix 秒 -> 'YYYY-MM-DD HH:MM:SS'；无效值返回 '时间未知'。"""
    if not ts or ts <= 0:
        return "时间未知"
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
