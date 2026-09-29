# -*- coding: utf-8 -*-
"""
NTQQ 内存密钥扫描（只读 / 无注入 / 无 Hook）

原理（参照 NapNeko/qq_dump_db 公开描述）：
  NTQQ 登录后，SQLCipher 凭据以特征串 x'<64hex_key><32hex_salt>' 形式驻留 QQ 进程内存。
  本脚本用 OpenProcess + VirtualQueryEx + ReadProcessMemory 外部只读遍历可读内存区，
  正则匹配该特征串；再用 nt_msg.db 文件头中的盐值交叉验证
  （SQLCipher salt = 剥离 1024 字节自定义头后 page1 的前 16 字节），盐值一致即为本库确认凭据。

不修改 QQ 任何文件、不写 QQ 内存、不注入、不 Hook。

用法:
  python ntqq_key_scan.py [--src-db PATH] [--pid N] [--json-out PATH] [--no-write-config]

退出码: 0 命中 / 1 未命中或异常
注意: QQ 必须处于登录运行状态；结果 JSON 含明文密钥，属敏感信息，勿外传。
"""
import argparse
import ctypes
from ctypes import wintypes as wt
import json
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL_DIR = os.path.dirname(HERE)
CONFIG_PATH = os.path.join(SKILL_DIR, "config.json")

DEFAULT_HEADER_SIZE = 1024

TH32CS_SNAPPROCESS = 0x00000002
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
PAGE_GUARD = 0x100
PAGE_READABLE = {0x02, 0x04, 0x20, 0x40}
CHUNK = 16 << 20  # 16MB

PAT_FULL = re.compile(rb"x'([0-9a-fA-F]{64})([0-9a-fA-F]{32})'?")   # key + salt
PAT_KEYONLY = re.compile(rb"x'([0-9a-fA-F]{32})'")                  # 纯 key（16 字节 hex）
PAT_ASCII16 = re.compile(rb"[ -~]{16}")                             # 备选形态样本

k32 = ctypes.WinDLL("kernel32", use_last_error=True)


class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD), ("cntUsage", wt.DWORD), ("th32ProcessID", wt.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)), ("th32ModuleID", wt.DWORD),
        ("cntThreads", wt.DWORD), ("th32ParentProcessID", wt.DWORD),
        ("pcPriClassBase", ctypes.c_long), ("dwFlags", wt.DWORD),
        ("szExeFile", ctypes.c_char * 260),
    ]


class MEMORY_BASIC_INFORMATION64(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_ulonglong), ("AllocationBase", ctypes.c_ulonglong),
        ("AllocationProtect", wt.DWORD), ("__alignment1", wt.DWORD),
        ("RegionSize", ctypes.c_ulonglong), ("State", wt.DWORD), ("Protect", wt.DWORD),
        ("Type", wt.DWORD), ("__alignment2", wt.DWORD),
    ]


k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k32.OpenProcess.restype = wt.HANDLE
k32.CloseHandle.argtypes = [wt.HANDLE]
k32.VirtualQueryEx.argtypes = [wt.HANDLE, ctypes.c_ulonglong,
                               ctypes.POINTER(MEMORY_BASIC_INFORMATION64), ctypes.c_size_t]
k32.VirtualQueryEx.restype = ctypes.c_size_t
k32.ReadProcessMemory.argtypes = [wt.HANDLE, ctypes.c_ulonglong, ctypes.c_void_p,
                                  ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.ReadProcessMemory.restype = wt.BOOL
k32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
k32.CreateToolhelp32Snapshot.restype = wt.HANDLE
k32.Process32First.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESSENTRY32)]
k32.Process32Next.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESSENTRY32)]


def enum_pids(exe_name="qq.exe"):
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    pids = []
    if snap == wt.HANDLE(-1).value or not snap:
        return pids
    pe = PROCESSENTRY32()
    pe.dwSize = ctypes.sizeof(pe)
    ok = k32.Process32First(snap, ctypes.byref(pe))
    while ok:
        if pe.szExeFile.decode("mbcs", "ignore").lower() == exe_name:
            pids.append(int(pe.th32ProcessID))
        ok = k32.Process32Next(snap, ctypes.byref(pe))
    k32.CloseHandle(snap)
    return pids


def read_salt(db_path, header_size=DEFAULT_HEADER_SIZE):
    with open(db_path, "rb") as f:
        f.seek(header_size)
        return f.read(16)


def scan_pid(pid, salt_hex, ascii_samples):
    h = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not h:
        return {"pid": pid, "error": "OpenProcess failed err=%d" % ctypes.get_last_error(),
                "hits": [], "bytes_read": 0}
    mbi = MEMORY_BASIC_INFORMATION64()
    addr, hits, scanned, t0 = 0, [], 0, time.time()
    while k32.VirtualQueryEx(h, addr, ctypes.byref(mbi), ctypes.sizeof(mbi)):
        base, size = int(mbi.BaseAddress), int(mbi.RegionSize)
        if size <= 0:
            break
        prot = mbi.Protect & 0xFF
        if mbi.State == MEM_COMMIT and prot in PAGE_READABLE and not (mbi.Protect & PAGE_GUARD):
            off = 0
            while off < size:
                n_bytes = min(size - off, CHUNK)
                buf = ctypes.create_string_buffer(n_bytes)
                got = ctypes.c_size_t(0)
                if k32.ReadProcessMemory(h, base + off, buf, n_bytes, ctypes.byref(got)) and got.value:
                    data = buf.raw[:got.value]
                    scanned += got.value
                    for m in PAT_FULL.finditer(data):
                        hits.append({
                            "kind": "key+salt", "address": hex(base + off + m.start()),
                            "key_hex": m.group(1).decode(),
                            "salt_hex": m.group(2).decode(),
                            "salt_match": m.group(2).decode().lower() == salt_hex,
                        })
                    for m in PAT_KEYONLY.finditer(data):
                        hits.append({
                            "kind": "key_only", "address": hex(base + off + m.start()),
                            "key_hex": m.group(1).decode(), "salt_hex": None,
                            "salt_match": False,
                        })
                    if len(ascii_samples) < 40:
                        for m in PAT_ASCII16.finditer(data):
                            s = m.group(0).decode("ascii", "ignore")
                            if s not in ascii_samples:
                                ascii_samples.append(s)
                            if len(ascii_samples) >= 40:
                                break
                off += n_bytes
        nxt = base + size
        if nxt <= addr:
            break
        addr = nxt
    k32.CloseHandle(h)
    return {"pid": pid, "hits": hits, "bytes_read": scanned,
            "seconds": round(time.time() - t0, 1)}


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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src-db", default=None, help="nt_msg.db 路径（默认取 config.json）")
    ap.add_argument("--pid", type=int, default=0, help="只扫指定 pid（默认为全部 QQ.exe）")
    ap.add_argument("--json-out", default=None, help="扫描结果 JSON 路径（默认 <work_dir>/ntqq_key_scan.json）")
    ap.add_argument("--no-write-config", action="store_true", help="命中后不回写 config.json")
    args = ap.parse_args()

    cfg = load_config()
    db_path = resolve_db_path(cfg, args.src_db)
    if not db_path:
        print("[X] 找不到 nt_msg.db（检查 config.json 的 db_path / db_path_candidates）")
        print("[RESULT] %s" % json.dumps({"ok": False, "error": "db_path not found"}, ensure_ascii=False))
        return 1

    header = cfg.get("header_size", DEFAULT_HEADER_SIZE)
    salt = read_salt(db_path, header)
    salt_hex = salt.hex()
    pids = [args.pid] if args.pid else enum_pids()
    print("[*] QQ.exe pids: %s" % pids)
    print("[*] 库: %s" % db_path)
    print("[*] salt(bytes%d-%d): %s" % (header, header + 16, salt_hex))
    if not pids:
        print("[X] 未发现 QQ.exe 进程：请先启动并登录 QQ")
        print("[RESULT] %s" % json.dumps({"ok": False, "error": "QQ.exe not running"}, ensure_ascii=False))
        return 1

    results, ascii_samples = [], []
    for pid in pids:
        r = scan_pid(pid, salt_hex, ascii_samples)
        print("[*] pid=%s read=%.1fMB hits=%d %s" % (
            pid, r.get("bytes_read", 0) / 1048576.0, len(r.get("hits", [])),
            ("ERR:" + r["error"]) if r.get("error") else ""))
        results.append(r)

    confirmed = []
    for r in results:
        for h in r.get("hits", []):
            h["pid"] = r["pid"]
            if h.get("salt_match"):
                confirmed.append(h)

    out_path = args.json_out or os.path.join(cfg.get("work_dir") or os.path.join(SKILL_DIR, ".work"),
                                             "ntqq_key_scan.json")
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    out = {
        "db_path": db_path,
        "salt_hex": salt_hex,
        "scanned_pids": pids,
        "confirmed": confirmed,
        "all_hits": [h for r in results for h in r.get("hits", [])],
        "ascii16_samples": ascii_samples,
        "scan_stats": [{k: v for k, v in r.items() if k != "hits"} for r in results],
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print("[*] 命中(密钥+盐一致): %d / 总命中 %d" % (len(confirmed), len(out["all_hits"])))
    for c in confirmed[:5]:
        print("    pid=%s addr=%s key=%s…%s salt=%s" % (
            c["pid"], c["address"], c["key_hex"][:8], c["key_hex"][-6:], c["salt_hex"]))
    print("[*] 落盘: %s（含明文密钥，勿外传）" % os.path.abspath(out_path))

    wrote_config = False
    if confirmed and not args.no_write_config:
        try:
            cfg["data_key"] = confirmed[0]["key_hex"].lower()
            cfg["salt"] = confirmed[0]["salt_hex"].lower()
            with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump(cfg, f, ensure_ascii=False, indent=2)
            wrote_config = True
            print("[*] 已回写 config.json 的 data_key / salt")
        except Exception as e:
            print("[!] 回写 config.json 失败: %s" % e)

    print("[RESULT] %s" % json.dumps({
        "ok": bool(confirmed), "confirmed": len(confirmed), "total_hits": len(out["all_hits"]),
        "salt_hex": salt_hex, "key_hex": confirmed[0]["key_hex"].lower() if confirmed else None,
        "config_updated": wrote_config, "scan_json": os.path.abspath(out_path),
    }, ensure_ascii=False))
    return 0 if confirmed else 1


if __name__ == "__main__":
    sys.exit(main())
