# qq-nt-export

[English](README_EN.md) | 简体中文

**NTQQ（QQ 9.x / QQNT）Windows 本地聊天记录解密与导出工具** —— 纯外部只读实现：内存扫描提取 SQLCipher 密钥 → 解密消息库 → 导出可读 TXT 与结构化 JSON。不注入、不 Hook、不修改 QQ 任何文件。

> ⚠️ **仅供学习研究与个人数据备份使用**。请勿用于获取他人聊天记录等侵犯隐私的用途，使用本工具产生的一切法律责任由使用者自行承担。

---

## 功能特性

- **密钥提取**：外部只读扫描 QQ 进程内存，用正则匹配凭据特征串，并以目标数据库文件头的盐值做交叉验证（防止误取其它库的密钥）。一次扫描可获得 `nt_db` 目录下**全部数据库**的凭据。
- **数据库解密**：处理 NTQQ 的 1024 字节自定义头 + SQLCipher（`cipher_page_size=4096`、`kdf_iter=4000`、`HMAC_SHA1`、`PBKDF2-HMAC-SHA512`）组合加密；自动探测多种密钥形态，命中后记住最优形态；`sqlcipher_export` 产出标准明文 SQLite，`integrity_check` 全量校验。
- **辅助库昵称回填**：可一并解密 `group_info.db`（群成员/群名片/群名）与 `profile_info.db`（好友昵称），把导出结果中的 uid / 裸 QQ 号回填为可读昵称。
- **全量 / 指定导出**：支持全量导出所有会话，也可按 **QQ 号 / 群号 / uid** 指定导出（可多选）。
- **可读命名**：文件名格式为 `名称_QQ号`（群聊 `群名_群号`、单聊 `昵称_对方QQ号`），中文与 emoji 完整保留，重名自动加序号。
- **消息解析**：内置极简 Protobuf wire 解码器（不依赖 protobuf 库），支持文本 / 图片 / 视频 / 文件 / 引用回复 / 合并转发 / 名片 / 通话记录 / 富文本混排等类型；未知类型降级保留，不中断导出。
- **工程化三件套**：`selftest.py` 自检（快检 + 深检，退出码 = 失败项数）、踩坑记录、变更日志，环境变化时能快速定位问题。

## 工作原理

```
QQ.exe 进程内存 ──(只读扫描)──► 密钥+盐值（盐值与库文件头交叉验证）
                                     │
nt_msg.db (+wal) ──备份──► 剥离 1024 字节自定义头 ──► SQLCipher 解密（多形态探测）
                                     │
                        sqlcipher_export → 明文 SQLite（integrity_check=ok）
                                     │
   group_info.db / profile_info.db ─┴─► 解析导出 ──► json/*.json + txt/*.txt + sessions_index.json
```

关键实测事实（QQ 9.9.35 实测，更新后可能变化）：

1. `nt_msg.db` 在 SQLCipher 数据区前有 **1024 字节非标准头**，必须先剥离；
2. 登录后凭据以 `x'<64位hex密钥><32位hex盐>'` 形式驻留 QQ 主进程内存；
3. 密钥形态为 **raw 32 字节 hex + 盐值直拼**，且必须显式设置 `cipher_hmac_algorithm = HMAC_SHA1`（默认 SHA512 打不开）；
4. 消息表为 `c2c_msg_table` / `group_msg_table`，列名是数字字符串（`40001`=msg_id、`40050`=时间戳、`40800`=正文 protobuf 等）；
5. 最新消息可能在 `-wal` 中未 checkpoint，**备份必须连同 `-wal` 一起拷贝**。

## 环境要求

- Windows 10/11（Win32 API 内存扫描）
- Python 3.10+（3.13 实测通过）
- 依赖：`sqlcipher3-wheels`、`pycryptodome`、`zstandard`
- QQ（NTQQ）已登录且正在运行（仅密钥扫描需要；解密/导出用副本即可）

```bash
pip install sqlcipher3-wheels pycryptodome zstandard
```

> 国内网络 `pip` 安装 `sqlcipher3-wheels` 失败时，可从清华镜像索引页直接下载对应版本的 `.whl` 后本地安装。

## 快速开始

1. 把 `config.example.json` 复制为 `config.json`，填写数据库路径等信息（密钥/盐可先留空）；
2. 依次执行：

```bash
# 0) 提取密钥（QQ 必须处于登录运行状态；命中后自动回写 config.json）
python scripts/ntqq_key_scan.py

# 1) 解密主库（只读源库，产物在 work_dir）
python scripts/ntqq_decrypt.py

# 1.5)（推荐）解密辅助库，提升昵称/群名覆盖率
python scripts/ntqq_aux_decrypt.py

# 2) 导出全部会话
python scripts/ntqq_export.py

# 3) 校验导出结果
python scripts/ntqq_verify.py

# 4) 自检
python selftest.py            # 快检
python selftest.py --deep     # 含明文库与导出产物检查
```

### 指定会话导出

```bash
python scripts/ntqq_export.py --only 123456789             # 单聊：对方 QQ 号
python scripts/ntqq_export.py --only 987654321             # 群聊：群号
python scripts/ntqq_export.py --only 987654321 123456789   # 可多个，混合指定
```

- 数字自动识别为群号和/或单聊 QQ 号（同一数字两者都命中时都导出）；`u_` 开头识别为单聊 uid；
- 未指定输出目录时写入 `output/filter_<条件>/`，不覆盖全量导出；
- 条件全部未命中时报错并返回退出码 1，不产生半成品。

## 输出说明

```
output/
├─ json/                          # 结构化消息（每会话一个文件）
│   ├─ 群名_群号.json
│   └─ 昵称_对方QQ号.json
├─ txt/                           # 可读转录（每会话一个文件）
├─ sessions_index.json            # 会话清单：条数/时间范围/文件名映射/回填统计
├─ verify_report.json             # 校验报告
└─ nt_msg_plain_schema.sql        # 明文库表结构快照
```

- 每条消息含 `msg_id / time / direction / sender_uid / sender_qq / sender_name（含回填来源 sender_name_src）/ msg_type / content_type / text / content`；
- `content` 为统一结构：`text / image / video / file / reply / forward / contact / call / mixed / ...`，媒体类带文件名、大小、md5 等元信息（仅元信息，不下载媒体文件）；
- 单条 JSON 样例：

```json
{
  "msg_id": 7637455716438164227,
  "time": "2026-05-08 17:14:26",
  "direction": 0,
  "sender_name": "某某",
  "sender_name_src": "member_nick",
  "content_type": "text",
  "text": "你好",
  "content": {"type": "text", "text": "你好"}
}
```

## 配置说明（config.json）

| 字段 | 说明 |
|---|---|
| `db_path` / `db_path_candidates` | `nt_msg.db` 路径与候选列表（自动探测） |
| `data_key` / `salt` | 密钥与盐值（**敏感**，由 `ntqq_key_scan.py` 自动回写） |
| `key_variant` | 实测命中的密钥形态，探测时优先尝试 |
| `work_dir` | 副本/明文库等中间产物目录 |
| `output_dir` | 导出产物目录 |
| `self_uid` / `self_qq` | 本人标识（用于单聊方向判定，可留空） |

## 安全与法律提示

- `config.json`、`work_dir`、`output_dir` 中含**明文密钥与私密聊天内容**，严禁提交仓库或外传（发布包已含 `.gitignore` 兜底）；
- 全流程对 QQ 数据**只读**：备份在副本上解密，绝不写源库；
- 仅限备份**本人**设备上的数据；用于其他目的可能违反当地法律法规。

## 已知限制

- 已退群且从未在任何消息中带过昵称的发言人仍显示为 uid/QQ 号（约占总量 20%）；
- 媒体文件仅导出元信息，不下载文件体；
- 极少数 `unknown` 类型仅保留类型号；
- QQ 大版本更新可能改变密钥形态或列语义，重跑 `ntqq_key_scan.py` 并按自检提示排查。

## 致谢

- [NapNeko/qq_dump_db](https://github.com/NapNeko/qq_dump_db) —— 密钥内存驻留形态的公开描述
- [QQBackup/nt_msg_db_util](https://github.com/QQBackup/nt_msg_db_util) —— 解密参数与表结构参考
- 本项目工程范式（自检/踩坑库/变更日志）参照自一个微信 4.x 导出技能的内部实现

## License

[MIT](LICENSE)
