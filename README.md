# Seabed Observatory Checkpoint Transparency Log

岸基值班员用来核验海底观测站日志历史没有被向不同观察者隐藏或改写的
签名检查点服务。每个日志维护一棵 RFC 9162（原 RFC 6962）Merkle 树，
检查点由 Ed25519 私钥对**规定的原始二进制消息**（而非 JSON）签名；
服务端只接受通过一致性证明确认为"旧树是新树前缀"的推进，并永久封存
同尺寸分叉证据。

整个服务只依赖 Python 3.11 标准库（含一份可审计的纯 Python Ed25519
实现，已用 RFC 8032 向量与 OpenSSL CLI 交叉验证），镜像构建无需访问
任何包索引。

## 快速开始

```bash
# 在可配置宿主端口启动 API（默认 8080）
docker compose up -d --build api
PORT=18080 docker compose up -d api        # 自定义宿主端口

curl -s http://localhost:8080/healthz

# 容器内验收：首次检查点 / 合法扩展 / 伪造扩展 HTTP 冒烟，
# 穿插证明算法测试、镜像构建检查与重启持久化检查，退出码即裁决
docker compose run --rm verify
echo "acceptance exit: $?"
```

## API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET`  | `/healthz` | 健康检查 |
| `POST` | `/logs/{logId}/checkpoints` | 提交签名检查点 |
| `GET`  | `/logs/{logId}` | 可信树大小、根哈希、状态（`active`/`forked`） |
| `GET`  | `/logs/{logId}/forks` | 已封存分叉证据列表 |
| `GET`  | `/logs/{logId}/forks/{forkId}` | 单条分叉证据 |
| `GET`  | `/logs/{logId}/history` | 仅追加的已发布头历史 |

`logId` 为 1–128 字符 ASCII：`[A-Za-z0-9][A-Za-z0-9_.-]*`。
所有二进制字段使用标准 Base64。

### 请求体

```json
{
  "tree_size": 7,
  "timestamp_ms": 1780000060000,
  "root_hash": "<base64, 32 bytes>",
  "public_key": "<base64, 32 bytes Ed25519>",
  "signature": "<base64, 64 bytes Ed25519>",
  "consistency_proof": ["<base64 32-byte hash>", "..."]
}
```

### 被签名的原始二进制消息

签名**必须**覆盖以下大端定长字节串，JSON 转写本身不被签名：

```
SEABED-LOG-CHECKPOINT-V1\n        (25 字节魔数)
uint8   log_id 字节长度
bytes   log_id 的 ASCII 字节
uint64  tree_size        (big-endian)
uint64  timestamp_ms     (big-endian)
bytes   root_hash        (32)
bytes   public_key       (32)
```

把 `log_id` 与 `public_key` 纳入签名使签名无法跨日志或跨密钥重放。
参考 `examples/sign_and_submit.py`。

### 裁决语义

| 场景 | 结果 |
| --- | --- |
| 该日志首次有效提交 | `201 genesis`，冻结公钥，proof 必须为空 |
| 相同检查点重传（含并发） | `200 duplicate`，同一裁决，无副作用 |
| 更大树 + 合法 RFC 9162 一致性证明（旧树为新树前缀） | `201 advanced`，锁内原子推进 |
| 过期大小 | `422 stale_tree_size` |
| 空/截断/异史证明、错误根哈希 | `422 invalid_consistency_proof` |
| 无效签名（含对 JSON/非标字节签名、跨日志重放） | `422 invalid_signature` |
| 冻结密钥之外的密钥尝试扩展 | `422 public_key_mismatch` |
| 同尺寸但根/时间/密钥/签名不同的**已验签**提交 | `409 fork_detected`，封存双方证据，可信记录不改写 |

所有失败请求都不写入任何状态（无半成品）；错误体含可定位的
`error` 代码与人类可读 `message`。

## 持久化与并发

* 每个日志一个目录：`state.json`（原子 rename + fsync 替换）、
  仅追加 `history.jsonl`、`forks/*.json`、`lock`。
* 写入同时持有进程内互斥锁与 `flock(LOCK_EX)`，线程与多进程并发
  都收敛到同一裁决；提交顺序为"日志先落盘、状态再替换"，启动时
  从日志重放修复崩溃窗口，并容忍/截断末尾撕裂行。
* 重启后可信检查点与分叉记录均可查询（验收服务会真的拉起第二个
  API 进程验证这一点）。

## 目录

```
app/                 纯标准库服务（HTTP + 存储 + Merkle + Ed25519）
verify/acceptance.py 容器内验收程序（verify 服务的入口）
docker/gen_build_info.py  构建清单生成（验收会在镜像内复核摘要）
examples/            调用方签名与提交示例
Dockerfile, docker-compose.yml
```
