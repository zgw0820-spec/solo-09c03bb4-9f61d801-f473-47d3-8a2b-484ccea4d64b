# 单域名 A 记录发布系统（FastAPI + SQLite + dnslib）

机房设备管理域名的 A 记录发布：管理服务生成**严格递增修订**，向两台**独立持久化**的
UDP 权威 DNS 节点整列表下发；运维以两端**实际 DNS 答复**核对一致后再安排切流。
整条发布链路带授权与防重放：运维令牌、按节点分发的 HMAC 签名（绑定用途/节点身份/
修订/完整地址组，带时间戳与持久化 nonce）。

## 架构

```
                 ┌──────────────────────────────┐
  Swagger /docs  │  mgmt (FastAPI + SQLite/WAL)  │
  POST /publishes│  修订表 / 节点状态 / 对账循环   │   ← /publishes、/reconcile 需运维令牌
                 └───────────────┬──────────────┘
        签名 HTTP /publish       │     ▲ 签名 heartbeat / report
              ┌──────────────────┴─────┴──────────────────┐
              ▼                                             ▼
     ┌─────────────────┐                           ┌─────────────────┐
     │ node-a (dnslib) │◄────── UDP A 查询 ───────►│ node-b (dnslib) │
     │ 独立 SQLite 卷   │                           │ 独立 SQLite 卷   │
     └─────────────────┘                           └─────────────────┘
        10053/udp (宿主)                               10054/udp (宿主)
```

## 安全模型（发布链路授权）

* **运维令牌**：`POST /publishes` 与 `POST /reconcile` 必须携带
  `Authorization: Bearer $OPS_TOKEN`（Swagger 右上角 Authorize 可配置）。
  未配置 `OPS_TOKEN` 时写接口拒绝服务（fail closed）。
* **管理端 → 节点下发签名**：每节点一把 HMAC-SHA256 密钥（管理端 `NODE_KEYS`
  持有全集，节点只有自己的 `NODE_KEY`）。签名串绑定用途 `publish`、节点身份、
  修订号、域名与**完整地址组哈希**，并带时间戳与随机 nonce。
* **节点 → 管理端回传签名**：心跳与已服务版本上报同样按节点密钥签名，
  绑定用途（`heartbeat`/`report`）与已服务版本号。
* **时效与防重放**：签名时间戳偏差超过 `SIG_TTL_SECONDS`（默认 300s）即拒绝；
  nonce 写入各自 SQLite 的 `seen_nonces` 表持久化去重，**重启后重放仍被拒绝**。
* 因此：未授权、过期、跨节点复用或重放的请求**不能改动节点区域**，
  也**不能伪造管理端在线状态与同步结论**（`/status` 只认带合法签名的心跳）。
* **幂等重试**：节点把每个已应用修订的内容持久化在 `applied_log`。下发已生效
  但回执丢失时，同修订同内容的重试返回 `200 already-applied`（安全确认，不动
  区域）；同修订不同内容返回 `409 content-conflict`；更旧的未知修订返回
  `409 stale-revision`。重启后行为不变。

## 数据一致性保证

* **修订递增**：每次 `POST /publishes` 在 `BEGIN IMMEDIATE` 事务内写入，
  SQLite 保留锁串行化并发请求，修订号用 AUTOINCREMENT，绝不重号/乱序。
* **只接受较新修订**：节点对更旧/冲突修订一律 409 拒绝；
  管理端节点状态用 `MAX(served, 上报值)` 钳制，迟到旧上报无法回退版本。
* **地址列表整体生效**：节点在单个事务内替换整行 zone，UDP 应答要么全旧、要么全新。
* **失联不误报**：`/status` 区分 `synced / syncing / degraded-node-offline`；
  单节点失联时另一节点继续应答，待补节点显示 `waiting-node-recovery`，
  `synced` 恒为 false；恢复后后台对账循环自动补齐。
* **实答核对**：`GET /verify` 与 `scripts/verify_dns.py` 都直接发 UDP 查询，
  以两端真实答复比对最新修订，而不是只看控制面状态。

## 启动（Docker Compose）

```bash
docker compose up -d --build
# Swagger（Authorize 里填入 OPS_TOKEN，默认开发值 dev-ops-token-change-me）:
open http://localhost:8000/docs
```

发布与核对：

```bash
curl -X POST http://localhost:8000/publishes \
  -H "Authorization: Bearer dev-ops-token-change-me" \
  -H 'Content-Type: application/json' \
  -d '{"addresses":["10.10.1.11","10.10.1.12"]}'
curl http://localhost:8000/status
curl http://localhost:8000/verify

# 运维侧直接核对两端 UDP 实答（切流前必做）
python scripts/verify_dns.py device.example.internal 127.0.0.1:10053 127.0.0.1:10054
```

## 配置（环境变量）

| 变量 | 服务 | 说明 |
| --- | --- | --- |
| `OPS_TOKEN` | mgmt | 运维令牌（Bearer）。**生产必须替换默认值** |
| `NODE_KEYS` | mgmt | JSON：`{"node-a":"key-a",...}`，每节点一把 HMAC 密钥 |
| `NODE_KEY` | node | 本节点的 HMAC 密钥，与 `NODE_KEYS` 中对应项一致 |
| `SIG_TTL_SECONDS` | 双方 | 签名时间戳允许偏差，默认 300 |
| `MANAGED_DOMAIN` / `NODES` / `RECONCILE_INTERVAL` / `OFFLINE_AFTER_SECONDS` | mgmt | 业务配置 |
| `UDP_PORT` / `HTTP_PORT` / `HEARTBEAT_INTERVAL` / `MGMT_BASE_URL` | node | 业务配置 |

Compose 内置的是**开发用默认口令**，生产部署务必替换并保密分发。

## API 摘要

| 方法 | 路径 | 鉴权 | 说明 |
| --- | --- | --- | --- |
| POST | `/publishes` | 运维令牌 | 提交完整地址列表，生成新修订（201） |
| GET  | `/status` | 无（只读） | 最新修订、各节点在线状态/已服务版本/待补状态、总体结论 |
| GET  | `/verify` | 无（只读） | 用两端实际 UDP DNS 答复核对最新修订 |
| GET  | `/revisions` | 无（只读） | 修订历史 |
| POST | `/reconcile` | 运维令牌 | 手动触发一次对账下发 |
| POST | `/internal/nodes/{id}/heartbeat` | 节点 HMAC 签名 | 节点心跳（在线判定依据） |
| POST | `/internal/nodes/{id}/report` | 节点 HMAC 签名 | 节点已服务版本上报 |
| GET  | `/docs` | 无 | Swagger UI |

## 本地无 Docker 自测

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python scripts/selftest.py
```

自测覆盖：发布同步与实答一致、单节点失联（不误报）、恢复补齐、
迟到旧修订 409 拒绝、并发发布修订连续、**授权与伪造防护**（无令牌/错令牌/
无签名/错密钥/过期时间戳/跨用途/跨节点复用/重放 nonce 全部拒绝且区域与
管理端结论不变）、**幂等重试**（同修订同内容安全确认、内容冲突 409）、
**重启持久化**（节点区域与防重放记录、管理端修订与 nonce 记录重启后仍有效）、
输入校验。

