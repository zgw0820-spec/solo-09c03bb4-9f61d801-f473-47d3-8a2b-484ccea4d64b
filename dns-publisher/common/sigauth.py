"""发布链路的请求签名与防重放（管理端与 DNS 节点共用）。

签名方案
--------
HMAC-SHA256，密钥按节点分发：管理端持有全部节点密钥（``NODE_KEYS``），
每个节点只持有自己的密钥（``NODE_KEY``）。被签名的规范串为紧凑 JSON 数组，
按**用途**绑定不同字段：

* ``publish``:   ``["v1","publish",node_id,revision,domain,addresses_sha256,ts,nonce]``
* ``heartbeat``: ``["v1","heartbeat",node_id,served_revision,ts,nonce]``
* ``report``:    ``["v1","report",node_id,served_revision,ts,nonce]``

由此获得以下性质：

* **绑定节点身份**：签名内含 node_id，且每个节点密钥不同 —— 给 node-a 的
  签名请求发给 node-b 无法通过校验（跨节点复用拒绝）。
* **绑定操作用途**：heartbeat 的签名不能冒充 publish，反之亦然。
* **绑定修订与完整地址组**：publish 签名覆盖修订号与整个地址列表的哈希，
  篡改任一地址即失效。
* **时效**：时间戳偏差超过 ``ttl`` 秒的请求被拒绝。
* **防重放**：nonce 经 SQLite 持久化去重（``seen_nonces`` 表），消费记录
  与业务状态在同事务内提交，**重启之后重放依然被拒绝**。
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
import time

SIG_VERSION = "v1"
PURPOSE_PUBLISH = "publish"
PURPOSE_HEARTBEAT = "heartbeat"
PURPOSE_REPORT = "report"

HEADER_NODE = "X-Sig-Node"
HEADER_TS = "X-Sig-Ts"
HEADER_NONCE = "X-Sig-Nonce"
HEADER_SIGNATURE = "X-Signature"

DEFAULT_TTL_SECONDS = 300.0
# 已消费 nonce 的保留时长 = 时效窗口 + 宽限；超出时效窗口的时间戳本来就会被拒。
REPLAY_GRACE_SECONDS = 120.0

REPLAY_TABLE_DDL = """
CREATE TABLE IF NOT EXISTS seen_nonces (
    purpose TEXT NOT NULL,
    nonce   TEXT NOT NULL,
    ts      REAL NOT NULL,
    PRIMARY KEY (purpose, nonce)
);
"""


class AuthError(Exception):
    """签名/时效/身份校验失败。message 可安全返回给调用方。"""


def addresses_hash(addresses: list[str]) -> str:
    """完整地址组的规范哈希：内容与顺序任一不同即不同。"""
    canonical = json.dumps(list(addresses), separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _canonical(fields: list) -> bytes:
    return json.dumps(fields, separators=(",", ":")).encode("ascii")


def _hmac_hex(key: str, fields: list) -> str:
    return hmac.new(key.encode("utf-8"), _canonical(fields), hashlib.sha256).hexdigest()


def new_nonce() -> str:
    return secrets.token_hex(16)


def now_ts() -> int:
    return int(time.time())


# --------------------------------------------------------------------------- #
# 签名构造
# --------------------------------------------------------------------------- #
def sign_publish(key: str, node_id: str, revision: int, domain: str,
                 addresses: list[str], ts: int, nonce: str) -> str:
    return _hmac_hex(key, [SIG_VERSION, PURPOSE_PUBLISH, node_id, int(revision),
                           domain, addresses_hash(addresses), int(ts), nonce])


def sign_report(key: str, purpose: str, node_id: str, served_revision: int,
                ts: int, nonce: str) -> str:
    if purpose not in (PURPOSE_HEARTBEAT, PURPOSE_REPORT):
        raise ValueError(f"bad report purpose {purpose!r}")
    return _hmac_hex(key, [SIG_VERSION, purpose, node_id, int(served_revision),
                           int(ts), nonce])


def publish_headers(key: str, node_id: str, revision: int, domain: str,
                    addresses: list[str]) -> dict[str, str]:
    """管理端下发用的完整签名头（每次调用生成新时间戳与新 nonce）。"""
    ts, nonce = now_ts(), new_nonce()
    return {
        HEADER_NODE: node_id,
        HEADER_TS: str(ts),
        HEADER_NONCE: nonce,
        HEADER_SIGNATURE: sign_publish(key, node_id, revision, domain,
                                       addresses, ts, nonce),
    }


def report_headers(key: str, purpose: str, node_id: str,
                   served_revision: int) -> dict[str, str]:
    """节点回传（心跳/已服务版本上报）用的完整签名头。"""
    ts, nonce = now_ts(), new_nonce()
    return {
        HEADER_NODE: node_id,
        HEADER_TS: str(ts),
        HEADER_NONCE: nonce,
        HEADER_SIGNATURE: sign_report(key, purpose, node_id,
                                      served_revision, ts, nonce),
    }


# --------------------------------------------------------------------------- #
# 校验
# --------------------------------------------------------------------------- #
def check_freshness(ts: int, ttl: float) -> None:
    skew = abs(time.time() - ts)
    if skew > ttl:
        raise AuthError(f"签名时间戳超出时效窗口（偏差 {skew:.0f}s > {ttl:.0f}s）")


def verify_publish_signature(key: str, expected_node_id: str, hdr_node: str,
                             ts: int, nonce: str, signature: str,
                             revision: int, domain: str,
                             addresses: list[str], ttl: float) -> None:
    """节点侧校验管理端下发：身份、时效、签名（绑定修订与完整地址组）。"""
    if hdr_node != expected_node_id:
        raise AuthError(
            f"签名绑定节点 {hdr_node!r}，本节点为 {expected_node_id!r}，跨节点复用拒绝")
    check_freshness(ts, ttl)
    expected = sign_publish(key, expected_node_id, revision, domain,
                            addresses, ts, nonce)
    if not hmac.compare_digest(expected, signature or ""):
        raise AuthError("签名校验失败")


def verify_report_signature(key: str, purpose: str, expected_node_id: str,
                            hdr_node: str, ts: int, nonce: str, signature: str,
                            served_revision: int, ttl: float) -> None:
    """管理端校验节点回传：身份、时效、签名（绑定已服务版本）。"""
    if purpose not in (PURPOSE_HEARTBEAT, PURPOSE_REPORT):
        raise ValueError(f"bad report purpose {purpose!r}")
    if hdr_node != expected_node_id:
        raise AuthError("签名节点身份与路径节点不一致")
    check_freshness(ts, ttl)
    expected = sign_report(key, purpose, expected_node_id,
                           served_revision, ts, nonce)
    if not hmac.compare_digest(expected, signature or ""):
        raise AuthError("签名校验失败")


# --------------------------------------------------------------------------- #
# 防重放（SQLite 持久化，随调用方事务提交）
# --------------------------------------------------------------------------- #
def consume_nonce(conn: sqlite3.Connection, purpose: str, nonce: str,
                  ts: float, ttl: float) -> bool:
    """记录并消费一个 nonce；已存在（重放）返回 False。

    表结构见 ``REPLAY_TABLE_DDL``，由调用方在建库时创建。本函数在调用方的
    事务内执行，与业务状态修改同事务提交： nonce 一旦消费，重启后重放同一
    请求依然被识别。过期条目按 ``ttl + REPLAY_GRACE_SECONDS`` 惰性清理。
    """
    horizon = time.time() - ttl - REPLAY_GRACE_SECONDS
    conn.execute("DELETE FROM seen_nonces WHERE ts < ?", (horizon,))
    cur = conn.execute(
        "INSERT OR IGNORE INTO seen_nonces(purpose, nonce, ts) VALUES (?, ?, ?)",
        (purpose, nonce, ts),
    )
    return cur.rowcount == 1
