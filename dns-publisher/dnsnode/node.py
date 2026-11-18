"""Persistent authoritative DNS node (UDP) with a push control API.

The node owns its own SQLite database (independent persistent volume in
Compose). It answers A queries for exactly one managed domain and applies the
full address list atomically.

Control-plane security (see ``common.sigauth``):

* ``POST /publish`` only accepts pushes HMAC-signed with this node's own key
  (``NODE_KEY``). The signature binds purpose "publish", the node identity,
  the revision and the complete address set, plus a timestamp and a nonce.
  Unsigned, wrong-key, expired, cross-node or replayed pushes are rejected
  without touching the zone.
* A push with a revision **newer** than the served one is applied. A push
  with an already-seen revision is checked against the persistent
  ``applied_log``: identical content is confirmed idempotently
  (``already-applied``, HTTP 200 — safe retry after a lost receipt), while
  different content for the same revision is rejected as a conflict
  (HTTP 409). Both decisions survive node restarts.
* Heartbeats and served-revision reports back to the management service are
  signed with the node key as well.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib import request as urlrequest

from dnslib import A, QTYPE, RCODE, RR, DNSRecord

from common import sigauth

NODE_ID = os.environ.get("NODE_ID", "dns-node")
DB_PATH = os.environ.get("NODE_DB_PATH", "/data/node.db")
UDP_HOST = os.environ.get("UDP_HOST", "0.0.0.0")
UDP_PORT = int(os.environ.get("UDP_PORT", "5353"))
HTTP_HOST = os.environ.get("HTTP_HOST", "0.0.0.0")
HTTP_PORT = int(os.environ.get("HTTP_PORT", "8053"))
DNS_TTL = int(os.environ.get("DNS_TTL", "30"))
MGMT_BASE_URL = os.environ.get("MGMT_BASE_URL", "").rstrip("/")
HEARTBEAT_INTERVAL = float(os.environ.get("HEARTBEAT_INTERVAL", "5"))
# 本节点的 HMAC 密钥（管理端在 NODE_KEYS 中持有同一把）；未配置则拒绝一切下发。
NODE_KEY = os.environ.get("NODE_KEY", "")
# 签名时间戳允许的最大偏差（秒）。
SIG_TTL = float(os.environ.get("SIG_TTL_SECONDS", str(sigauth.DEFAULT_TTL_SECONDS)))

_state_lock = threading.Lock()
# In-memory mirror of the durable SQLite row; loaded at startup.
_current: dict = {"revision": 0, "domain": "", "addresses": [], "applied_at": 0.0}


# --------------------------------------------------------------------------- #
# Persistence
# --------------------------------------------------------------------------- #
def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=30, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=FULL")
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


def init_db() -> None:
    with _connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS zone (
                id           INTEGER PRIMARY KEY CHECK (id = 1),
                revision     INTEGER NOT NULL,
                domain       TEXT NOT NULL,
                addresses    TEXT NOT NULL,
                applied_at   REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS applied_log (
                revision    INTEGER PRIMARY KEY,
                domain      TEXT NOT NULL,
                addresses   TEXT NOT NULL,
                applied_at  REAL NOT NULL
            );
            """
        )
        # 下发请求的防重放 nonce 表（持久化，重启后重放仍被拒绝）
        conn.executescript(sigauth.REPLAY_TABLE_DDL)
        row = conn.execute(
            "SELECT revision, domain, addresses, applied_at FROM zone WHERE id = 1"
        ).fetchone()
        if row is not None:
            _current.update(
                revision=row["revision"],
                domain=row["domain"],
                addresses=json.loads(row["addresses"]),
                applied_at=row["applied_at"],
            )
            print(f"[node {NODE_ID}] restored revision {row['revision']} from {DB_PATH}")


def process_publish(revision: int, domain: str, addresses: list[str],
                    nonce: str, ts: int) -> tuple[int, dict]:
    """Consume the nonce and apply/confirm/reject a signed publish, atomically.

    Returns ``(http_code, body)``. All decisions are made under the state
    lock and committed in a single SQLite transaction together with the
    consumed nonce, so the behaviour is identical after a restart:

    * ``revision > served``            -> apply the whole list, 200 "applied"
    * known revision, same content     -> 200 "already-applied" (safe retry
                                          after a lost receipt; zone untouched)
    * known revision, other content    -> 409 "content-conflict"
    * unknown older revision           -> 409 "stale-revision"
    * nonce already consumed           -> 409 "replay-nonce"
    """
    with _state_lock:
        conn = _connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            if not sigauth.consume_nonce(conn, sigauth.PURPOSE_PUBLISH,
                                         nonce, ts, SIG_TTL):
                conn.execute("COMMIT")
                return 409, {"status": "rejected", "reason": "replay-nonce",
                             "served_revision": _current["revision"]}

            current = _current["revision"]
            if revision > current:
                now = time.time()
                payload = json.dumps(addresses)
                conn.execute(
                    "INSERT INTO zone(id, revision, domain, addresses, applied_at) "
                    "VALUES (1, ?, ?, ?, ?) "
                    "ON CONFLICT(id) DO UPDATE SET "
                    "revision=excluded.revision, domain=excluded.domain, "
                    "addresses=excluded.addresses, applied_at=excluded.applied_at",
                    (revision, domain, payload, now),
                )
                conn.execute(
                    "INSERT OR IGNORE INTO applied_log"
                    "(revision, domain, addresses, applied_at) VALUES (?, ?, ?, ?)",
                    (revision, domain, payload, now),
                )
                conn.execute("COMMIT")
                _current.update(
                    revision=revision, domain=domain,
                    addresses=list(addresses), applied_at=now,
                )
                print(f"[node {NODE_ID}] applied revision {revision}: "
                      f"{domain} -> {addresses}")
                return 200, {"status": "applied", "served_revision": revision}

            # revision <= current: consult the persistent applied log.
            row = conn.execute(
                "SELECT domain, addresses FROM applied_log WHERE revision = ?",
                (revision,),
            ).fetchone()
            conn.execute("COMMIT")
            if (
                row is not None
                and row["domain"] == domain
                and json.loads(row["addresses"]) == list(addresses)
            ):
                # 同修订同内容：回执丢失后的安全重试，幂等确认，不动 zone。
                return 200, {"status": "already-applied",
                             "served_revision": current}
            reason = "content-conflict" if row is not None else "stale-revision"
            return 409, {"status": "rejected", "reason": reason,
                         "served_revision": current}
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()


def snapshot() -> dict:
    with _state_lock:
        return dict(_current)


# --------------------------------------------------------------------------- #
# UDP authoritative DNS server (dnslib)
# --------------------------------------------------------------------------- #
class ManagedZoneResolver:
    """Answers A queries for the managed domain only; authoritative AA=1."""

    def resolve(self, request: DNSRecord, handler) -> DNSRecord:
        reply = request.reply()
        qname = str(request.q.qname).rstrip(".")
        qtype = QTYPE[request.q.qtype]
        snap = snapshot()

        if qtype != "A":
            # The service only publishes A records.
            reply.header.rcode = RCODE.REFUSED
            return reply
        if not snap["domain"] or qname != snap["domain"].rstrip("."):
            # Authoritative server, unknown name -> NXDOMAIN.
            reply.header.rcode = RCODE.NXDOMAIN
            return reply
        if snap["revision"] == 0:
            # No revision has ever been applied: do not fabricate data.
            reply.header.rcode = RCODE.SERVFAIL
            return reply

        for addr in snap["addresses"]:  # the whole list takes effect together
            reply.add_answer(
                RR(
                    request.q.qname,
                    QTYPE.A,
                    rdata=A(addr),
                    ttl=DNS_TTL,
                )
            )
        return reply


# --------------------------------------------------------------------------- #
# Control/health HTTP API
# --------------------------------------------------------------------------- #
class ControlHandler(BaseHTTPRequestHandler):
    server_version = f"dnsnode/{NODE_ID}"

    def log_message(self, fmt, *args):  # quieter logs
        print(f"[node {NODE_ID} http] {fmt % args}")

    def _send_json(self, code: int, obj: dict) -> None:
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.rstrip("/") in ("/health", "/zones/current"):
            snap = snapshot()
            self._send_json(200, {"node_id": NODE_ID, **snap})
        else:
            self._send_json(404, {"error": "not found"})

    def do_POST(self):
        if self.path.rstrip("/") != "/publish":
            self._send_json(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            data = json.loads(self.rfile.read(length) or b"{}")
            revision = int(data["revision"])
            domain = str(data["domain"])
            addresses = [str(a) for a in data["addresses"]]
            assert revision > 0 and domain and addresses
            for a in addresses:
                parts = a.split(".")
                assert len(parts) == 4 and all(
                    p.isdigit() and 0 <= int(p) <= 255 for p in parts
                )
        except Exception:
            self._send_json(400, {"error": "invalid publish payload"})
            return

        if not NODE_KEY:
            # 未配置密钥：拒绝一切下发（fail closed）。
            self._send_json(503, {"error": "NODE_KEY 未配置，拒绝下发"})
            return
        hdr_node = self.headers.get(sigauth.HEADER_NODE, "")
        nonce = self.headers.get(sigauth.HEADER_NONCE, "")
        signature = self.headers.get(sigauth.HEADER_SIGNATURE, "")
        try:
            ts = int(self.headers.get(sigauth.HEADER_TS, ""))
        except ValueError:
            self._send_json(401, {"error": "签名时间戳格式错误"})
            return
        try:
            sigauth.verify_publish_signature(
                NODE_KEY, NODE_ID, hdr_node, ts, nonce, signature,
                revision, domain, addresses, SIG_TTL,
            )
        except sigauth.AuthError as exc:
            self._send_json(401, {"error": f"unauthorized: {exc}"})
            return

        code, body = process_publish(revision, domain, addresses, nonce, ts)
        if body.get("status") in ("applied", "already-applied"):
            _report_to_management(body["served_revision"])
        self._send_json(code, {"node_id": NODE_ID, **body})


# --------------------------------------------------------------------------- #
# Best-effort reporting back to the management service (signed)
# --------------------------------------------------------------------------- #
def _post_json(url: str, payload: dict, timeout: float = 5.0,
               headers: dict[str, str] | None = None) -> bool:
    req = urlrequest.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", **(headers or {})},
        method="POST",
    )
    try:
        with urlrequest.urlopen(req, timeout=timeout) as resp:
            return 200 <= resp.status < 300
    except Exception as exc:
        print(f"[node {NODE_ID}] report to {url} failed: {exc}")
        return False


def _report_to_management(revision: int) -> None:
    if not MGMT_BASE_URL or not NODE_KEY:
        return

    def _worker():
        url = f"{MGMT_BASE_URL}/internal/nodes/{NODE_ID}/report"
        for attempt in range(5):  # bounded retries; reconcile loop is the backstop
            headers = sigauth.report_headers(
                NODE_KEY, sigauth.PURPOSE_REPORT, NODE_ID, revision
            )
            if _post_json(url, {"served_revision": revision}, headers=headers):
                return
            time.sleep(min(2 ** attempt, 10))

    threading.Thread(target=_worker, daemon=True).start()


def _heartbeat_loop() -> None:
    if not MGMT_BASE_URL or not NODE_KEY:
        return
    while True:
        time.sleep(HEARTBEAT_INTERVAL)
        served = snapshot()["revision"]
        _post_json(
            f"{MGMT_BASE_URL}/internal/nodes/{NODE_ID}/heartbeat",
            {"served_revision": served},
            headers=sigauth.report_headers(
                NODE_KEY, sigauth.PURPOSE_HEARTBEAT, NODE_ID, served
            ),
        )


def main() -> None:
    init_db()
    if not NODE_KEY:
        print(f"[node {NODE_ID}] WARNING: NODE_KEY 未配置，"
              "将拒绝一切下发且无法回传心跳/上报")

    from dnslib.server import DNSServer

    resolver = ManagedZoneResolver()
    dns_server = DNSServer(resolver, port=UDP_PORT, address=UDP_HOST, tcp=False)
    dns_server.start_thread()
    print(f"[node {NODE_ID}] UDP authoritative DNS on {UDP_HOST}:{UDP_PORT}")

    http_server = ThreadingHTTPServer((HTTP_HOST, HTTP_PORT), ControlHandler)
    print(f"[node {NODE_ID}] control API on {HTTP_HOST}:{HTTP_PORT}")

    threading.Thread(target=_heartbeat_loop, daemon=True).start()
    try:
        http_server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        dns_server.stop()
        http_server.server_close()


if __name__ == "__main__":
    main()
