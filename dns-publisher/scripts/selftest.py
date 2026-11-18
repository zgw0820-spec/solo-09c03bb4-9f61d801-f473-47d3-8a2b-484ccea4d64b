#!/usr/bin/env python3
"""端到端自测：在本机模拟 Compose 拓扑（管理服务 + 两个独立持久化节点）。

覆盖:
  1. 发布与双节点同步、整列表原子生效、实答一致
  2. 单节点失联：另一节点继续应答；状态显示待补，绝不误报 synced
  3. 节点恢复后自动补齐到最新修订
  4. 迟到的旧修订推送被节点拒绝(409)，节点/同步结论不回退
  5. 并发发布：修订严格递增、无重号
  6. 授权与伪造防护：运维令牌、节点签名（身份/用途/时效）、跨节点复用、
     重放、伪造心跳/上报不能改动区域也不能伪造在线与同步结论
  7. 幂等重试：同修订同内容安全确认(already-applied)，同修订不同内容 409
  8. 重启持久化：节点区域/已应用日志/防重放 nonce、管理端修订/状态/nonce
     均在重启后保持；失联节点恢复后仍可补齐
  9. 非法输入校验

用法: python scripts/selftest.py [python可执行路径]
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))  # 使 common.sigauth 可导入（与服务同一份实现）

from common import sigauth  # noqa: E402

PY = sys.argv[1] if len(sys.argv) > 1 else sys.executable

DOMAIN = "device.example.internal"
MGMT_PORT = 18000
NODE_SPECS = [
    {"id": "node-a", "udp": 10053, "http": 18053},
    {"id": "node-b", "udp": 10054, "http": 18054},
]
OPS_TOKEN = "selftest-ops-token"
NODE_KEYS = {"node-a": "selftest-node-a-key", "node-b": "selftest-node-b-key"}

PASS, FAIL = 0, 0
procs: dict[str, subprocess.Popen] = {}
tmpdir: Path | None = None


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [PASS] {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name} {detail}")


def http(method: str, path: str, body: dict | None = None, port: int = MGMT_PORT,
         token: str | None = OPS_TOKEN, headers_extra: dict | None = None):
    """管理端 HTTP 调用；默认携带运维令牌，token=None 表示不带。"""
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if headers_extra:
        headers.update(headers_extra)
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}", data=data,
        headers=headers, method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def make_publish_headers(node_id: str, revision: int, addresses: list[str],
                         key: str, domain: str = DOMAIN,
                         ts: int | None = None, nonce: str | None = None) -> dict:
    """构造一条管理端风格的签名下发包（测试可篡改字段后直发节点）。"""
    ts = sigauth.now_ts() if ts is None else ts
    nonce = nonce or sigauth.new_nonce()
    return {
        sigauth.HEADER_NODE: node_id,
        sigauth.HEADER_TS: str(ts),
        sigauth.HEADER_NONCE: nonce,
        sigauth.HEADER_SIGNATURE: sigauth.sign_publish(
            key, node_id, revision, domain, addresses, ts, nonce),
    }


def make_report_headers(node_id: str, purpose: str, served_revision: int,
                        key: str, ts: int | None = None,
                        nonce: str | None = None) -> dict:
    ts = sigauth.now_ts() if ts is None else ts
    nonce = nonce or sigauth.new_nonce()
    return {
        sigauth.HEADER_NODE: node_id,
        sigauth.HEADER_TS: str(ts),
        sigauth.HEADER_NONCE: nonce,
        sigauth.HEADER_SIGNATURE: sigauth.sign_report(
            key, purpose, node_id, served_revision, ts, nonce),
    }


def node_publish(spec: dict, revision: int, addresses: list[str],
                 headers: dict | None = None, domain: str = DOMAIN):
    """绕过管理端直接向节点控制口发 /publish（默认正确签名）。"""
    if headers is None:
        headers = make_publish_headers(spec["id"], revision, addresses,
                                       NODE_KEYS[spec["id"]], domain)
    body = {"revision": revision, "domain": domain, "addresses": addresses}
    req = urllib.request.Request(
        f"http://127.0.0.1:{spec['http']}/publish",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", **headers}, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def dns_answers(port: int, domain: str = DOMAIN, timeout: float = 3.0) -> set[str]:
    from dnslib import DNSRecord
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(DNSRecord.question(domain, qtype="A").pack(), ("127.0.0.1", port))
        data, _ = s.recvfrom(65535)
    finally:
        s.close()
    reply = DNSRecord.parse(data)
    return {str(rr.rdata) for rr in reply.rr}


def wait_status(cond, timeout: float = 20.0, interval: float = 0.5):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        _, last = http("GET", "/status")
        if cond(last):
            return last
        time.sleep(interval)
    return last


def start_node(spec: dict) -> subprocess.Popen:
    assert tmpdir is not None
    data_dir = tmpdir / spec["id"]
    data_dir.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env.update({
        "NODE_ID": spec["id"],
        "NODE_DB_PATH": str(data_dir / "node.db"),
        "MGMT_BASE_URL": f"http://127.0.0.1:{MGMT_PORT}",
        "NODE_KEY": NODE_KEYS[spec["id"]],
        "SIG_TTL_SECONDS": "300",
        "UDP_PORT": str(spec["udp"]),
        "HTTP_PORT": str(spec["http"]),
        "HEARTBEAT_INTERVAL": "2",
    })
    p = subprocess.Popen(
        [PY, "-m", "dnsnode.node"], cwd=ROOT, env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    procs[spec["id"]] = p
    return p


def start_mgmt() -> subprocess.Popen:
    assert tmpdir is not None
    env = dict(os.environ)
    nodes_json = json.dumps([
        {"id": s["id"],
         "control_url": f"http://127.0.0.1:{s['http']}",
         "dns_host": "127.0.0.1",
         "dns_port": s["udp"]} for s in NODE_SPECS
    ])
    env.update({
        "MANAGED_DOMAIN": DOMAIN,
        "MGMT_DB_PATH": str(tmpdir / "management.db"),
        "OFFLINE_AFTER_SECONDS": "5",
        "RECONCILE_INTERVAL": "1",
        "OPS_TOKEN": OPS_TOKEN,
        "NODE_KEYS": json.dumps(NODE_KEYS),
        "SIG_TTL_SECONDS": "300",
        "NODES": nodes_json,
    })
    p = subprocess.Popen(
        [PY, "-m", "uvicorn", "management.app:app",
         "--host", "127.0.0.1", "--port", str(MGMT_PORT)],
        cwd=ROOT, env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    procs["mgmt"] = p
    return p


def wait_http(url_port: int, path: str, timeout: float = 15.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{url_port}{path}", timeout=2
            ) as r:
                if r.status == 200:
                    return True
        except Exception:
            time.sleep(0.4)
    return False


def stop(name: str) -> None:
    p = procs.pop(name, None)
    if p and p.poll() is None:
        p.terminate()
        try:
            p.wait(timeout=8)
        except subprocess.TimeoutExpired:
            p.kill()


def teardown() -> None:
    for name in list(procs):
        stop(name)


# --------------------------------------------------------------------------- #
# Test scenarios
# --------------------------------------------------------------------------- #
def scenario_basic() -> None:
    print("\n=== 1. 发布/同步/整列表生效/实答一致 ===")
    code, body = http("POST", "/publishes", {"addresses": ["10.0.0.1", "10.0.0.2"]})
    check("首次发布返回201且修订号=1", code == 201 and body["revision"] == 1, str(body))

    st = wait_status(lambda s: s["overall_status"] == "synced")
    check("双节点同步完成 overall=synced", st["overall_status"] == "synced", json.dumps(st))
    check("两节点 served_revision 均为1",
          all(n["served_revision"] == 1 for n in st["nodes"]), json.dumps(st["nodes"]))

    a = dns_answers(NODE_SPECS[0]["udp"])
    b = dns_answers(NODE_SPECS[1]["udp"])
    check("节点A 实答=整列表", a == {"10.0.0.1", "10.0.0.2"}, str(a))
    check("节点B 实答=整列表", b == {"10.0.0.1", "10.0.0.2"}, str(b))
    check("两端实际答复一致", a == b)

    code, ver = http("GET", "/verify")
    check("/verify 全部匹配最新修订", code == 200 and ver["all_nodes_match"], json.dumps(ver))

    # 第二次发布：整列表替换，旧地址必须全部消失
    code, body = http("POST", "/publishes", {"addresses": ["10.0.0.3"]})
    check("第二次发布修订号=2(严格递增)", code == 201 and body["revision"] == 2, str(body))
    wait_status(lambda s: s["overall_status"] == "synced")
    a2 = dns_answers(NODE_SPECS[0]["udp"])
    b2 = dns_answers(NODE_SPECS[1]["udp"])
    check("整列表替换: 新地址生效", a2 == {"10.0.0.3"}, str(a2))
    check("整列表替换: 旧地址全部消失", "10.0.0.1" not in a2 and "10.0.0.2" not in a2, str(a2))
    check("替换后两端仍一致", a2 == b2)


def scenario_outage() -> None:
    print("\n=== 2. 单节点失联: 另一节点继续应答, 不误报 synced ===")
    stop("node-b")
    time.sleep(1)

    code, body = http("POST", "/publishes", {"addresses": ["10.0.1.10", "10.0.1.11"]})
    rev3 = body["revision"]
    check("失联期间发布成功, 修订号=3", code == 201 and rev3 == 3, str(body))

    # 存活节点应在数个对账周期内追上
    deadline = time.time() + 15
    st = None
    while time.time() < deadline:
        _, st = http("GET", "/status")
        na = next(n for n in st["nodes"] if n["node_id"] == "node-a")
        if na["served_revision"] == 3:
            break
        time.sleep(0.5)
    na = next(n for n in st["nodes"] if n["node_id"] == "node-a")
    nb = next(n for n in st["nodes"] if n["node_id"] == "node-b")
    check("存活节点A 追上修订3", na["served_revision"] == 3, json.dumps(na))
    check("存活节点A 继续提供 DNS 实答",
          dns_answers(NODE_SPECS[0]["udp"]) == {"10.0.1.10", "10.0.1.11"})

    # 等待离线判定窗口
    time.sleep(6)
    _, st = http("GET", "/status")
    nb = next(n for n in st["nodes"] if n["node_id"] == "node-b")
    check("失联节点B 标记 offline", st["overall_status"] == "degraded-node-offline"
          and not nb["online"], json.dumps(st))
    check("synced=false, 绝不误报同步完成", st["synced"] is False)
    check("待补状态: node-b waiting-node-recovery",
          nb["catch_up_status"] == "waiting-node-recovery", json.dumps(nb))
    check("pending_nodes 包含 node-b", "node-b" in st["pending_nodes"])

    code, ver = http("GET", "/verify")
    check("失联期间 /verify 明确不通过(不假装一致)",
          ver["all_nodes_match"] is False
          and any(not n["matches_latest_revision"] for n in ver["nodes"]),
          json.dumps(ver))


def scenario_recovery() -> None:
    print("\n=== 3. 节点恢复后自动补齐 ===")
    start_node(NODE_SPECS[1])
    check("节点B 控制面恢复", wait_http(NODE_SPECS[1]["http"], "/health"))
    st = wait_status(lambda s: s["overall_status"] == "synced", timeout=25)
    nb = next(n for n in st["nodes"] if n["node_id"] == "node-b")
    check("恢复后 node-b 自动补齐到修订3",
          st["overall_status"] == "synced" and nb["served_revision"] == 3, json.dumps(st))
    check("补齐后两端实答一致",
          dns_answers(NODE_SPECS[0]["udp"]) == dns_answers(NODE_SPECS[1]["udp"]))


def scenario_stale() -> None:
    print("\n=== 4. 迟到旧修订被拒(409), 不回退 ===")
    # 持节点密钥直发一个旧 revision=1 的发布（签名合法但修订陈旧且内容冲突）
    spec = NODE_SPECS[0]
    code, raw = node_publish(spec, 1, ["1.2.3.4"])
    check("旧修订推送被节点 409 拒绝", code == 409 and raw["status"] == "rejected", str(raw))
    check("节点仍服务当前修订(不回退)", raw.get("served_revision") == 3, str(raw))
    check("节点实答未被旧数据污染",
          dns_answers(spec["udp"]) == {"10.0.1.10", "10.0.1.11"})

    # 管理端状态同样不回退
    _, st = http("GET", "/status")
    check("管理端同步结论仍为 synced", st["overall_status"] == "synced", json.dumps(st))

    # 模拟迟到的旧上报（签名合法，数值陈旧 → 被 MAX 钳制）
    hdrs = make_report_headers("node-a", sigauth.PURPOSE_REPORT, 1,
                               NODE_KEYS["node-a"])
    code, _ = http("POST", "/internal/nodes/node-a/report",
                   {"served_revision": 1}, token=None, headers_extra=hdrs)
    _, st = http("GET", "/status")
    na = next(n for n in st["nodes"] if n["node_id"] == "node-a")
    check("迟到旧上报被 MAX 钳制, served 不回退",
          code == 200 and na["served_revision"] == 3, json.dumps(na))


def scenario_interleave() -> None:
    print("\n=== 4b. 交错/乱序下发: 跳号接受、随后旧号拒绝 ===")
    spec = NODE_SPECS[0]
    _, st0 = http("GET", "/status")
    base = st0["latest_revision"]["revision"]

    def direct_push(rev: int, addr: str):
        # 持有节点密钥的带外下发（签名合法），用于构造乱序场景
        return node_publish(spec, rev, [addr])

    # 乱序先到一个跳号的较新修订 -> 必须接受
    code, body = direct_push(base + 3, "192.0.2.20")
    check("跳号的较新修订(base+3)被接受", code == 200
          and body["served_revision"] == base + 3, str(body))
    check("节点实答立即切换为跳号修订数据",
          dns_answers(spec["udp"]) == {"192.0.2.20"})

    # 迟到的中间修订(base+1) -> 必须 409, 数据不回退
    code, body = direct_push(base + 1, "192.0.2.19")
    check("迟到的中间修订被 409 拒绝", code == 409
          and body["status"] == "rejected", str(body))
    check("拒绝后实答不回退", dns_answers(spec["udp"]) == {"192.0.2.20"})

    # 同号不同内容 -> 冲突拒绝(幂等保护)
    code, body = direct_push(base + 3, "192.0.2.99")
    check("同号不同内容被 409 冲突拒绝", code == 409
          and body.get("reason") == "content-conflict", str(body))
    check("冲突拒绝不改变实答", dns_answers(spec["udp"]) == {"192.0.2.20"})

    # 管理端连续发布: 落后的 node-b 逐版追上; node-a 对旧版持续 409,
    # 直到管理端修订号超过 base+3 后两节点重新收敛。
    last_rev = base
    for i in range(1, 5):
        code, body = http("POST", "/publishes",
                          {"addresses": [f"198.51.100.{i}"]})
        check(f"管理端第{i}次发布成功(修订 {body['revision']})", code == 201)
        last_rev = body["revision"]
    check("管理端修订号已超过注入的跳号修订", last_rev == base + 4)
    st = wait_status(lambda s: s["overall_status"] == "synced", timeout=30)
    check("交错后双节点最终收敛到管理端最新修订",
          all(n["served_revision"] == last_rev for n in st["nodes"]),
          json.dumps(st["nodes"]))
    check("收敛后两端实答一致",
          dns_answers(NODE_SPECS[0]["udp"]) == dns_answers(NODE_SPECS[1]["udp"])
          == {"198.51.100.4"})


def scenario_concurrent() -> None:
    print("\n=== 5. 并发发布: 修订严格递增无重号 ===")
    import concurrent.futures
    payloads = [[f"172.16.0.{i}"] for i in range(1, 9)]
    # 基线必须在并发发布之前取，否则拿到的是风暴后的最新修订号
    _, st0 = http("GET", "/status")
    base = st0["latest_revision"]["revision"]
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(
            lambda p: http("POST", "/publishes", {"addresses": p}), payloads
        ))
    codes = [c for c, _ in results]
    revs = sorted(b["revision"] for _, b in results)
    check("8 个并发发布全部 201", all(c == 201 for c in codes), str(codes))
    check("修订号唯一且连续递增(base+1..base+8)",
          revs == list(range(base + 1, base + 9)), str(revs))

    st = wait_status(lambda s: s["overall_status"] == "synced", timeout=30)
    check("并发风暴后最终双节点收敛到最新修订",
          st["overall_status"] == "synced"
          and all(n["served_revision"] == base + 8 for n in st["nodes"]), json.dumps(st))
    check("收敛后两端实答一致",
          dns_answers(NODE_SPECS[0]["udp"]) == dns_answers(NODE_SPECS[1]["udp"]))


def scenario_auth() -> None:
    print("\n=== 6. 授权/伪造/跨节点/重放/幂等重试 ===")
    spec_a, spec_b = NODE_SPECS

    # 先通过管理端连续发布两版，使节点 applied_log 确定含有 rev_k 与 rev_cur
    code, b1 = http("POST", "/publishes", {"addresses": ["10.7.0.1"]})
    rev_k = b1["revision"]
    code, b2 = http("POST", "/publishes", {"addresses": ["10.7.0.2", "10.7.0.3"]})
    rev_cur = b2["revision"]
    check("带令牌连续发布两版成功", code == 201 and rev_cur == rev_k + 1,
          f"{b1} {b2}")
    st = wait_status(lambda s: s["overall_status"] == "synced")
    check("两版均已同步", st["overall_status"] == "synced", json.dumps(st))
    cur_addrs = ["10.7.0.2", "10.7.0.3"]

    # --- 运维令牌 ---
    code, _ = http("POST", "/publishes", {"addresses": ["10.9.9.9"]}, token=None)
    check("无运维令牌发布被 401 拒绝", code == 401, str(code))
    code, _ = http("POST", "/publishes", {"addresses": ["10.9.9.9"]},
                   token="wrong-token")
    check("错误运维令牌被 401 拒绝", code == 401, str(code))
    _, st2 = http("GET", "/status")
    check("伪造发布后修订号未变", st2["latest_revision"]["revision"] == rev_cur,
          json.dumps(st2["latest_revision"]))

    # --- 节点控制口签名 ---
    code, _ = node_publish(spec_a, rev_cur + 1, ["10.8.8.8"], headers={})
    check("无签名下发被 401 拒绝", code == 401, str(code))
    bad_key = make_publish_headers(spec_a["id"], rev_cur + 1, ["10.8.8.8"],
                                   key="attacker-key")
    code, _ = node_publish(spec_a, rev_cur + 1, ["10.8.8.8"], headers=bad_key)
    check("错误密钥签名被 401 拒绝", code == 401, str(code))
    expired = make_publish_headers(spec_a["id"], rev_cur + 1, ["10.8.8.8"],
                                   key=NODE_KEYS[spec_a["id"]],
                                   ts=sigauth.now_ts() - 3600)
    code, _ = node_publish(spec_a, rev_cur + 1, ["10.8.8.8"], headers=expired)
    check("过期时间戳被 401 拒绝", code == 401, str(code))
    # 用途混淆：用 report 用途的签名冒充 publish
    ts, nonce = sigauth.now_ts(), sigauth.new_nonce()
    confused = {
        sigauth.HEADER_NODE: spec_a["id"],
        sigauth.HEADER_TS: str(ts),
        sigauth.HEADER_NONCE: nonce,
        sigauth.HEADER_SIGNATURE: sigauth.sign_report(
            NODE_KEYS[spec_a["id"]], sigauth.PURPOSE_REPORT,
            spec_a["id"], rev_cur + 1, ts, nonce),
    }
    code, _ = node_publish(spec_a, rev_cur + 1, ["10.8.8.8"], headers=confused)
    check("跨用途签名被 401 拒绝", code == 401, str(code))
    # 跨节点复用：给 node-a 的合法签名发给 node-b
    cross = make_publish_headers(spec_a["id"], rev_cur + 1, ["10.8.8.8"],
                                 key=NODE_KEYS[spec_a["id"]])
    code, _ = node_publish(spec_b, rev_cur + 1, ["10.8.8.8"], headers=cross)
    check("跨节点复用签名被 401 拒绝", code == 401, str(code))
    check("伪造尝试后节点A实答未变", dns_answers(spec_a["udp"]) == set(cur_addrs))
    check("伪造尝试后节点B实答未变", dns_answers(spec_b["udp"]) == set(cur_addrs))

    # --- 幂等重试与重放 ---
    good = make_publish_headers(spec_a["id"], rev_cur, cur_addrs,
                                key=NODE_KEYS[spec_a["id"]])
    code, body = node_publish(spec_a, rev_cur, cur_addrs, headers=good)
    check("同修订同内容重试安全确认(already-applied)",
          code == 200 and body["status"] == "already-applied"
          and body["served_revision"] == rev_cur, f"{code} {body}")
    code, _ = node_publish(spec_a, rev_cur, cur_addrs, headers=good)  # 同一请求原样重发
    check("同一签名请求重放(同nonce)被 409 拒绝", code == 409, str(code))
    conflict = make_publish_headers(spec_a["id"], rev_cur, ["203.0.113.1"],
                                    key=NODE_KEYS[spec_a["id"]])
    code, body = node_publish(spec_a, rev_cur, ["203.0.113.1"], headers=conflict)
    check("同修订不同内容被 409 冲突拒绝",
          code == 409 and body.get("reason") == "content-conflict", f"{code} {body}")
    check("冲突拒绝后实答未变", dns_answers(spec_a["udp"]) == set(cur_addrs))
    # 更旧的已应用修订：内容一致 → 安全确认；不一致 → 拒绝
    old_same = make_publish_headers(spec_a["id"], rev_k, ["10.7.0.1"],
                                    key=NODE_KEYS[spec_a["id"]])
    code, body = node_publish(spec_a, rev_k, ["10.7.0.1"], headers=old_same)
    check("旧修订同内容重试安全确认(回执丢失场景)",
          code == 200 and body["status"] == "already-applied"
          and body["served_revision"] == rev_cur, f"{code} {body}")
    old_diff = make_publish_headers(spec_a["id"], rev_k, ["203.0.113.9"],
                                    key=NODE_KEYS[spec_a["id"]])
    code, _ = node_publish(spec_a, rev_k, ["203.0.113.9"], headers=old_diff)
    check("旧修订不同内容被 409 拒绝", code == 409, str(code))
    check("全部重试后实答仍未变", dns_answers(spec_a["udp"]) == set(cur_addrs))

    # --- 伪造节点回传 ---
    code, _ = http("POST", "/internal/nodes/node-a/report",
                   {"served_revision": 999}, token=None)
    check("无签名上报被 401 拒绝", code == 401, str(code))
    forged = make_report_headers("node-b", sigauth.PURPOSE_REPORT, 999,
                                 NODE_KEYS["node-a"])  # 用 node-a 的密钥冒充 node-b
    code, _ = http("POST", "/internal/nodes/node-b/report",
                   {"served_revision": 999}, token=None, headers_extra=forged)
    check("跨节点密钥伪造上报被 401 拒绝", code == 401, str(code))
    _, st = http("GET", "/status")
    nb = next(n for n in st["nodes"] if n["node_id"] == "node-b")
    check("伪造上报未改变 node-b 已服务版本",
          nb["served_revision"] == rev_cur, json.dumps(nb))

    # --- 伪造在线状态：node-b 失联后，伪造心跳不能让其"复活" ---
    stop("node-b")
    time.sleep(6)  # 超过 OFFLINE_AFTER=5s
    _, st = http("GET", "/status")
    nb = next(n for n in st["nodes"] if n["node_id"] == "node-b")
    check("node-b 已判定离线", not nb["online"]
          and st["overall_status"] == "degraded-node-offline", json.dumps(nb))
    code, _ = http("POST", "/internal/nodes/node-b/heartbeat",
                   {"served_revision": rev_cur}, token=None)
    check("无签名心跳被 401 拒绝", code == 401, str(code))
    wrong = make_report_headers("node-b", sigauth.PURPOSE_HEARTBEAT, rev_cur,
                                NODE_KEYS["node-a"])  # 错误密钥
    code, _ = http("POST", "/internal/nodes/node-b/heartbeat",
                   {"served_revision": rev_cur}, token=None, headers_extra=wrong)
    check("错误密钥心跳被 401 拒绝", code == 401, str(code))
    _, st = http("GET", "/status")
    nb = next(n for n in st["nodes"] if n["node_id"] == "node-b")
    check("伪造心跳未能伪造在线/同步结论", not nb["online"]
          and st["overall_status"] == "degraded-node-offline", json.dumps(st))
    # 合法签名心跳被接受，但同一 nonce 重放被 409 拒绝
    legit = make_report_headers("node-b", sigauth.PURPOSE_HEARTBEAT, rev_cur,
                                NODE_KEYS["node-b"])
    code1, _ = http("POST", "/internal/nodes/node-b/heartbeat",
                    {"served_revision": rev_cur}, token=None, headers_extra=legit)
    code2, _ = http("POST", "/internal/nodes/node-b/heartbeat",
                    {"served_revision": rev_cur}, token=None, headers_extra=legit)
    check("合法签名心跳接受(200)，同 nonce 重放被 409 拒绝",
          code1 == 200 and code2 == 409, f"{code1}/{code2}")

    # 恢复真实 node-b，避免影响后续场景
    start_node(NODE_SPECS[1])
    check("node-b 控制面恢复", wait_http(NODE_SPECS[1]["http"], "/health"))
    st = wait_status(lambda s: s["overall_status"] == "synced", timeout=25)
    check("node-b 恢复后整体重新 synced",
          st["overall_status"] == "synced", json.dumps(st))


def scenario_persistence() -> None:
    print("\n=== 7. 重启持久化: 区域/幂等/防重放/管理端状态 ===")
    spec_a = NODE_SPECS[0]
    _, st = http("GET", "/status")
    cur = st["latest_revision"]["revision"]
    cur_addrs = st["latest_revision"]["addresses"]

    # 重启前消费一个 nonce（同修订同内容 → 幂等确认）
    replay_hdrs = make_publish_headers(spec_a["id"], cur, cur_addrs,
                                       NODE_KEYS[spec_a["id"]])
    code, body = node_publish(spec_a, cur, cur_addrs, headers=replay_hdrs)
    check("重启前同内容重试安全确认",
          code == 200 and body["status"] == "already-applied", f"{code} {body}")
    # 重启前在管理端消费一个上报 nonce
    consumed_report = make_report_headers("node-a", sigauth.PURPOSE_REPORT, cur,
                                          NODE_KEYS["node-a"])
    code, _ = http("POST", "/internal/nodes/node-a/report",
                   {"served_revision": cur}, token=None,
                   headers_extra=consumed_report)
    check("重启前合法上报被接受", code == 200, str(code))

    # --- 节点重启：独立 SQLite 持久化 ---
    for spec in NODE_SPECS:
        stop(spec["id"])
    for spec in NODE_SPECS:
        start_node(spec)
    for spec in NODE_SPECS:
        check(f"{spec['id']} 重启后健康", wait_http(spec["http"], "/health", timeout=15))
    # 节点未收到任何新发布也应凭本地库继续应答最新数据
    time.sleep(2)
    a = dns_answers(NODE_SPECS[0]["udp"])
    b = dns_answers(NODE_SPECS[1]["udp"])
    _, st0 = http("GET", "/status")
    expected = set(st0["latest_revision"]["addresses"])
    check("重启后节点A 凭持久化继续应答", a == expected, str(a))
    check("重启后节点B 凭持久化继续应答", b == expected, str(b))

    # 重启后：已消费 nonce 的重放仍被拒绝；同修订同内容仍可幂等确认
    code, _ = node_publish(spec_a, cur, cur_addrs, headers=replay_hdrs)
    check("节点重启后重放已消费 nonce 仍被 409 拒绝", code == 409, str(code))
    fresh = make_publish_headers(spec_a["id"], cur, cur_addrs,
                                 NODE_KEYS[spec_a["id"]])
    code, body = node_publish(spec_a, cur, cur_addrs, headers=fresh)
    check("节点重启后同修订同内容仍安全确认(幂等持久化)",
          code == 200 and body["status"] == "already-applied", f"{code} {body}")
    conflict = make_publish_headers(spec_a["id"], cur, ["203.0.113.77"],
                                    NODE_KEYS[spec_a["id"]])
    code, _ = node_publish(spec_a, cur, ["203.0.113.77"], headers=conflict)
    check("节点重启后同修订不同内容仍 409 冲突", code == 409, str(code))

    # --- 管理端重启：修订/节点状态/防重放记录持久 ---
    stop("mgmt")
    start_mgmt()
    check("管理端重启后恢复服务", wait_http(MGMT_PORT, "/status", timeout=20))
    code, _ = http("POST", "/internal/nodes/node-a/report",
                   {"served_revision": cur}, token=None,
                   headers_extra=consumed_report)
    check("管理端重启后重放上报仍被 409 拒绝", code == 409, str(code))
    _, st = http("GET", "/status")
    na = next(n for n in st["nodes"] if n["node_id"] == "node-a")
    check("管理端重启后修订与已服务版本未丢",
          st["latest_revision"]["revision"] == cur
          and na["served_revision"] == cur, json.dumps(st))

    st = wait_status(lambda s: s["overall_status"] == "synced", timeout=20)
    check("心跳恢复后管理端重新判定 synced",
          st["overall_status"] == "synced", json.dumps(st))


def scenario_validation() -> None:
    print("\n=== 8. 输入校验 ===")
    code, _ = http("POST", "/publishes", {"addresses": []})
    check("空地址列表拒绝", code == 422, str(code))
    code, _ = http("POST", "/publishes", {"addresses": ["10.0.0.999"]})
    check("非法 IPv4 拒绝", code == 422, str(code))
    code, _ = http("POST", "/publishes", {"addresses": ["10.0.0.1", "10.0.0.1"]})
    check("重复地址拒绝", code == 422, str(code))


def main() -> int:
    global tmpdir
    tmpdir = Path(tempfile.mkdtemp(prefix="dns-pub-test-"))
    print(f"临时数据目录: {tmpdir}")
    try:
        start_mgmt()
        if not wait_http(MGMT_PORT, "/status", timeout=20):
            print("管理服务启动失败")
            if procs.get("mgmt"):
                print(procs["mgmt"].stdout.read(4000))
            return 2
        for spec in NODE_SPECS:
            start_node(spec)
            if not wait_http(spec["http"], "/health", timeout=15):
                print(f"{spec['id']} 启动失败")
                return 2

        scenario_basic()
        scenario_outage()
        scenario_recovery()
        scenario_stale()
        scenario_interleave()
        scenario_concurrent()
        scenario_auth()
        scenario_persistence()
        scenario_validation()
    finally:
        teardown()

    print(f"\n==== 结果: {PASS} 通过, {FAIL} 失败 ====")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
