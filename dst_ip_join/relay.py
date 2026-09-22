# -*- coding: utf-8 -*-
"""UDP 中继：把两段互相不可达的网络缝起来（纯转发，不改游戏一个字节）。

背景
----
饥荒联机版的传输层是 IPv4-only 的 ENet，所以「有一方只有 IPv6」就联不上。
本模块不去动游戏，只做一件事：在两端各起一个双向 UDP 转发器，把包原样搬过去。

    ┌─ 主机侧（可以双栈） ────────────────────────┐
    │  DST 服务器   0.0.0.0:10999                  │
    │        ↕ 本机回环（每位朋友一个 127.0.0.x）  │
    │  中继 listen  [::]:20000                     │
    └─────────────── ↕ 公网 IPv6 ────────────────┘
    ┌─ 朋友侧（只有 IPv4） ───────────────────────┐
    │  中继 listen  127.0.0.1:10999                │
    │        ↕ 本机回环                            │
    │  DST 客户端   c_connect("127.0.0.1", 10999) │
    └──────────────────────────────────────────────┘

两端跑的是**同一份代码**，只要把 ``--map 监听=目标`` 的方向反过来配。

设计要点
--------
* **不解析游戏协议**：只凭「谁先说话」建 peer 表，之后原样 ``sendto``，
  一个字节都不改。所以它不认识饥荒，也能中继别的 UDP 游戏。
* **一位朋友一个独立套接字**。主机侧还会给每位朋友分配一个
  ``127.0.0.x`` 回环地址，于是游戏服务器那边看到的是「局域网里几台
  不同的机器」，和原生联机最接近（也避免多客户端共用同一个源地址）。
* 空闲 peer 自动回收，绝不无限增长。
"""

from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import os
import re
import secrets
import selectors
import socket
import sys
import threading
import time
from dataclasses import dataclass, field

# UDP 报文长度上限（去掉 IP/UDP 头后 65507，这里按整包上限收）
BUFFER_SIZE = 65535

# 主机侧给朋友分配的回环地址池：127.0.0.2 ~ 127.0.0.254。
# Windows 上整个 127.0.0.0/8 都指向回环，已实测 127.0.0.99 可正常 bind。
_LOOPBACK_POOL = [f"127.0.0.{i}" for i in range(2, 255)]

# ---------------------------------------------------------------------------
# 连通性探测
# ---------------------------------------------------------------------------
# 中继收到以 PROBE_MAGIC 开头的包时**自己应答**（不转发给游戏），
# 用来把两种失败分开：
#   OK     —— 包到达主机且通过白名单（路是通的）
#   DENIED —— 包到达主机但被白名单拒绝（地址没加对）
#   timeout—— 包根本没到主机（防火墙 / 光猫路由 / 地址错）
PROBE_MAGIC = b"DST-IP-JOIN-PROBE/1 "
PROBE_REPLY_OK = b"DST-IP-JOIN-PROBE-OK"
PROBE_REPLY_DENIED = b"DST-IP-JOIN-PROBE-DENIED"


# ==========================================================================
# 地址工具
# ==========================================================================
def format_endpoint(host: str, port: int) -> str:
    """把地址格式化成 ``1.2.3.4:80`` / ``[::1]:80``。"""
    if ":" in host:
        return f"[{host}]:{port}"
    return f"{host}:{port}"


def parse_endpoint(text: str) -> tuple[str, int]:
    """解析 ``1.2.3.4:10999`` 或 ``[::]:10999``。

    IPv6 字面量**必须**加方括号，否则冒号会和端口分隔符混淆。
    """
    text = (text or "").strip()
    if not text:
        raise ValueError("地址为空")

    if text.startswith("["):
        close = text.find("]")
        if close < 0:
            raise ValueError(f"IPv6 地址缺少右方括号：{text!r}")
        host = text[1:close]
        rest = text[close + 1 :]
        if not rest.startswith(":"):
            raise ValueError(f"方括号后面必须是 :端口：{text!r}")
        port_text = rest[1:]
    else:
        if ":" not in text:
            raise ValueError(f"缺少端口（应为 地址:端口）：{text!r}")
        host, _, port_text = text.rpartition(":")
        if ":" in host:
            # ::1:10999 本身也是个合法的 IPv6 地址，歧义无法消解，
            # 所以强制要求带方括号
            raise ValueError(
                f"IPv6 地址必须加方括号：{text!r} 应写成 [{host}]:{port_text}"
            )

    if not host:
        raise ValueError(f"地址为空：{text!r}")

    try:
        port = int(port_text)
    except ValueError:
        raise ValueError(f"端口不是数字：{port_text!r}") from None
    if not 0 <= port <= 65535:
        raise ValueError(f"端口超出范围：{port}")

    return host, port


def _resolve(host: str, port: int, *, passive: bool = False) -> tuple[int, tuple]:
    """``getaddrinfo`` 的简化封装，返回 ``(地址族, sockaddr)``。"""
    flags = socket.AI_PASSIVE if passive else 0
    infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_DGRAM, 0, flags)
    if not infos:
        raise OSError(f"无法解析地址 {format_endpoint(host, port)}")
    family, _, _, _, sockaddr = infos[0]
    return family, sockaddr


def _bind_socket(family: int, sockaddr: tuple, *, dual_stack: bool = False) -> socket.socket:
    """建一个非阻塞 UDP 套接字并绑定。

    刻意**不设** ``SO_REUSEADDR``：Windows 上它会允许两个进程抢占同一端口，
    收包分流变得不可预测。让端口冲突老老实实报错更安全。
    """
    sock = socket.socket(family, socket.SOCK_DGRAM)
    try:
        if family == socket.AF_INET6:
            # Windows 默认 IPV6_V6ONLY=1，即 [::] 只收 IPv6。
            sock.setsockopt(
                socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0 if dual_stack else 1
            )
        sock.bind(sockaddr)
        sock.setblocking(False)
    except OSError:
        sock.close()
        raise
    return sock


def _key(sockaddr: tuple) -> tuple[str, int]:
    """取 (主机, 端口) 作为 peer 表的键，丢掉 IPv6 的 flowinfo / scope_id。"""
    return (sockaddr[0], sockaddr[1])


def _target_is_loopback(host: str) -> bool:
    """判断转发目标是不是本机回环（是的话就该给朋友分独立的回环地址）。"""
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.split("%", 1)[0]).is_loopback
    except ValueError:
        return False


class AddressAllowList:
    """来源地址白名单。支持单个地址或 CIDR，例如 ``2001:db8::1`` / ``2409:8a60::/32``。"""

    def __init__(self, entries: list[str] | None = None) -> None:
        self._networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._allow_any = False
        for entry in entries or []:
            text = entry.strip()
            if not text:
                continue
            if text.lower() in ("any", "*", "all"):
                self._allow_any = True
                continue
            try:
                self._networks.append(ipaddress.ip_network(text, strict=False))
            except ValueError as exc:
                raise ValueError(f"白名单条目无法解析：{entry!r}（{exc}）") from None

    @property
    def is_open(self) -> bool:
        """没有任何限制（等于不设防）。"""
        return self._allow_any or not self._networks

    def allows(self, host: str) -> bool:
        if self._allow_any:
            return True
        if not self._networks:
            return True
        try:
            addr = ipaddress.ip_address(host.split("%", 1)[0])
        except ValueError:
            return False
        # IPv4-mapped IPv6（::ffff:1.2.3.4）按内层的 IPv4 再判一次
        mapped = getattr(addr, "ipv4_mapped", None)
        for net in self._networks:
            if addr in net:
                return True
            if mapped is not None and mapped in net:
                return True
        return False

    def describe(self) -> str:
        if self.is_open:
            return "不限制（任何人都能连）"
        parts = [str(n) for n in self._networks]
        if self._allow_any:
            parts.append("any")
        return "、".join(parts)


# ==========================================================================
# peer
# ==========================================================================
@dataclass(eq=False)
class Peer:
    """一位对端（朋友），独占一个套接字。"""

    remote: tuple  # 对端的 sockaddr，回包时用它
    sock: socket.socket  # 朝「游戏那一侧」说话用的套接字
    bound_ip: str = ""  # 绑定的回环地址（主机侧才有，仅用于归还地址池）
    created: float = 0.0
    last_seen: float = 0.0
    # to_game：外部 -> 游戏；to_remote：游戏 -> 外部
    to_game_packets: int = 0
    to_game_bytes: int = 0
    to_remote_packets: int = 0
    to_remote_bytes: int = 0

    @property
    def address_text(self) -> str:
        return format_endpoint(self.remote[0], self.remote[1])


# ==========================================================================
# 转发规则
# ==========================================================================
class ForwardRule:
    """一条转发规则：监听 ``listen``，把所有包原样转给 ``target``，并回传。

    数据流（两个方向都是「收到就转」，没有任何协议判断）：

        [外部] --> listen_sock --> peer.sock --> [游戏]
        [外部] <-- listen_sock <-- peer.sock <-- [游戏]
    """

    def __init__(
        self,
        listen_text: str,
        target_text: str,
        *,
        allow: AddressAllowList | None = None,
        peer_bind: str = "",
        dual_stack: bool = False,
        max_peers: int = 32,
    ) -> None:
        self.listen_text = listen_text
        self.target_text = target_text
        self.allow = allow or AddressAllowList()
        self.max_peers = max_peers

        lhost, lport = parse_endpoint(listen_text)
        self.listen_family, self.listen_addr = _resolve(lhost, lport, passive=True)
        self.listen_sock = _bind_socket(
            self.listen_family, self.listen_addr, dual_stack=dual_stack
        )
        self.listen_host, self.listen_port = lhost, lport
        self._configured_listen_port = lport

        thost, tport = parse_endpoint(target_text)
        self.target_host, self.target_port = thost, tport
        self.target_family, self.target_addr = _resolve(thost, tport)

        # 目标是本机回环时，给每位朋友一个不同的回环地址
        self._pool: list[str] = (
            list(_LOOPBACK_POOL)
            if self.target_family == socket.AF_INET and _target_is_loopback(thost)
            else []
        )

        self.peer_bind_addr: tuple | None = None
        if peer_bind:
            phost, pport = parse_endpoint(peer_bind)
            self.peer_bind_addr = _resolve(phost, pport, passive=True)[1]

        self.peers: dict[tuple[str, int], Peer] = {}
        self._peers_lock = threading.Lock()
        self.dropped_untrusted = 0
        self.dropped_busy = 0

        # 累计量单独记：peer 被回收后仍要能报出这轮总共转了多少
        self.total_to_game_packets = 0
        self.total_to_game_bytes = 0
        self.total_to_remote_packets = 0
        self.total_to_remote_bytes = 0

    # ---------------------------------------------------------------- 属性
    @property
    def listen_text_full(self) -> str:
        return format_endpoint(self.listen_host, self.listen_port)

    @property
    def target_text_full(self) -> str:
        return format_endpoint(self.target_host, self.target_port)

    def actual_listen_endpoint(self) -> tuple[str, int]:
        """实际生效的监听端点（配置端口写 0 时由系统分配，这里取真实值）。"""
        host, port = self.listen_sock.getsockname()[:2]
        return host, port

    # ------------------------------------------------------------ 套接字
    def _new_peer_socket(self) -> tuple[socket.socket, str]:
        """为一位朋友准备「朝游戏那一侧」的套接字。"""
        if self.peer_bind_addr is not None:
            return _bind_socket(self.target_family, self.peer_bind_addr), ""

        if self._pool:
            # 主机侧：一人一个回环地址，游戏眼里像局域网
            while self._pool:
                ip = self._pool[0]
                try:
                    sock = _bind_socket(self.target_family, (ip, 0))
                except OSError:
                    self._pool.pop(0)  # 这个地址用不了，直接淘汰
                    continue
                self._pool.pop(0)
                return sock, ip

        any_addr = ("::", 0, 0, 0) if self.target_family == socket.AF_INET6 else ("0.0.0.0", 0)
        return _bind_socket(self.target_family, any_addr), ""

    def _release_peer(self, peer: Peer) -> None:
        if peer.bound_ip:
            self._pool.append(peer.bound_ip)
            self._pool.sort(key=lambda s: int(s.rsplit(".", 1)[1]))

    # --------------------------------------------------------------- peer
    def create_peer(self, remote: tuple) -> Peer | None:
        with self._peers_lock:
            if len(self.peers) >= self.max_peers:
                self.dropped_busy += 1
                return None
        try:
            sock, bound_ip = self._new_peer_socket()
        except OSError:
            self.dropped_busy += 1
            return None
        now = time.monotonic()
        peer = Peer(remote=remote, sock=sock, bound_ip=bound_ip, created=now, last_seen=now)
        with self._peers_lock:
            self.peers[_key(remote)] = peer
        return peer

    def remove_peer(self, peer: Peer) -> None:
        with self._peers_lock:
            self.peers.pop(_key(peer.remote), None)
        self._release_peer(peer)
        try:
            peer.sock.close()
        except OSError:
            pass

    def close(self) -> None:
        for peer in list(self.peers.values()):
            self.remove_peer(peer)
        try:
            self.listen_sock.close()
        except OSError:
            pass

    # --------------------------------------------------------------- 统计
    @property
    def free_loopback_slots(self) -> int:
        """回环地址池还剩几个（0 表示不走独立地址方案）。"""
        return len(self._pool)

    def stats(self) -> dict[str, int]:
        return {
            "peer_count": len(self.peers),
            "to_game_packets": self.total_to_game_packets,
            "to_game_bytes": self.total_to_game_bytes,
            "to_remote_packets": self.total_to_remote_packets,
            "to_remote_bytes": self.total_to_remote_bytes,
            "dropped_untrusted": self.dropped_untrusted,
            "dropped_busy": self.dropped_busy,
        }


# ==========================================================================
# 中继主体
# ==========================================================================
class UdpRelay:
    """把若干条 ``ForwardRule`` 跑在一个事件循环里。"""

    def __init__(
        self,
        rules: list[ForwardRule],
        *,
        idle_timeout: float = 300.0,
        verbose: bool = False,
        stats_interval: float = 0.0,
        log=None,
        callback=None,
    ) -> None:
        self.rules = rules
        self.idle_timeout = idle_timeout
        self.verbose = verbose
        self.stats_interval = stats_interval
        self._log = log or (lambda text: print(text, flush=True))
        # 可选的事件回调，形如 callback(kind, payload)。
        # 只在中继线程里被调用，因此 GUI 接入时必须用线程安全的方式（例如
        # 排队 + 信号）把事件搬到主线程再更新界面。kind 目前有：
        #   "connect" / "drop" / "reject" / "busy" / "stats"
        self._callback = callback
        self._sel = selectors.DefaultSelector()
        self._running = False
        self._started = 0.0
        self._last_stats = 0.0
        self._last_sweep = 0.0

    # ---------------------------------------------------------------- 日志
    def log(self, text: str) -> None:
        self._log(f"[{time.strftime('%H:%M:%S')}] {text}")

    def _vlog(self, text: str) -> None:
        if self.verbose:
            self.log(text)

    def fire_event(self, kind: str, payload: dict | None = None) -> None:
        """向订阅者推一个事件。回调抛错不能拖垮中继，全部吞掉。"""
        if self._callback is None:
            return
        try:
            self._callback(kind, payload or {})
        except Exception:  # noqa: BLE001
            pass

    # ------------------------------------------------------------ 生命周期
    def _register_rule(self, rule: ForwardRule) -> None:
        self._sel.register(rule.listen_sock, selectors.EVENT_READ, ("listen", rule, None))

    def run(self, max_seconds: float = 0.0) -> None:
        """跑起来，直到 :meth:`stop` 或超时（``max_seconds>0`` 时）。"""
        for rule in self.rules:
            self._register_rule(rule)

        self._running = True
        self._started = time.monotonic()
        self._last_stats = self._started
        self._last_sweep = self._started

        try:
            while self._running:
                for key, _ in self._sel.select(timeout=0.5):
                    kind, rule, peer = key.data
                    if kind == "listen":
                        self._pump_listen(rule)
                    else:
                        self._pump_peer(rule, peer)

                now = time.monotonic()
                if self.idle_timeout > 0 and now - self._last_sweep >= 1.0:
                    self._sweep_idle(now)
                    self._last_sweep = now
                if self.stats_interval > 0 and now - self._last_stats >= self.stats_interval:
                    self._print_stats()
                    self._last_stats = now
                if max_seconds > 0 and now - self._started >= max_seconds:
                    self.log(f"达到设定时长 {max_seconds:g} 秒，退出")
                    break
        finally:
            self.stop()

    def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        for rule in self.rules:
            try:
                self._sel.unregister(rule.listen_sock)
            except (KeyError, ValueError):
                pass
            rule.close()
        self._sel.close()

    # ---------------------------------------------------------------- 收包
    def _pump_listen(self, rule: ForwardRule) -> None:
        """外部 -> 游戏。"""
        while True:
            try:
                data, remote = rule.listen_sock.recvfrom(BUFFER_SIZE)
            except (BlockingIOError, InterruptedError):
                return
            except OSError as exc:
                self._vlog(f"{rule.listen_text_full} 收包出错：{exc}")
                return

            # 连通性探测：中继自己回包，不交给游戏进程（游戏不会响应这种包）
            if data.startswith(PROBE_MAGIC):
                allowed = rule.allow.allows(remote[0])
                reply = PROBE_REPLY_OK if allowed else PROBE_REPLY_DENIED
                try:
                    rule.listen_sock.sendto(reply, remote)
                except OSError:
                    pass
                self.log(
                    f"收到连通性探测 {format_endpoint(remote[0], remote[1])}："
                    + ("已回包（在白名单内）" if allowed else "已回包（不在白名单！）")
                )
                self.fire_event(
                    "probe",
                    {
                        "remote": format_endpoint(remote[0], remote[1]),
                        "allowed": allowed,
                    },
                )
                continue

            if not rule.allow.allows(remote[0]):
                rule.dropped_untrusted += 1
                if rule.dropped_untrusted in (1, 2, 10, 100) or rule.dropped_untrusted % 1000 == 0:
                    self.log(
                        f"拒绝来源 {format_endpoint(remote[0], remote[1])}"
                        f"（不在白名单，累计 {rule.dropped_untrusted} 包）"
                    )
                self.fire_event(
                    "reject",
                    {
                        "remote": format_endpoint(remote[0], remote[1]),
                        "count": rule.dropped_untrusted,
                    },
                )
                continue

            with rule._peers_lock:
                peer = rule.peers.get(_key(remote))
            if peer is None:
                peer = rule.create_peer(remote)
                if peer is None:
                    self.log(
                        f"忽略来源 {format_endpoint(remote[0], remote[1])}："
                        f"peer 数已达上限 {rule.max_peers}"
                    )
                    self.fire_event(
                        "busy",
                        {
                            "remote": format_endpoint(remote[0], remote[1]),
                            "max": rule.max_peers,
                        },
                    )
                    continue
                self._sel.register(peer.sock, selectors.EVENT_READ, ("peer", rule, peer))
                extra = f"，本机表现为 {peer.bound_ip}" if peer.bound_ip else ""
                self.log(f"新连接 {peer.address_text} -> {rule.target_text_full}{extra}")
                self.fire_event(
                    "connect",
                    {
                        "remote": peer.address_text,
                        "target": rule.target_text_full,
                        "bound_ip": peer.bound_ip,
                        "peers": len(rule.peers),
                    },
                )

            peer.last_seen = time.monotonic()
            peer.to_game_packets += 1
            peer.to_game_bytes += len(data)
            rule.total_to_game_packets += 1
            rule.total_to_game_bytes += len(data)
            self._send(peer.sock, data, rule.target_addr, rule, "-> 游戏")

    def _pump_peer(self, rule: ForwardRule, peer: Peer) -> None:
        """游戏 -> 外部。"""
        while True:
            try:
                data, _ = peer.sock.recvfrom(BUFFER_SIZE)
            except (BlockingIOError, InterruptedError):
                return
            except OSError as exc:
                self._vlog(f"{peer.address_text} 回包出错：{exc}")
                self._drop_peer(rule, peer)
                return

            peer.last_seen = time.monotonic()
            peer.to_remote_packets += 1
            peer.to_remote_bytes += len(data)
            rule.total_to_remote_packets += 1
            rule.total_to_remote_bytes += len(data)
            self._send(rule.listen_sock, data, peer.remote, rule, "-> 外部")

    def _send(self, sock, data: bytes, dest: tuple, rule: ForwardRule, tag: str) -> None:
        try:
            sock.sendto(data, dest)
        except OSError as exc:
            # UDP 发送失败（缓冲区满 / 对端不可达）不该拖垮中继，丢掉即可
            self._vlog(f"{rule.listen_text_full} 发送失败（{tag}）：{exc}")

    # ------------------------------------------------------------ 清理维护
    def _drop_peer(self, rule: ForwardRule, peer: Peer) -> None:
        try:
            self._sel.unregister(peer.sock)
        except (KeyError, ValueError):
            pass
        rule.remove_peer(peer)
        if self.verbose or peer.to_game_packets or peer.to_remote_packets:
            self.log(
                f"断开 {peer.address_text}"
                f"（上行 {peer.to_game_packets} 包 / 下行 {peer.to_remote_packets} 包）"
            )
        self.fire_event(
            "drop",
            {
                "remote": peer.address_text,
                "up": peer.to_game_packets,
                "down": peer.to_remote_packets,
                "peers": len(rule.peers),
            },
        )

    def _sweep_idle(self, now: float) -> None:
        for rule in self.rules:
            for peer in list(rule.peers.values()):
                if now - peer.last_seen > self.idle_timeout:
                    self._vlog(
                        f"回收空闲 peer {peer.address_text}"
                        f"（静默 {now - peer.last_seen:.0f} 秒）"
                    )
                    self._drop_peer(rule, peer)

    # ---------------------------------------------------------------- 汇总
    def _print_stats(self) -> None:
        for rule in self.rules:
            st = rule.stats()
            self.log(
                f"{rule.listen_text_full} -> {rule.target_text_full} | "
                f"peer {st['peer_count']} | 上行 {st['to_game_packets']} 包 "
                f"{_human_bytes(st['to_game_bytes'])} | 下行 {st['to_remote_packets']} 包 "
                f"{_human_bytes(st['to_remote_bytes'])}"
                + (f" | 拒收 {st['dropped_untrusted']}" if st["dropped_untrusted"] else "")
            )
        self.fire_event("stats", self.snapshot())

    def snapshot(self) -> dict:
        """给 GUI 用的状态快照：规则 + 每位 peer 的实时流量。

        只读调用，可从任意线程发起（数据在中继线程里被更新，
        最坏情况拿到的是上一瞬间的值，不会破坏结构）。
        """
        rules: list[dict] = []
        for rule in self.rules:
            with rule._peers_lock:
                peers = [
                    {
                        "remote": p.address_text,
                        "bound_ip": p.bound_ip,
                        "idle": round(time.monotonic() - p.last_seen, 1),
                        "to_game_packets": p.to_game_packets,
                        "to_game_bytes": p.to_game_bytes,
                        "to_remote_packets": p.to_remote_packets,
                        "to_remote_bytes": p.to_remote_bytes,
                    }
                    for p in rule.peers.values()
                ]
            st = rule.stats()
            rules.append(
                {
                    "listen": rule.listen_text_full,
                    "target": rule.target_text_full,
                    "peers": peers,
                    **st,
                }
            )
        uptime = time.monotonic() - self._started if self._started else 0.0
        return {"uptime": round(uptime, 1), "rules": rules}

    def summary_lines(self) -> list[str]:
        lines = [f"运行时长 {time.monotonic() - self._started:.0f} 秒"]
        for rule in self.rules:
            st = rule.stats()
            lines.append(
                f"  {rule.listen_text_full} -> {rule.target_text_full}："
                f"上行 {st['to_game_packets']} 包 {_human_bytes(st['to_game_bytes'])}，"
                f"下行 {st['to_remote_packets']} 包 {_human_bytes(st['to_remote_bytes'])}"
                + (f"，拒收 {st['dropped_untrusted']} 包" if st["dropped_untrusted"] else "")
            )
        return lines


def _human_bytes(size: int) -> str:
    value = float(size)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.0f}{unit}" if unit == "B" else f"{value:.1f}{unit}"
        value /= 1024
    return f"{value:.1f}GB"


# ==========================================================================
# 本机地址（配 --map 时得知道主机该填什么地址）
# ==========================================================================
def _address_rank(addr: str) -> int:
    """排序权重：全局地址 0 < 链路本地 1 < 回环 2。"""
    try:
        parsed = ipaddress.ip_address(addr.split("%", 1)[0])
    except ValueError:
        return 3
    if parsed.is_loopback:
        return 2
    if parsed.is_link_local:
        return 1
    return 0


def list_local_addresses() -> tuple[list[str], list[str]]:
    """返回 ``(IPv4 列表, IPv6 列表)``，全局地址排在最前。"""
    v4: list[str] = []
    v6: list[str] = []
    try:
        infos = socket.getaddrinfo(
            socket.gethostname(), None, socket.AF_UNSPEC, socket.SOCK_DGRAM
        )
    except OSError:
        infos = []
    for family, _, _, _, sockaddr in infos:
        addr = sockaddr[0]
        bucket = v6 if family == socket.AF_INET6 else v4
        if addr not in bucket:
            bucket.append(addr)
    v4.sort(key=_address_rank)
    v6.sort(key=_address_rank)
    return v4, v6


def pick_public_address(prefer_ipv6: bool = True) -> str:
    """挑一个最适合发给别人的地址：优先全局 IPv6，退到第一个 IPv4。"""
    v4, _ = list_local_addresses()
    if prefer_ipv6:
        globals_v6 = global_ipv6_addresses()
        if globals_v6:
            return globals_v6[0]
    return v4[0] if v4 else ""


def global_ipv6_addresses() -> list[str]:
    """本机所有全局 IPv6 地址（排除链路本地 / 回环 / ULA fd00::/8）。"""
    _, v6 = list_local_addresses()
    result: list[str] = []
    for addr in v6:
        try:
            parsed = ipaddress.ip_address(addr.split("%", 1)[0])
        except ValueError:
            continue
        if parsed.is_global:
            result.append(addr)
    return result


# ==========================================================================
# 从文本里抠地址（朋友把地址发给主机时常直接粘一整段话）
# ==========================================================================
# IPv6 候选：允许 16 进制 / 冒号 / 点；IPv4 候选：四段点分十进制。
# 边界用 lookaround，但**不含冒号**：地址后面常跟 ``:端口``（如 ``1.2.3.4:10999``），
# 把冒号当边界会把带端口的地址整个丢掉。最终合法性仍由 ip_address() 把关。
_IP_TOKEN_RE = re.compile(
    r"(?<![\w.])"
    r"([0-9A-Fa-f:]{2,}(?:\.[0-9]{1,3}){0,2}|[0-9]{1,3}(?:\.[0-9]{1,3}){3})"
    r"(?![\w.])"
)


def extract_addresses(text: str) -> list[str]:
    """从任意文本里提取合法 IP（v4/v6 混合），去重、全局地址排前。

    会忽略明显不像地址的候选（纯数字、纯字母、单段），
    以及回环 / 链路本地（`::1` / `fe80::`）这类发给别人没用的。
    """
    seen: list[str] = []
    for match in _IP_TOKEN_RE.finditer(text or ""):
        token = match.group(1)
        if ":" not in token and "." not in token:
            continue
        try:
            addr = ipaddress.ip_address(token)
        except ValueError:
            continue
        if addr.is_loopback or addr.is_link_local or addr.is_multicast:
            continue
        if addr.is_unspecified:
            continue
        if token not in seen:
            seen.append(token)

    def rank(item: str) -> int:
        try:
            addr = ipaddress.ip_address(item)
        except ValueError:
            return 3
        if addr.is_global:
            return 0
        return 1

    return sorted(seen, key=rank)


def format_address_listing() -> str:
    """「发给别人」场景用的本机地址一句话，全局 IPv6 优先。"""
    globals_v6 = global_ipv6_addresses()
    if globals_v6:
        return globals_v6[0]
    v4, _ = list_local_addresses()
    return v4[0] if v4 else ""


# ==========================================================================
# 联机码（主机码 / 加入码）
# ==========================================================================
# 规则：把「对方需要的一切」打包进一段自包含文本，复制即用，不用手填端口/IP。
#
#   主机码 HOSTxxx   主机 → 加入方：本端地址 + 中继端口 + 游戏端口映射 + 校验
#   加入码 JOINxxx   加入方 → 主机：加入方的地址（用于白名单）+ 与主机码一致的校验
#
# 校验值（session）把「主机码」和「允许进来的加入码」绑在一起：
# 主机只放行校验值与自己匹配、且地址已被管理员加进白名单的加入方。
CODE_VERSION = 1
CODE_HOST_PREFIX = "HOST"
CODE_JOIN_PREFIX = "JOIN"
DEFAULT_RELAY_BASE = 20000


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_decode(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def make_session_token() -> str:
    """生成一次性会话校验值，把主机码与加入码绑在一起。"""
    return _b64url_encode(secrets.token_bytes(9))[:12]


def encode_host_code(
    addresses: list[str],
    base_port: int,
    game_ports: list[int],
    master_port: int,
    session: str,
) -> str:
    """打包主机码。addresses 按优先级排序（全局 IPv6 在前）。

    ``master_port`` 是**主世界分片**的游戏端口，必须由主机显式给出：
    加入方看到一串游戏端口时无法自行判断哪个是主世界（DST 默认主世界 10999、
    洞穴 10998，取最小会选到洞穴，而客户端连不进洞穴分片）。
    """
    payload = {
        "v": CODE_VERSION,
        "addr": addresses,
        "base": base_port,
        "maps": [[base_port + i, p] for i, p in enumerate(game_ports)],
        "master": master_port,
        "sid": session,
    }
    return CODE_HOST_PREFIX + _b64url_encode(
        json.dumps(payload, separators=(",", ":")).encode("utf-8")
    )


def encode_join_code(addresses: list[str], session: str) -> str:
    """打包加入码（只含加入方地址 + 校验，发给主机加白名单用）。"""
    payload = {"v": CODE_VERSION, "addr": addresses, "sid": session}
    return CODE_JOIN_PREFIX + _b64url_encode(
        json.dumps(payload, separators=(",", ":")).encode("utf-8")
    )


def _decode_payload(code: str, prefix: str) -> dict:
    text = (code or "").strip()
    if not text:
        raise ValueError("联机码为空")
    # 允许整段复制：截取出 CODE 前缀到结尾的最长合法字符段
    start = text.find(prefix)
    if start < 0:
        raise ValueError(f"不是{('主机码' if prefix == CODE_HOST_PREFIX else '加入码')}（缺少 {prefix} 前缀）")
    body = text[start + len(prefix):]
    body = re.split(r"[^A-Za-z0-9_\-=]", body, maxsplit=1)[0]
    try:
        data = json.loads(_b64url_decode(body).decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"联机码无法解析（可能不完整或被截断）：{exc}") from None
    if data.get("v") != CODE_VERSION:
        raise ValueError(f"联机码版本不支持：{data.get('v')}")
    return data


def decode_host_code(code: str) -> dict:
    """解析主机码 →
    ``{addresses, base_port, maps[(relay_port, game_port)], master_port, session}``。
    """
    data = _decode_payload(code, CODE_HOST_PREFIX)
    try:
        addresses = [str(a) for a in data["addr"]]
        base = int(data["base"])
        maps = [(int(r), int(g)) for r, g in data["maps"]]
        session = str(data["sid"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"主机码字段不完整：{exc}") from None
    if not addresses:
        raise ValueError("主机码里没有地址")
    if not maps:
        raise ValueError("主机码里没有端口映射")

    game_ports = [g for _, g in maps]
    try:
        master = int(data["master"])
    except (KeyError, TypeError, ValueError):
        master = 0
    if master not in game_ports:
        # 只有「不带 master 字段」的旧版主机码才走到这里。
        # 只能按最小端口猜（有洞穴时可能猜成 10998，请双方都用新版）。
        master = min(game_ports)

    return {
        "addresses": addresses,
        "base_port": base,
        "maps": maps,
        "master_port": master,
        "session": session,
    }


def decode_join_code(code: str) -> dict:
    """解析加入码 → {addresses, session}。"""
    data = _decode_payload(code, CODE_JOIN_PREFIX)
    try:
        addresses = [str(a) for a in data["addr"]]
        session = str(data["sid"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"加入码字段不完整：{exc}") from None
    if not addresses:
        raise ValueError("加入码里没有地址")
    return {"addresses": addresses, "session": session}


# ==========================================================================
# 中继就绪检测
# ==========================================================================
def check_relay_readiness(role: str = "host") -> list[tuple[bool, str, str]]:
    """检测本机能否跑 UDP 中继。

    返回 ``[(是否通过, 级别, 说明)]``，级别为 "ok" / "warn" / "fail"。
    role = "host"（我开房）或 "join"（我加入）。
    """
    results: list[tuple[bool, str, str]] = []

    # 1. 能建 UDP socket（基本前提）
    try:
        probe = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        probe.close()
        results.append((True, "ok", "本机支持 IPv6 UDP socket"))
    except OSError as exc:
        results.append((False, "fail", f"无法创建 IPv6 socket：{exc}"))

    # 2. 有公网地址（主机需要全局地址让朋友连）
    globals_v6 = global_ipv6_addresses()
    v4, _ = list_local_addresses()
    if globals_v6:
        results.append((True, "ok", f"有全局 IPv6：{globals_v6[0]}"))
        if len(globals_v6) > 1:
            results.append(
                (True, "ok",
                 f"共 {len(globals_v6)} 个全局 IPv6（已全部写进主机码，"
                 f"朋友会逐个试）")
            )
    elif role == "host":
        if v4:
            results.append(
                (False, "fail",
                 "没有全局 IPv6。主机端需要别人能直连的地址；IPv4 仅在局域网可用")
            )
        else:
            results.append((False, "fail", "没有任何可用地址"))
    else:
        results.append(
            (True, "warn",
             "本机没有全局 IPv6（不影响作为加入方，只要主机有即可）")
        )

    # 3. 主机的游戏端口：开世界后才能识别
    if role == "host":
        ports = detect_dst_ports()
        if ports:
            results.append((True, "ok", "已识别饥荒监听端口：" + "、".join(map(str, ports))))
        else:
            results.append(
                (False, "fail", "未识别到饥荒监听端口，请先在游戏里开好世界")
            )

    return results


# ---------------------------------------------------------------------------
# 主机端自检（中继专用：端口、防火墙、自环可达）
# ---------------------------------------------------------------------------

def _relay_ports_for_check(host_ports: list[int] | None,
                           count: int = 4) -> list[int]:
    """按主机规则的实际排布推算出中继要用的端口序列。

    游戏没开（拿不到端口）时按 ``count`` 个估算 —— 中继规则是
    「一个游戏端口一条」，实测典型是 4 条（主世界 + 洞穴 + 两个 Steam 端口）。
    """
    n = len(host_ports) if host_ports else count
    return [DEFAULT_RELAY_BASE + i for i in range(min(n, count))]


def can_bind_port(port: int, host: str = "::") -> tuple[bool, str]:
    """测试能否在 ``host`` 上绑定该 UDP 端口。

    两点必须与中继实际行为一致，否则结论不可信：
    1. **不设 ``SO_REUSEADDR``** —— Windows 上它允许两个进程抢绑同一端口，
       收包分流会变得不可预测。用独占绑定才能测出真实冲突。
    2. **``IPV6_V6ONLY=1``**（与 ``ForwardRule`` 默认的 ``dual_stack=False`` 一致）。
       若这里用 0（双栈）去测，而占用方是 1，Windows 会**允许两者共存**，
       于是明明被占用却报「可用」。
    """
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    try:
        if host == "::":
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.bind((host, port))
        return True, "可用"
    except OSError as exc:
        code = getattr(exc, "winerror", None) or exc.errno
        # 10048 / WSAEADDRINUSE：已被占用
        if code == 10048:
            return False, "已被其他程序占用"
        if code in (10013, 10049):  # 权限/地址不可用
            return False, f"无法绑定（{exc}）"
        return False, str(exc)
    finally:
        sock.close()


def self_loop_probe(port: int, address: str | None = None,
                    timeout: float = 0.6) -> dict:
    """从本机经**公网地址**回连自己的中继端口。

    ⚠️ 局限：本机自发自收可能走系统内部优化，**不能证明外部入站可达**。
    但它能验证很有价值的三件事：端口真的绑上了、防火墙规则对本机也生效、
    地址与端口这一对是自洽的。

    结果里的 ``denied`` 要当作**好消息**：说明包到达了中继（路径通），
    只是本机地址不在白名单里 —— 主机自己本来就不需要加入码。
    """
    globals_v6 = global_ipv6_addresses()
    target = address or (globals_v6[0] if globals_v6 else None)
    if target is None:
        v4, _ = list_local_addresses()
        target = v4[0] if v4 else None
    if target is None:
        return {"status": "error", "address": "-", "detail": "本机没有任何可用地址"}
    return probe_endpoint(target, port, timeout=timeout)


def check_host_readiness(
    host_ports: list[int] | None = None,
    *,
    session: str = "",
    join_entries: list[dict] | None = None,
    loopback: bool = True,
    loopback_timeout: float = 0.6,
) -> list[tuple[bool, str, str]]:
    """主机端中继的**完整自检**（在 ``check_relay_readiness`` 基础上补足）。

    补的三类检查正是「朋友连不上」的高频原因：
      1. 中继端口能否绑定（被占用 / 权限）
      2. Windows 防火墙是否已放行这些端口
      3. 自环可达（经公网地址回连自己）
    外加加入码与主机码一致性检查。
    """
    results = check_relay_readiness("host")
    ports = _relay_ports_for_check(host_ports)

    # 4. 中继端口能否绑定
    busy: list[int] = []
    for port in ports:
        ok, why = can_bind_port(port)
        if not ok:
            busy.append(port)
        results.append((ok, "ok" if ok else "warn",
                        f"中继端口 UDP {port}：{why}"))
    if busy:
        results.append(
            (False, "warn",
             "端口被占用不影响启动（启动时若仍占用会报错），"
             "但请确认不是另一个中继实例在跑")
        )

    # 5. Windows 防火墙放行状态
    try:
        from . import firewall

        missing = [p for p in ports if not firewall.rule_exists(p)]
        if not missing:
            results.append((True, "ok",
                            f"防火墙已放行：" + "、".join(f"UDP {p}" for p in ports)))
        else:
            results.append(
                (False, "warn",
                 "防火墙未放行：" + "、".join(f"UDP {p}" for p in missing)
                 + "（点「确认生效并启动中继」会自动放行，需管理员）")
            )
    except Exception as exc:  # noqa: BLE001
        results.append((False, "warn", f"防火墙状态查询失败：{exc}"))

    # 6. 加入码（白名单）
    entries = join_entries or []
    # 注意 allow_entries_from_codes 返回的是**地址字符串列表**，不是条目列表，
    # 所以这里自己过一遍条目，才能区分「没码」与「码没启用/校验值不匹配」。
    active = [e for e in entries if e.get("enabled", True)]
    if session:
        active = [e for e in active
                  if not e.get("session") or e["session"] == session]
    addrs: list[str] = []
    for e in active:
        for a in e.get("addresses", []):
            if a not in addrs:
                addrs.append(a)

    if not entries:
        results.append(
            (False, "warn",
             "还没有任何加入码：朋友连进来会被全部拒绝。"
             "请在「第 4 步」粘贴朋友发来的 JOIN… 码")
        )
    elif not active:
        results.append(
            (False, "warn",
             f"有 {len(entries)} 个加入码，但没有「启用且校验值匹配」的 —— "
             "朋友会被拒绝。请检查是否启用，或重新生成主机码")
        )
    else:
        shown = "、".join(addrs[:3]) + ("…" if len(addrs) > 3 else "")
        results.append(
            (True, "ok",
             f"白名单生效：{len(active)} 个加入码，{len(addrs)} 个地址（{shown}）")
        )

    # 7. 自环可达（经公网地址回连自己的中继端口）
    if loopback:
        got = self_loop_probe(ports[0], timeout=loopback_timeout)
        status = got.get("status")
        addr = got.get("address", "-")
        if status == "ok":
            results.append((True, "ok", f"自环测试：经 {addr} 回连成功"))
        elif status == "denied":
            # 主机自己不在白名单里，这是预期行为 —— 关键证明「包能到中继」
            results.append(
                (True, "ok",
                 f"自环测试：经 {addr} 包已到达中继（被白名单拒，属预期 —— "
                 f"主机自己不需要加入码）")
            )
        elif status == "refused":
            results.append(
                (False, "warn",
                 f"自环测试：{addr} 端口没人监听（中继尚未启动，属正常）")
            )
        elif status == "timeout":
            results.append(
                (False, "warn",
                 f"自环测试：经 {addr} 无响应 —— 可能被防火墙拦住本机入站，"
                 f"或该地址不可用")
            )
        else:
            results.append((False, "warn", f"自环测试：{addr} → {status}"))

    return results


# ==========================================================================
# 加入码持久化（主机端管理）
# ==========================================================================
def _store_dir() -> str:
    from . import config as _config

    base = os.environ.get("APPDATA") or os.path.expanduser("~")
    path = os.path.join(base, _config.CONFIG_DIR_NAME)
    os.makedirs(path, exist_ok=True)
    return path


def _store_file() -> str:
    return os.path.join(_store_dir(), "relay_join_codes.json")


def load_join_codes() -> list[dict]:
    """读取主机端保存的加入码列表。文件损坏/不存在都返回空列表。"""
    try:
        with open(_store_file(), encoding="utf-8") as handle:
            data = json.load(handle)
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
    except (OSError, ValueError):
        pass
    return []


def save_join_codes(entries: list[dict]) -> None:
    """覆盖写加入码列表。只保留必要字段。"""
    clean = [
        {
            "addresses": [str(a) for a in item.get("addresses", [])],
            "session": str(item.get("session", "")),
            "note": str(item.get("note", "")),
            "enabled": bool(item.get("enabled", True)),
        }
        for item in entries
    ]
    path = _store_file()
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(clean, handle, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def allow_entries_from_codes(entries: list[dict], session: str = "") -> list[str]:
    """把启用的加入码变成白名单条目（CIDR 形式的单个地址）。

    session 非空时只收校验值匹配的码（防止把上一次的旧码放进来）。
    """
    entries_set: list[str] = []
    for item in entries:
        if not item.get("enabled", True):
            continue
        if session and item.get("session") and item["session"] != session:
            continue
        for addr in item.get("addresses", []):
            if addr not in entries_set:
                entries_set.append(addr)
    return entries_set


def build_guest_rules(host_info: dict) -> list[tuple[str, str]]:
    """加入方根据主机码生成 ``(listen, target)`` 规则列表。

    用主机码里**第一个**地址做目标（主机生成时全局 IPv6 已排最前）。
    """
    target_host = host_info["addresses"][0]
    host_part = f"[{target_host}]" if ":" in target_host else target_host
    rules: list[tuple[str, str]] = []
    for relay_port, game_port in host_info["maps"]:
        rules.append(
            (format_endpoint("127.0.0.1", game_port), f"{host_part}:{relay_port}")
        )
    return rules


# ---------------------------------------------------------------------------
# 连通性探测（加入方 -> 主机中继）
# ---------------------------------------------------------------------------

def probe_endpoint(host: str, port: int, timeout: float = 1.5) -> dict:
    """向某个中继端口发一个探测包，返回结果字典。

    状态含义：
      ``ok``      包到达主机且通过白名单（路是通的）
      ``denied``  包到达主机但**被白名单拒绝**（地址没加对）
      ``timeout`` 包根本没到主机（防火墙 / 光猫路由 / 地址写错）
      ``error``   本机发送就失败了
    """
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    result: dict = {
        "address": format_endpoint(host, port),
        "status": "timeout",
        "rtt_ms": None,
        "detail": "",
    }
    try:
        started = time.monotonic()
        sock.sendto(PROBE_MAGIC + secrets.token_bytes(4), (host, port))
        data, _ = sock.recvfrom(256)
        result["rtt_ms"] = round((time.monotonic() - started) * 1000, 1)
        if data.startswith(PROBE_REPLY_OK):
            result["status"] = "ok"
        elif data.startswith(PROBE_REPLY_DENIED):
            result["status"] = "denied"
        else:
            result["status"] = "unknown"
    except socket.timeout:
        result["status"] = "timeout"
    except OSError as exc:
        # UDP 收到 ICMP 端口不可达时，Windows 会在后续 recvfrom 报
        # WSAECONNRESET(10054) / WSAECONNREFUSED(10061)。
        # 这反而是好消息：**包能到那台机器**，只是那个端口没人监听。
        if getattr(exc, "winerror", None) in (10054, 10061):
            result["status"] = "refused"
        else:
            result["status"] = "error"
            result["detail"] = str(exc)
    finally:
        sock.close()
    return result


def probe_host_info(host_info: dict, timeout: float = 1.5,
                    max_addresses: int = 3) -> list[dict]:
    """对主机码里的每个地址探测**主世界那条映射**的端口。

    只探主世界那一条：能通就说明整条路可用，全探太慢。
    """
    addresses = list(host_info.get("addresses") or [])[:max_addresses]
    maps = list(host_info.get("maps") or [])
    master = host_info.get("master_port")
    relay_port = next((rp for rp, gp in maps if gp == master), None)
    if relay_port is None and maps:
        relay_port = maps[0][0]
    if relay_port is None:
        return []
    return [probe_endpoint(addr, relay_port, timeout) for addr in addresses]


def describe_probe(results: list[dict]) -> list[str]:
    """把探测结果转成人话。"""
    label = {
        "ok": "✅ 通",
        "denied": "⛔ 包到了主机，但被白名单拒绝（地址没加对）",
        "refused": "⚠ 包到了那台机器，但端口没人监听（中继没启动？）",
        "timeout": "❌ 无响应：包没到主机（防火墙 / 光猫路由 / 地址写错）",
        "unknown": "⚠ 收到非预期回包",
        "error": "⚠ 本机发送失败",
    }
    lines = []
    for r in results:
        text = label.get(r["status"], r["status"])
        extra = f"（{r['rtt_ms']} ms）" if r.get("rtt_ms") else ""
        detail = f"  {r['detail']}" if r.get("detail") else ""
        lines.append(f"  {r['address']}  {text}{extra}{detail}")
    return lines


def format_address_report() -> list[str]:
    """给用户看的本机地址清单。"""
    v4, v6 = list_local_addresses()
    lines = ["本机地址："]
    lines.append("  IPv4：" + ("、".join(v4) if v4 else "（无）"))
    lines.append("  IPv6：" + ("、".join(v6) if v6 else "（无）"))

    globals_v6 = [a for a in v6 if _address_rank(a) == 0]
    if globals_v6:
        lines.append("")
        lines.append("主机侧要告诉朋友的地址（挑一个全局 IPv6）：")
        lines.append(f"  {globals_v6[0]}")
        lines.append(
            f"  朋友侧示例：--map 127.0.0.1:10999=[{globals_v6[0]}]:20000"
        )
    else:
        lines.append("")
        lines.append(
            "没有找到全局 IPv6 地址。可能是宽带没开通 IPv6，"
            "或者 IPV6 协议栈被禁用了。"
        )
        if v4:
            lines.append(
                "退而求其次：如果走的是同一局域网 / 虚拟局域网（Tailscale 等），"
                f"也可以用 IPv4 地址 {v4[0]}。"
            )
    return lines


# ==========================================================================
# 自动识别饥荒端口
# ==========================================================================
def detect_dst_ports() -> list[int]:
    """读系统 UDP 表，拿到饥荒真正监听的端口。

    ``winproc`` 是可选依赖（本项目自带），这样 relay 单独拷走也能当通用
    转发器用，只是没有自动识别。
    """
    try:
        from . import winproc
    except ImportError:
        # 被当作独立脚本运行（python dst_ip_join/relay.py）
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if root not in sys.path:
            sys.path.insert(0, root)
        from dst_ip_join import winproc

    pids = {proc.pid for proc in winproc.find_dst_processes()}
    if not pids:
        return []
    return winproc.get_dst_listen_ports(pids)


def build_auto_rules(
    base_port: int,
    *,
    listen_host: str = "::",
    ports: list[int] | None = None,
    dual_stack: bool = False,
    allow: AddressAllowList | None = None,
    peer_bind: str = "",
    max_peers: int = 32,
) -> tuple[list[ForwardRule], list[str]]:
    """为每个饥荒监听端口生成一条 ``[::]:base+i -> 127.0.0.1:port`` 规则。

    返回 ``(规则列表, 给朋友侧的对照说明)``。端口按升序排列，保证两端编号一致。
    """
    detected = sorted(ports if ports else detect_dst_ports())
    if not detected:
        return [], []

    # 朋友侧要填的是「主机公网地址」，这里只留占位符
    placeholder = "[<你的IPv6>]" if ":" in listen_host else "<你的IPv4>"

    rules: list[ForwardRule] = []
    hints: list[str] = ["朋友侧中继请这样配（把占位符换成主机的公网地址）："]
    for offset, game_port in enumerate(detected):
        relay_port = base_port + offset
        rules.append(
            ForwardRule(
                format_endpoint(listen_host, relay_port),
                format_endpoint("127.0.0.1", game_port),
                allow=allow,
                peer_bind=peer_bind,
                dual_stack=dual_stack,
                max_peers=max_peers,
            )
        )
        hints.append(
            f"  --map {format_endpoint('127.0.0.1', game_port)}={placeholder}:{relay_port}"
            f"    （对应游戏端口 {game_port}）"
        )
    return rules, hints


# ==========================================================================
# 命令行
# ==========================================================================
@dataclass
class RelayOptions:
    maps: list[str] = field(default_factory=list)
    allow: list[str] = field(default_factory=list)
    peer_bind: str = ""
    dual_stack: bool = False
    idle_timeout: float = 300.0
    max_peers: int = 32
    stats_interval: float = 0.0
    verbose: bool = False
    max_seconds: float = 0.0
    auto_ports: bool = False
    auto_base: int = 20000
    auto_listen: str = "::"
    ports: str = ""


def _fix_console_encoding() -> None:
    """中文 Windows 控制台是 GBK，遇到生僻字符会抛 UnicodeEncodeError。"""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except Exception:  # noqa: BLE001
            pass


def _parse_maps(entries: list[str]) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for entry in entries:
        if "=" not in entry:
            raise ValueError(f"--map 要写成 监听=目标，收到的是 {entry!r}")
        listen, _, target = entry.partition("=")
        listen, target = listen.strip(), target.strip()
        parse_endpoint(listen)  # 提前校验，错误信息更清楚
        parse_endpoint(target)
        pairs.append((listen, target))
    return pairs


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dst-relay",
        description="UDP 中继：两端各跑一份，把任意两段 UDP 通路缝起来（不解析协议）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "示例\n"
            "  主机侧（自动识别饥荒端口，在 [::]:20000 起中继）\n"
            "    python -m dst_ip_join.relay --auto-ports --auto-base 20000 "
            "--allow 2409:8a60::/32\n\n"
            "  朋友侧（连主机的 20000，本地伪装成 127.0.0.1:10999）\n"
            "    python -m dst_ip_join.relay "
            "--map 127.0.0.1:10999=[2409:8a60:cc40:8ea4::1]:20000\n\n"
            "  手工指定（不依赖饥荒进程识别）\n"
            "    python -m dst_ip_join.relay --map \"[::]:20000=127.0.0.1:10999\"\n\n"
            "  查本机该填什么地址\n"
            "    python -m dst_ip_join.relay --show-address\n"
        ),
    )
    parser.add_argument(
        "--map",
        action="append",
        default=[],
        metavar="监听=目标",
        help="一条转发规则，可重复。IPv6 要写方括号，例如 \"[::]:20000=127.0.0.1:10999\"",
    )
    parser.add_argument(
        "--auto-ports",
        action="store_true",
        help="自动读系统 UDP 表识别饥荒监听端口，为每个端口生成一条规则（需管理员可省）",
    )
    parser.add_argument(
        "--auto-base",
        type=int,
        default=20000,
        metavar="PORT",
        help="自动模式下的起始监听端口，默认 20000",
    )
    parser.add_argument(
        "--auto-listen",
        default="::",
        metavar="HOST",
        help="自动模式下的监听地址，默认 ::（所有 IPv6）",
    )
    parser.add_argument(
        "--ports",
        default="",
        metavar="10999,10998",
        help="配合 --auto-ports 使用：跳过进程识别，直接按这些端口生成规则",
    )
    parser.add_argument(
        "--allow",
        action="append",
        default=[],
        metavar="地址或CIDR",
        help="来源白名单，可重复，例如 2409:8a60::/32；不填则不限制",
    )
    parser.add_argument(
        "--peer-bind",
        default="",
        metavar="地址:端口",
        help="强制朝游戏那一侧的套接字绑定地址（默认自动：目标是回环时分独立的 127.0.0.x）",
    )
    parser.add_argument(
        "--dual-stack",
        action="store_true",
        help="监听 :: 时同时接受 IPv4 连接（默认只收 IPv6）",
    )
    parser.add_argument(
        "--idle",
        type=float,
        default=300.0,
        metavar="秒",
        help="空闲超过这么久就回收该 peer，0 表示不回收（默认 300）",
    )
    parser.add_argument(
        "--max-peers",
        type=int,
        default=32,
        metavar="N",
        help="每条规则最多同时中继几路连接（默认 32）",
    )
    parser.add_argument(
        "--stats",
        type=float,
        default=0.0,
        metavar="秒",
        help="每隔多少秒打印一次流量统计，0 表示只在退出时打印（默认 0）",
    )
    parser.add_argument(
        "--show-address",
        action="store_true",
        help="只打印本机 IPv4 / IPv6 地址然后退出（配 --map 时用得到）",
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=0.0,
        metavar="秒",
        help="跑够这么久就自动退出（默认一直跑，Ctrl+C 停止）",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="打印每次收发与清理细节")
    return parser


def build_rules_from_options(opts: RelayOptions) -> tuple[list[ForwardRule], list[str]]:
    """把命令行选项变成实际的转发规则。"""
    allow = AddressAllowList(opts.allow)
    rules: list[ForwardRule] = []
    hints: list[str] = []

    if opts.auto_ports or opts.ports:
        ports: list[int] | None = None
        if opts.ports:
            ports = [int(p) for p in opts.ports.replace("，", ",").split(",") if p.strip()]
        auto_rules, hints = build_auto_rules(
            opts.auto_base,
            listen_host=opts.auto_listen,
            ports=ports,
            dual_stack=opts.dual_stack,
            allow=allow,
            peer_bind=opts.peer_bind,
            max_peers=opts.max_peers,
        )
        if not auto_rules:
            raise RuntimeError(
                "没找到饥荒的监听端口。请先在游戏里开好世界，"
                "或者用 --map 手工指定，或用 --ports 直接给端口号。"
            )
        rules.extend(auto_rules)

    for listen_text, target_text in _parse_maps(opts.maps):
        rules.append(
            ForwardRule(
                listen_text,
                target_text,
                allow=allow,
                peer_bind=opts.peer_bind,
                dual_stack=opts.dual_stack,
                max_peers=opts.max_peers,
            )
        )

    if not rules:
        raise RuntimeError("没有任何转发规则，请用 --map 指定，或加 --auto-ports。")

    return rules, hints


def _print_banner(rules: list[ForwardRule], hints: list[str], idle: float, log) -> None:
    log(f"已建立 {len(rules)} 条转发规则（纯 UDP 转发，不解析任何协议）：")
    for rule in rules:
        log(f"  {rule.listen_text_full}  <->  {rule.target_text_full}")
        note = f"      来源限制：{rule.allow.describe()}"
        if rule.free_loopback_slots:
            note += f"；每位朋友独占一个 127.0.0.x 回环地址（池 {rule.free_loopback_slots}）"
        log(note)
    if hints:
        log("")
        for line in hints:
            log(line)
    log("")
    log(f"空闲回收 {idle:g} 秒；按 Ctrl+C 停止")


def main(argv: list[str] | None = None) -> int:
    _fix_console_encoding()
    parser = _build_parser()
    args = parser.parse_args(argv)

    def log(text: str = "") -> None:
        print(text, flush=True)

    if args.show_address:
        for line in format_address_report():
            log(line)
        return 0

    opts = RelayOptions(
        maps=args.map,
        allow=args.allow,
        peer_bind=args.peer_bind,
        dual_stack=args.dual_stack,
        idle_timeout=args.idle,
        max_peers=args.max_peers,
        stats_interval=args.stats,
        verbose=args.verbose,
        max_seconds=args.duration,
        auto_ports=args.auto_ports,
        auto_base=args.auto_base,
        auto_listen=args.auto_listen,
        ports=args.ports,
    )

    try:
        rules, hints = build_rules_from_options(opts)
    except (ValueError, RuntimeError, OSError) as exc:
        log(f"无法启动：{exc}")
        return 2

    _print_banner(rules, hints, opts.idle_timeout, log)

    relay = UdpRelay(
        rules,
        idle_timeout=opts.idle_timeout,
        verbose=opts.verbose,
        stats_interval=opts.stats_interval,
        log=log,
    )

    try:
        relay.run(max_seconds=opts.max_seconds)
    except KeyboardInterrupt:
        log("")
        log("收到中断，正在收尾……")
        relay.stop()
    except OSError as exc:
        log(f"运行中断：{exc}")
        relay.stop()
        return 1

    log("")
    for line in relay.summary_lines():
        log(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
