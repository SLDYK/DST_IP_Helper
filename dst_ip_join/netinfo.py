# -*- coding: utf-8 -*-
"""网络信息检测：本机地址、公网出口 IP、STUN NAT 类型判定。

全部基于标准库实现：
  * 公网 IP   —— 轮询多个国内可达的 HTTP 接口，用正则抓 IPv4
  * NAT 判定  —— 自己实现 STUN Binding Request（RFC 5389），
                 用同一个本地端口向两台不同的 STUN 服务器查询，
                 比较路由器分给我们的映射端口，从而区分
                 「端点无关映射（好 NAT）」与「对称 NAT（难搞）」
"""

from __future__ import annotations

import ipaddress
import os
import re
import socket
import struct
import urllib.error
import urllib.request
from dataclasses import dataclass, field

from . import config, winproc

# --------------------------------------------------------------------------
# STUN 协议常量（RFC 5389）
# --------------------------------------------------------------------------
_STUN_MAGIC_COOKIE = 0x2112A442
_STUN_BINDING_REQUEST = 0x0001
_STUN_BINDING_SUCCESS = 0x0101
_ATTR_MAPPED_ADDRESS = 0x0001
_ATTR_XOR_MAPPED_ADDRESS = 0x0020

_IPV4_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")

# 直连 opener：不使用任何代理。
# UPnP / STUN 必须直连；公网 IP 查询如果走系统代理会拿到代理出口的 IP，是错的。
_DIRECT_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _system_proxy_opener() -> urllib.request.OpenerDirector:
    """走系统代理的 opener（仅在直连失败时作为兜底）。"""
    return urllib.request.build_opener()


# ==========================================================================
# IP 工具
# ==========================================================================
def is_valid_ipv4(text: str) -> bool:
    try:
        ipaddress.IPv4Address(text)
        return True
    except ValueError:
        return False


def classify_ip(text: str) -> str:
    """返回 'cgnat' / 'private' / 'loopback' / 'public' / 'invalid'。"""
    try:
        addr = ipaddress.IPv4Address(text)
    except ValueError:
        return "invalid"

    cgnat = ipaddress.ip_network(config.CGNAT_NETWORK)
    if addr in cgnat:
        return "cgnat"
    if addr.is_loopback:
        return "loopback"
    if addr.is_private:
        return "private"
    return "public"


# ==========================================================================
# 本机地址
# ==========================================================================
def get_local_ips() -> list[str]:
    """本机可用 IPv4 列表，默认出口网卡的地址排在最前。"""
    addresses = winproc.get_local_ipv4_addresses()
    primary = winproc.get_primary_local_ip()

    ordered: list[str] = []
    if primary and primary not in ordered:
        ordered.append(primary)
    for addr in addresses:
        if addr not in ordered:
            ordered.append(addr)
    return ordered


# ==========================================================================
# 公网出口 IP
# ==========================================================================
def _http_get_text(url: str, opener, timeout: float) -> str:
    request = urllib.request.Request(
        url, headers={"User-Agent": "curl/8.0", "Accept": "*/*"}
    )
    with opener.open(request, timeout=timeout) as response:
        return response.read(8192).decode("utf-8", "ignore")


def get_public_ip(log=None, allow_proxy_fallback: bool = True) -> tuple[str, str, bool]:
    """查询本机公网出口 IP。

    返回 ``(ip, 来源名称, 是否经过代理)``；全部失败时返回 ``("", "", False)``。
    """
    errors: list[str] = []

    # 第一轮：直连（结果最可信）
    for name, url in config.PUBLIC_IP_APIS:
        try:
            text = _http_get_text(url, _DIRECT_OPENER, config.HTTP_TIMEOUT)
        except Exception as exc:  # noqa: BLE001 - 网络异常种类很多，统一兜住
            errors.append(f"{name}: {exc}")
            continue
        match = _IPV4_RE.search(text)
        if match and is_valid_ipv4(match.group(1)):
            return match.group(1), name, False
        errors.append(f"{name}: 返回内容无法解析 -> {text[:60]!r}")

    if log:
        for line in errors:
            log(f"    直连失败 {line}")

    # 第二轮：走系统代理（有些网络环境必须先过代理才能出网）
    if allow_proxy_fallback:
        try:
            proxy_opener = _system_proxy_opener()
        except Exception:
            proxy_opener = None

        if proxy_opener is not None:
            if log:
                log("    改用系统代理重试公网 IP 查询……")
            for name, url in config.PUBLIC_IP_APIS[:3]:
                try:
                    text = _http_get_text(url, proxy_opener, config.HTTP_TIMEOUT)
                except Exception:
                    continue
                match = _IPV4_RE.search(text)
                if match and is_valid_ipv4(match.group(1)):
                    if log:
                        log("    注意：该结果经过代理，可能不是你的真实公网 IP")
                    return match.group(1), f"{name}(代理)", True

    return "", "", False


# ==========================================================================
# STUN
# ==========================================================================
@dataclass
class StunResult:
    mapped_ip: str
    mapped_port: int
    local_port: int


def _parse_stun_response(data: bytes, txn: bytes) -> tuple[str, int] | None:
    if len(data) < 20:
        return None
    msg_type, msg_len, cookie = struct.unpack(">HHI", data[:8])
    if cookie != _STUN_MAGIC_COOKIE:
        return None
    if data[8:20] != txn:
        return None  # 事务 ID 不匹配，丢弃
    if msg_type != _STUN_BINDING_SUCCESS:
        return None

    body = data[20 : 20 + msg_len]
    offset = 0
    plain: tuple[str, int] | None = None
    xor: tuple[str, int] | None = None

    while offset + 4 <= len(body):
        attr_type, attr_len = struct.unpack(">HH", body[offset : offset + 4])
        value = body[offset + 4 : offset + 4 + attr_len]
        offset += 4 + attr_len + ((4 - attr_len % 4) % 4)  # 4 字节对齐

        if attr_type not in (_ATTR_MAPPED_ADDRESS, _ATTR_XOR_MAPPED_ADDRESS):
            continue
        if len(value) < 8 or value[1] != 0x01:  # family 1 = IPv4
            continue

        port_raw, ip_raw = struct.unpack(">HI", value[2:8])
        if attr_type == _ATTR_XOR_MAPPED_ADDRESS:
            port = port_raw ^ (_STUN_MAGIC_COOKIE >> 16)
            ip_int = ip_raw ^ _STUN_MAGIC_COOKIE
        else:
            port = port_raw
            ip_int = ip_raw

        ip_text = socket.inet_ntoa(struct.pack(">I", ip_int))
        if attr_type == _ATTR_XOR_MAPPED_ADDRESS:
            xor = (ip_text, port)
        else:
            plain = (ip_text, port)

    return xor or plain


def stun_query(
    server: tuple[str, int], source_port: int = 0
) -> StunResult | None:
    """向一台 STUN 服务器发 Binding Request，拿回路由器映射后的公网端点。"""
    txn = os.urandom(12)
    request = struct.pack(
        ">HHI12s", _STUN_BINDING_REQUEST, 0, _STUN_MAGIC_COOKIE, txn
    )

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except OSError:
        return None

    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("0.0.0.0", source_port))
        except OSError:
            # 指定端口被占用则退回随机端口；再失败就放弃这次探测
            if not source_port:
                return None
            try:
                sock.bind(("0.0.0.0", 0))
            except OSError:
                return None

        local_port = sock.getsockname()[1]
        sock.settimeout(config.STUN_TIMEOUT)

        for _ in range(config.STUN_RETRIES):
            try:
                sock.sendto(request, server)
                data, _ = sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                return None

            parsed = _parse_stun_response(data, txn)
            if parsed:
                return StunResult(parsed[0], parsed[1], local_port)
        return None
    finally:
        sock.close()


@dataclass
class NatInfo:
    available: bool = False
    mapped_ip: str = ""
    mapped_port: int = 0
    local_port: int = 0
    servers_ok: int = 0
    # None = 信息不足；True = 端点无关映射（好）；False = 对称 NAT（难）
    endpoint_independent: bool | None = None
    port_preserved: bool = False
    notes: list[str] = field(default_factory=list)


def _pick_free_udp_port() -> int:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind(("0.0.0.0", 0))
            return sock.getsockname()[1]
        finally:
            sock.close()
    except OSError:
        return 0


# ==========================================================================
# 双重 NAT 支持
# ==========================================================================
def tcp_reachable(ip: str, port: int = 80, timeout: float = 1.0) -> bool:
    """能否建立到 ip:port 的 TCP 连接（用于判断上级网关是否真的可达）。"""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def upstream_gateway_candidates(wan_ip: str) -> list[str]:
    """从一个私有 WAN 地址推导上层网关的可能地址。

    家庭网络里上层设备几乎总在自己网段的 .1（少数型号用 .254），
    所以直接拿这两个地址去探，比扫整个网段快得多。
    """
    if classify_ip(wan_ip) != "private":
        return []

    octets = wan_ip.split(".")
    if len(octets) != 4:
        return []

    prefix = ".".join(octets[:3])
    candidates = [f"{prefix}.1", f"{prefix}.254"]
    return [ip for ip in dict.fromkeys(candidates) if ip != wan_ip]


def detect_nat(log=None) -> NatInfo:
    """用同一本地端口轮询多台 STUN 服务器，推断 NAT 行为。"""
    info = NatInfo()

    probe_port = _pick_free_udp_port()
    results: list[tuple[tuple[str, int], StunResult]] = []
    tried = 0

    for server in config.STUN_SERVERS:
        if tried >= config.STUN_MAX_SERVERS:
            break
        tried += 1
        result = stun_query(server, source_port=probe_port)
        if result is None:
            if log:
                log(f"    STUN {server[0]}:{server[1]} 无响应")
            continue
        results.append((server, result))
        info.servers_ok += 1
        if log:
            log(
                f"    STUN {server[0]} -> 映射为 {result.mapped_ip}:{result.mapped_port}"
                f"（本机 {result.local_port}）"
            )
        # 拿到 2 台即可比较映射行为，不必把剩余服务器跑完
        if info.servers_ok >= 2:
            break

    if not results:
        info.notes.append("所有 STUN 服务器均无响应，无法判断 NAT 类型")
        return info

    info.available = True
    first = results[0][1]
    info.mapped_ip = first.mapped_ip
    info.mapped_port = first.mapped_port
    info.local_port = first.local_port
    info.port_preserved = first.mapped_port == first.local_port

    if len(results) >= 2:
        same_ip_port = all(
            r.mapped_ip == first.mapped_ip and r.mapped_port == first.mapped_port
            for _, r in results[1:]
        )
        info.endpoint_independent = same_ip_port
        if info.endpoint_independent:
            info.notes.append("NAT 映射稳定，端口映射会生效")
        else:
            info.notes.append("疑似对称 NAT，外部主动连接较难建立")
    else:
        info.notes.append("只有一台 STUN 服务器响应，NAT 类型未知")

    if info.port_preserved:
        info.notes.append("公网端口与本地端口一致，NAT 未改写端口号")

    return info
