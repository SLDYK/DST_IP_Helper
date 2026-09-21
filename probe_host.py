# -*- coding: utf-8 -*-
"""网络设备排查小工具（可选，用于双重 NAT 场景）。

用来搞清楚「上一级设备到底是什么、开了哪些服务、为什么 UPnP 不通」，
方便决定是去它的管理页面做端口映射 / DMZ，还是干脆改桥接。

用法：
    python probe_host.py 192.168.1.1
    python probe_host.py 192.168.1.1 --ports 80,443,8080,1900,52869
"""

from __future__ import annotations

import argparse
import socket
import sys
import time
import urllib.error
import urllib.request

DEFAULT_PORTS = (80, 443, 8080, 1900, 52869, 52870, 37251, 5555, 5000)

PROXY_FREE_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))

SSDP_TARGETS = (
    "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "upnp:rootdevice",
    "ssdp:all",
)


def scan_tcp(host: str, ports: list[int], timeout: float = 0.8) -> list[int]:
    open_ports: list[int] = []
    for port in ports:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                open_ports.append(port)
        except OSError:
            continue
    return open_ports


def http_identify(host: str, ports: list[int]) -> None:
    for port in ports:
        if port in (1900, 52869):
            continue  # 这些不是 Web 端口
        url = f"http://{host}:{port}/"
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with PROXY_FREE_OPENER.open(request, timeout=2.0) as response:
                body = response.read(2000).decode("utf-8", "ignore")
                print(f"  {url} -> HTTP {response.status}  Server={response.headers.get('Server')!r}")
                _print_title(body)
        except urllib.error.HTTPError as exc:
            print(f"  {url} -> HTTP {exc.code}  Server={exc.headers.get('Server')!r}")
        except Exception as exc:  # noqa: BLE001
            print(f"  {url} -> {type(exc).__name__}: {exc}")


def _print_title(body: str) -> None:
    lowered = body.lower()
    start = lowered.find("<title>")
    if start < 0:
        return
    end = lowered.find("</title>", start)
    title = body[start + 7 : end if end > 0 else None].strip()
    if title:
        print(f"      页面标题：{title}")


def unicast_ssdp(host: str) -> None:
    """单播 M-SEARCH。设备完全不响应通常就等于「UPnP 已关闭」。"""
    for target in SSDP_TARGETS:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.5)
        message = (
            "M-SEARCH * HTTP/1.1\r\n"
            f"HOST: {host}:1900\r\n"
            'MAN: "ssdp:discover"\r\n'
            "MX: 2\r\n"
            f"ST: {target}\r\n"
            "\r\n"
        )
        try:
            sock.sendto(message.encode("ascii"), (host, 1900))
            data, addr = sock.recvfrom(4096)
            print(f"  ST={target}")
            for line in data.decode("latin-1", "replace").splitlines():
                if line.strip():
                    print(f"      {line.strip()}")
        except socket.timeout:
            print(f"  ST={target} -> 无响应")
        except OSError as exc:
            print(f"  ST={target} -> {exc}")
        finally:
            sock.close()
        time.sleep(0.2)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="排查局域网内某台设备开放了哪些服务")
    parser.add_argument("host", help="目标 IP，例如 192.168.1.1")
    parser.add_argument("--ports", help="自定义端口列表，逗号分隔")
    args = parser.parse_args(argv)

    ports = list(DEFAULT_PORTS)
    if args.ports:
        ports = [int(p) for p in args.ports.replace("，", ",").split(",") if p.strip()]

    print(f"=== 探测 {args.host} ===\n")

    print("[TCP 端口]")
    open_ports = scan_tcp(args.host, ports)
    if open_ports:
        for port in open_ports:
            print(f"  {port}  OPEN")
    else:
        print("  没有端口响应")

    print("\n[HTTP 服务标识]")
    http_identify(args.host, open_ports)

    print("\n[单播 SSDP（UPnP 探测）]")
    unicast_ssdp(args.host)

    print()
    if 1900 in open_ports:
        print("结论：SSDP 端口开放但无响应，UPnP 大概率被关闭了")
    else:
        print("结论：设备在线但完全未响应 UPnP —— 需要手动做端口映射或设 DMZ")
    return 0


if __name__ == "__main__":
    sys.exit(main())
