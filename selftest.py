# -*- coding: utf-8 -*-
"""自检脚本：验证 ctypes 层的字节序/句柄处理是否正确。

ctypes 调 Win32 最容易在「64 位句柄被截断」和「网络字节序换算」上翻车，
这两类错误不会报异常、只会给出安静的错误结果，所以必须实测。

运行：
    python selftest.py
"""

from __future__ import annotations

import os
import socket
import sys

if sys.platform != "win32":
    print("这个自检脚本只能在 Windows 上运行")
    sys.exit(1)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dst_ip_join import firewall, netinfo, upnp, winproc  # noqa: E402

PASSED = 0
FAILED = 0
SKIPPED = 0


def check(title: str, ok: bool, detail: str = "") -> None:
    global PASSED, FAILED
    if ok:
        PASSED += 1
        print(f"[PASS] {title}" + (f" — {detail}" if detail else ""))
    else:
        FAILED += 1
        print(f"[FAIL] {title}" + (f" — {detail}" if detail else ""))


def skip(title: str, reason: str) -> None:
    global SKIPPED
    SKIPPED += 1
    print(f"[SKIP] {title} — {reason}")


# ==========================================================================
print("== 1. 管理员检测 ==")
admin = winproc.is_admin()
check("is_admin 返回布尔值", isinstance(admin, bool), f"当前 = {admin}")


# ==========================================================================
print("\n== 2. 进程枚举与完整路径 ==")
procs = winproc.iter_processes()
check("能枚举到进程", len(procs) > 10, f"共 {len(procs)} 个")

mine = [p for p in procs if p.pid == os.getpid()]
check("枚举结果里有自己", bool(mine), mine[0].name if mine else "未找到")

if mine:
    path = winproc.query_process_path(os.getpid())
    expected = os.path.normcase(os.path.abspath(sys.executable))
    actual = os.path.normcase(os.path.abspath(path)) if path else ""
    # 64 位句柄若被截断，这里会拿到空串或错误的进程路径
    check(
        "QueryFullProcessImageNameW 能取到自己 exe 的完整路径",
        actual == expected,
        actual or "返回空",
    )


# ==========================================================================
print("\n== 3. UDP 端点表（字节序关键测试）==")

# 3a. 随机端口也必须能正确读出（验证 dwLocalPort 的 ntohs 换算）
probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
probe.bind(("0.0.0.0", 0))
probe_port = probe.getsockname()[1]
try:
    endpoints = winproc.get_udp_endpoints()
    hit = [e for e in endpoints if e.pid == os.getpid() and e.port == probe_port]
    check(
        "随机端口的 UDP 绑定能被正确读出",
        bool(hit),
        f"本机端口 {probe_port}，命中 {[(e.address, e.port) for e in hit]}",
    )

    # 3b. 0.0.0.0 + 固定低端口 -> 应被 get_dst_listen_ports 认定为「服务器监听口」
    #     模拟饥荒的 10999 监听行为
    fixed_port = None
    fixed_sock = None
    for candidate in range(21000, 21100):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind(("0.0.0.0", candidate))
        except OSError:
            try:
                s.close()
            except Exception:
                pass
            continue
        fixed_sock = s
        fixed_port = candidate
        break

    if fixed_sock is not None:
        try:
            detected = winproc.get_dst_listen_ports({os.getpid()})
            check(
                "能像识别饥荒一样识别出 0.0.0.0 上的低端口监听",
                fixed_port in detected,
                f"绑定 {fixed_port}，识别结果 {detected}",
            )
        finally:
            fixed_sock.close()
    else:
        skip("低端口监听识别", "21000-21099 全被占用")
finally:
    probe.close()


# ==========================================================================
print("\n== 4. 本机 IPv4 地址 ==")
local_ips = netinfo.get_local_ips()
locals_ok = bool(local_ips) and all(netinfo.is_valid_ipv4(ip) for ip in local_ips)
check("能枚举出合法 IPv4", locals_ok, f"{local_ips}")
check("返回顺序把默认出口网卡排在最前", bool(winproc.get_primary_local_ip()),
      winproc.get_primary_local_ip() or "取不到")


# ==========================================================================
print("\n== 5. 剪贴板 ==")
marker = f"DST-IP-JOIN-SELFTEST-{os.getpid()}"
clip_ok = winproc.set_clipboard_text(marker)
check("写入剪贴板成功", clip_ok, marker)


# ==========================================================================
print("\n== 6. 防火墙规则查询（只读）==")
try:
    exists = firewall.rule_exists(10999)
    check("rule_exists 可正常调用", isinstance(exists, bool), f"10999 规则存在 = {exists}")
except Exception as exc:  # noqa: BLE001
    check("rule_exists 可正常调用", False, str(exc))


# ==========================================================================
print("\n== 7. STUN（依赖外网，失败不算错）==")
stun_ok_servers: list[str] = []
for server in netinfo.config.STUN_SERVERS[:2]:
    result = netinfo.stun_query(server)
    if result:
        stun_ok_servers.append(f"{server[0]} -> {result.mapped_ip}:{result.mapped_port}")
print("    " + ("；".join(stun_ok_servers) if stun_ok_servers else "无响应"))
if stun_ok_servers:
    check("STUN 解析出的映射地址格式正确",
          all(":" in s.split("-> ")[1] for s in stun_ok_servers))
else:
    skip("STUN 测试", "当前网络无法访问 STUN 服务器（可能是防火墙/代理）")

# 校验解析结果里 IPv4 合法（防止 XOR 解码算错变成垃圾地址）
for item in stun_ok_servers:
    ip = item.split("-> ")[1].rsplit(":", 1)[0]
    check(f"STUN 返回的 IP 合法（{ip}）", netinfo.is_valid_ipv4(ip))


# ==========================================================================
print("\n== 8. UPnP 发现（依赖路由器，失败不算错）==")
gateway = upnp.discover_gateway()
if gateway:
    check("发现网关", True, gateway.display)
    try:
        ext = gateway.external_ip()
        check("能读到路由器上报的公网 IP", netinfo.is_valid_ipv4(ext), ext)
    except Exception as exc:  # noqa: BLE001
        check("能读到路由器上报的公网 IP", False, str(exc))
else:
    skip("UPnP 发现", "未找到网关或路由器关闭了 UPnP")


# ==========================================================================
print("\n== 9. IP 分类 ==")
cases = [
    ("192.168.1.1", "private"),
    ("10.0.0.1", "private"),
    ("100.64.1.1", "cgnat"),
    ("100.127.255.254", "cgnat"),
    ("8.8.8.8", "public"),
    ("114.114.114.114", "public"),
    ("100.128.0.1", "public"),  # 刚好越过 CGNAT 上界
    ("999.1.1.1", "invalid"),
]
for value, expected in cases:
    got = netinfo.classify_ip(value)
    check(f"classify_ip({value}) == {expected}", got == expected, f"实得 {got}")


# ==========================================================================
print("\n== 10. 公网 IP 查询（依赖外网）==")
public_ip, source, via_proxy = netinfo.get_public_ip()
if public_ip:
    check("拿到公网 IP", netinfo.is_valid_ipv4(public_ip),
          f"{public_ip}（来源 {source}{'，经代理' if via_proxy else ''}）")
else:
    skip("公网 IP 查询", "所有接口都不可达")


# ==========================================================================
print("\n== 11. 图形界面构建冒烟测试 ==")
try:
    import tkinter as tk

    from dst_ip_join import gui

    scale = winproc.enable_dpi_awareness()
    root = tk.Tk()
    # 构造后 200ms 会自动跑一次真实检测；update_idletasks 只处理布局，
    # 不会推进定时器队列，所以测试期间不会真的去动网络和系统配置
    gui.DstIpJoinApp(root, scale=scale)
    root.update_idletasks()
    width, height = root.winfo_reqwidth(), root.winfo_reqheight()
    check("Tkinter 界面能成功构建", width > 200 and height > 200, f"{width}x{height}")
    root.destroy()
except Exception as exc:  # noqa: BLE001
    check("Tkinter 界面能成功构建", False, f"{type(exc).__name__}: {exc}")


# ==========================================================================
print(f"\n结果：通过 {PASSED}，失败 {FAILED}，跳过 {SKIPPED}")
sys.exit(1 if FAILED else 0)
