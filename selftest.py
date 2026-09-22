# -*- coding: utf-8 -*-
"""自检脚本：验证 ctypes 层的字节序/句柄处理是否正确。

ctypes 调 Win32 最容易在「64 位句柄被截断」和「网络字节序换算」上翻车，
这两类错误不会报异常、只会给出安静的错误结果，所以必须实测。

运行：
    python selftest.py
"""

from __future__ import annotations

import os
import shutil
import socket
import sys
import tempfile

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

# 提权重启：必须能报出失败原因（旧实现只返回 bool，导致无法排查）
check(
    "ShellExecute 错误码有人话说明",
    all(winproc.describe_shell_error(c) for c in (1223, 5, 2, 3, 31, 0)),
    winproc.describe_shell_error(1223),
)
check("1223 归为「用户取消」而非故障",
      winproc.ElevationResult(started=False, code=1223).declined)
check("错误码 2 归为真实失败",
      not winproc.ElevationResult(started=False, code=2).declined)

# 提权命令必须是绝对路径 + 有工作目录：
# sys.argv[0] 可能是相对路径（python main.py），而提权后的进程工作目录未必相同
_elev_exe, _elev_params, _elev_cwd = winproc.build_elevation_command()
check("提权的 exe 是绝对路径且存在",
      os.path.isabs(_elev_exe) and os.path.exists(_elev_exe), _elev_exe)
check("提权指定了存在的工作目录",
      os.path.isabs(_elev_cwd) and os.path.isdir(_elev_cwd), _elev_cwd)
check("提权参数里带脚本/可执行文件", bool(_elev_params), _elev_params[:60])

# 无效窗口句柄必须被识别出来（传垃圾句柄会让 UAC 框弹不出来，比传 NULL 更糟）
check("is_valid_window 拒绝 None / 0 / 越界句柄",
      not winproc.is_valid_window(None)
      and not winproc.is_valid_window(0)
      and not winproc.is_valid_window(999999999))

# 单文件打包（Nuitka onefile）下 sys.executable 指向解包目录里的 python.exe，
# 该文件根本不存在，提权必然报「找不到指定的文件」（错误码 2）。
# 必须能还原成用户实际启动的那个 exe。
_prev_onefile = {k: os.environ.get(k) for k in winproc._ONEFILE_PATH_ENVS}
_probe_dir = tempfile.mkdtemp(prefix="dstip_elev_")
_fake_exe = os.path.join(_probe_dir, "fake_original.exe")
with open(_fake_exe, "wb") as _handle:
    _handle.write(b"MZ")
_real_fake_exe = os.path.abspath(_fake_exe)
try:
    for _key in winproc._ONEFILE_PATH_ENVS:
        os.environ[_key] = _real_fake_exe
    check("能从环境变量还原原始 exe",
          winproc.onefile_original_executable() == _real_fake_exe,
          winproc.onefile_original_executable())

    for _key in winproc._ONEFILE_PATH_ENVS:
        os.environ[_key] = os.path.join(_probe_dir, "not_here.exe")
    check("环境变量指向不存在的文件时不被采信",
          winproc.onefile_original_executable() == "")

    # 冻结分支：提权必须指向还原结果，而不是 sys.executable 那个副本
    os.environ[winproc._ONEFILE_PATH_ENVS[0]] = _real_fake_exe
    _saved_frozen = winproc.is_frozen
    winproc.is_frozen = lambda: True  # type: ignore[assignment]
    try:
        _fz_exe, _fz_params, _fz_cwd = winproc.build_elevation_command()
    finally:
        winproc.is_frozen = _saved_frozen  # type: ignore[assignment]
    check("冻结模式下提权指向还原出的 exe，而非 sys.executable 副本",
          _fz_exe == _real_fake_exe, f"{_fz_exe}（sys.executable={sys.executable}）")
    check("冻结模式下工作目录是 exe 所在目录",
          os.path.isdir(_fz_cwd) and os.path.abspath(_fz_cwd) == _probe_dir, _fz_cwd)

    # 兜底：环境变量都不在时，用 sys.argv[0]（实测单文件模式下它就是真实 exe）
    for _key in winproc._ONEFILE_PATH_ENVS:
        os.environ.pop(_key, None)
    _saved_argv = sys.argv
    sys.argv = [_real_fake_exe]
    try:
        check("无环境变量时用 sys.argv[0] 兜底",
              winproc.onefile_original_executable() == _real_fake_exe,
              winproc.onefile_original_executable())
        sys.argv = [os.path.abspath(__file__)]
        check("sys.argv[0] 不是 exe 时不乱猜",
              winproc.onefile_original_executable() == "")
    finally:
        sys.argv = _saved_argv
finally:
    for _key, _value in _prev_onefile.items():
        if _value is None:
            os.environ.pop(_key, None)
        else:
            os.environ[_key] = _value
    shutil.rmtree(_probe_dir, ignore_errors=True)


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
print("\n== 11b. PyQt6 中继标签页 ==")
try:
    from PyQt6.QtWidgets import QApplication  # noqa: E402
except ImportError:
    skip("PyQt6 中继标签页", "未安装 PyQt6（基础解释器不含 GUI 依赖）")
else:
    try:
        import os as _os

        _os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        from dst_ip_join import gui_qt  # noqa: E402

        _qt_app = QApplication.instance() or QApplication(sys.argv)
        # auto_run=False：离屏测试不碰真实网络诊断（否则会卡十几秒）
        _qt_win = gui_qt.MainWindow(auto_run=False)
        check("PyQt6 中继标签页存在", _qt_win.tabs.count() == 2,
              f"{_qt_win.tabs.count()} 个标签页")
        check(
            "中继向导控件齐全",
            all(
                hasattr(_qt_win, name)
                for name in (
                    "relay_ready_view",
                    "rb_host",
                    "rb_join",
                    "host_panel",
                    "join_panel",
                    "host_code_view",
                    "join_code_input",
                    "host_code_input",
                    "join_cmd_view",
                    "btn_join_apply",
                    "btn_join_start",
                )
            ),
        )
        _qt_win.close()
        check("PyQt6 中继窗口能干净关闭", True)
    except Exception as exc:  # noqa: BLE001
        check("PyQt6 中继标签页", False, f"{type(exc).__name__}: {exc}")


# ==========================================================================
print("\n== 12. UDP 中继（纯转发，不解析协议）==")
import threading  # noqa: E402
import time  # noqa: E402

from dst_ip_join import relay  # noqa: E402

check(
    "解析 IPv4 端点",
    relay.parse_endpoint("1.2.3.4:10999") == ("1.2.3.4", 10999),
)
check(
    "解析带方括号的 IPv6 端点",
    relay.parse_endpoint("[2409:8a60::1]:20000") == ("2409:8a60::1", 20000),
)
try:
    relay.parse_endpoint("::1:10999")
    check("未加方括号的 IPv6 被拒绝", False, "竟然接受了，会有歧义")
except ValueError:
    check("未加方括号的 IPv6 被拒绝", True, "提示要写成 [::1]:10999")

allow = relay.AddressAllowList(["2409:8a60::/32", "192.168.10.0/24"])
check("白名单命中 IPv6 前缀", allow.allows("2409:8a60:cc40:8ea4::1"))
check("白名单命中 IPv4 网段", allow.allows("192.168.10.4"))
check("白名单拒绝未列出的地址", not allow.allows("2001:db8::1"))

v4_addrs, v6_addrs = relay.list_local_addresses()
check("能列出本机 IPv4 地址", bool(v4_addrs), "、".join(v4_addrs) or "（无）")
if v6_addrs:
    check("能列出本机 IPv6 地址", True, f"共 {len(v6_addrs)} 个")
else:
    skip("列出本机 IPv6 地址", "本机没有启用 IPv6")

# 从任意文本提取地址（朋友把地址发给主机时常直接粘一整段话）
extracted = relay.extract_addresses("我的地址是 2409:8a60:cc40::1，谢谢")
check("extract_addresses 提取中文句中的 IPv6",
      extracted == ["2409:8a60:cc40::1"], str(extracted))
extracted = relay.extract_addresses("连 192.168.1.100:10999 或 10.0.0.5")
check("extract_addresses 提取带端口的 IPv4",
      "192.168.1.100" in extracted and "10.0.0.5" in extracted, str(extracted))
extracted = relay.extract_addresses("回环 ::1 与链路本地 fe80::1 不该出现")
check("extract_addresses 忽略回环/链路本地", extracted == [], str(extracted))

# 剪贴板读回（主机端「从剪贴板导入白名单」依赖它）
clip_marker = "SELFTEST-CLIP-2409:8a60::99"
if winproc.set_clipboard_text(clip_marker):
    check("剪贴板读回一致", winproc.get_clipboard_text() == clip_marker,
          repr(winproc.get_clipboard_text()[:40]))
else:
    skip("剪贴板读回", "写入剪贴板失败（可能被占用）")

# 双中继端到端：游戏服务器 <- 主机侧中继 <-(IPv6)-> 朋友侧中继 <- 客户端
game = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
game.bind(("127.0.0.1", 0))
game.settimeout(3.0)
game_port = game.getsockname()[1]
relays: list = []
client = None
try:
    host_rule = relay.ForwardRule("[::1]:0", f"127.0.0.1:{game_port}")
    _, host_relay_port = host_rule.actual_listen_endpoint()
    guest_rule = relay.ForwardRule("127.0.0.1:0", f"[::1]:{host_relay_port}")
    _, guest_relay_port = guest_rule.actual_listen_endpoint()

    relays = [
        relay.UdpRelay([host_rule], idle_timeout=0, log=lambda _: None),
        relay.UdpRelay([guest_rule], idle_timeout=0, log=lambda _: None),
    ]
    for item in relays:
        threading.Thread(
            target=item.run, kwargs={"max_seconds": 6}, daemon=True
        ).start()
    time.sleep(0.5)

    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.bind(("127.0.0.1", 0))
    client.settimeout(3.0)

    payload = b"selftest-upstream" * 20
    client.sendto(payload, ("127.0.0.1", guest_relay_port))
    got, seen_from = game.recvfrom(65535)
    check("中继上行：字节原样送达", got == payload, f"{len(got)} 字节")
    check(
        "中继上行：服务器看到的是独立回环地址",
        seen_from[0].startswith("127.0.0.") and seen_from[0] != "127.0.0.1",
        f"来源 {seen_from[0]}:{seen_from[1]}",
    )

    reply = b"selftest-downstream" * 30
    game.sendto(reply, seen_from)
    back, back_from = client.recvfrom(65535)
    check("中继下行：字节原样回传", back == reply, f"{len(back)} 字节")
    check(
        "中继下行：回包来源正是客户端所连的地址",
        back_from[:2] == ("127.0.0.1", guest_relay_port),
        f"来源 {back_from[0]}:{back_from[1]}",
    )
except socket.timeout as exc:
    check("中继端到端转发", False, f"超时：{exc}")
except OSError as exc:
    check("中继端到端转发", False, f"{type(exc).__name__}: {exc}")
finally:
    for item in relays:
        item.stop()
    game.close()
    if client is not None:
        client.close()


# ==========================================================================
print(f"\n结果：通过 {PASSED}，失败 {FAILED}，跳过 {SKIPPED}")
sys.exit(1 if FAILED else 0)
