# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 SLDYK
#
# 本程序是自由软件：你可以遵照 GNU 通用公共许可证第 3 版
# （GPL-3.0-only）的条款重新发布和/或修改它。
#
# 本程序基于「有用」的期望分发，但不提供任何担保；连适销性或
# 特定用途适用性的默示担保也没有。完整条款见仓库根目录的
# LICENSE 文件，或 <https://www.gnu.org/licenses/>。
"""自检脚本：验证 ctypes 层的字节序/句柄处理是否正确。

ctypes 调 Win32 最容易在「64 位句柄被截断」和「网络字节序换算」上翻车，
这两类错误不会报异常、只会给出安静的错误结果，所以必须实测。

运行：
    python selftest.py
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import sys
import tempfile
from pathlib import Path

if sys.platform != "win32":
    print("这个自检脚本只能在 Windows 上运行")
    sys.exit(1)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dst_ip_join import config, firewall, netinfo, relay, upnp, winproc  # noqa: E402

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
        from dst_ip_join import gui_qt, server  # noqa: E402

        _qt_app = QApplication.instance() or QApplication(sys.argv)
        # auto_run=False：离屏测试不碰真实网络诊断（否则会卡十几秒）
        _qt_win = gui_qt.MainWindow(auto_run=False)
        check("PyQt6 三个标签页（直连/中继/开服）", _qt_win.tabs.count() == 3,
              f"{_qt_win.tabs.count()} 个标签页")
        check(
            "开服标签页控件齐全",
            all(
                hasattr(_qt_win, name)
                for name in (
                    "cluster_combo",
                    "cluster_summary",
                    "mod_list",
                    "server_update_mods",
                    "btn_server_start",
                    "btn_server_attach",
                    "btn_server_stop",
                    "server_status_label",
                    "server_shards_label",
                    "server_log_view",
                    "server_cmd_view",
                    "btn_server_cmd_copy",
                    "btn_server_cmd_probe",
                    "server_cmd_hint",
                    "server_cmd_input",
                    "server_cmd_target",
                    "btn_server_cmd_send",
                    "btn_console_fix",
                )
            ),
        )
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
                    "btn_join_probe",
                )
            ),
        )
        # 关窗服务器确认：离屏下必须走默认（停止），绝不弹模态框
        check("关窗服务器确认在离屏下走默认（停止）",
              _qt_win._ask_stop_server_on_close() == "stop")

        # 开服页的加入指令（明文显示）
        check("split_address 拆分 IPv4:端口",
              gui_qt.split_address("1.2.3.4:10999") == ("1.2.3.4", "10999"))
        check("split_address 不拆 IPv6 字面量",
              gui_qt.split_address("2409:8a60::1") == ("2409:8a60::1", ""))
        check("未选存档时不给加入指令",
              _qt_win.server_cmd_view.text() == ""
              and not _qt_win.btn_server_cmd_copy.isEnabled())
        check("未选存档时提示去选存档",
              "选一个存档" in _qt_win.server_cmd_hint.text())

        # 造一个测试存档：洞穴 10998 + 主世界 10999，指令必须用主世界端口
        _fake_cluster = server.ClusterInfo(
            name="Cluster_Test",
            path=Path("Cluster_Test"),
            ownerdir=Path("0"),
            shards=[
                server.ShardInfo("Caves", False, 10998, Path("Cluster_Test")),
                server.ShardInfo("Master", True, 10999, Path("Cluster_Test")),
            ],
            cluster_name="测试存档",
            has_token=True,
        )
        _qt_win.cluster_combo.addItem("测试存档", _fake_cluster)
        _qt_win.cluster_combo.setCurrentIndex(_qt_win.cluster_combo.count() - 1)
        _cmd = _qt_win.server_cmd_view.text()
        check("开服页明文显示加入指令",
              _cmd.startswith('c_connect("') and _cmd.endswith(")"), _cmd)
        check("加入指令用主世界端口 10999（不是洞穴 10998）",
              _cmd.endswith(", 10999)"), _cmd)
        check("开服页复制按钮已启用", _qt_win.btn_server_cmd_copy.isEnabled())
        check("加入指令提示引导到中继页",
              "UDP 中继" in _qt_win.server_cmd_hint.text())
        check("服务器未运行时提醒朋友连不上",
              "尚未运行" in _qt_win.server_cmd_hint.text())

        # 启动时不碰网络：中继就绪自检要等切到那一页才跑
        check("启动时不自动跑中继就绪自检",
              not _qt_win._relay_checked_once and _qt_win._readiness_thread is None)
        check("中继页初始显示尚未检测",
              "尚未检测" in _qt_win.relay_ready_view.toPlainText())
        _qt_win.tabs.setCurrentIndex(_qt_win._relay_tab_index)
        check("切到中继页才跑就绪自检", _qt_win._relay_checked_once)

        # 服务器控制台：初始未运行 → 输入禁用 + 引导占位；Cluster_2 已开 console_enabled
        check("控制台初始下拉显示未运行",
              _qt_win.server_cmd_target.currentText() == "未运行",
              _qt_win.server_cmd_target.currentText())
        check("控制台初始按钮/输入禁用",
              not _qt_win.btn_server_cmd_send.isEnabled()
              and not _qt_win.server_cmd_input.isEnabled())
        check("控制台初始占位引导启动",
              "启动服务器后" in _qt_win.server_cmd_input.placeholderText(),
              _qt_win.server_cmd_input.placeholderText())
        # 一键常用指令：初始全部禁用，按钮集与定义一致
        check("一键指令按钮与定义一致",
              [b.text() for b in _qt_win.quick_cmd_buttons.values()]
              == [q[1] for q in _qt_win.QUICK_COMMANDS],
              str([b.text() for b in _qt_win.quick_cmd_buttons.values()]))
        check("一键指令按钮初始禁用",
              not any(b.isEnabled() for b in _qt_win.quick_cmd_buttons.values()))
        # 暂停/继续按钮：初始中性「暂停世界」（状态未知），不在回档确认名单里
        check("暂停按钮初始文案为暂停世界",
              _qt_win.quick_cmd_buttons["pause"].text() == "暂停世界",
              _qt_win.quick_cmd_buttons["pause"].text())

        # 回归（2026-09-24）：中继未启动时点「确认生效并启动中继」必须真的启动，
        # 不能被「已运行只热更新」分支静默吞掉（表现为按钮点了毫无反应）。
        # 全程打桩：detect_dst_ports 提供端口、add_udp_rule 免 netsh、换基础端口。
        _orig_detect = relay.detect_dst_ports
        _orig_add_udp = gui_qt.firewall.add_udp_rule
        _orig_base = relay.DEFAULT_RELAY_BASE
        relay.detect_dst_ports = lambda: [10998, 10999]
        gui_qt.firewall.add_udp_rule = lambda port: (True, "测试桩")
        relay.DEFAULT_RELAY_BASE = 23456
        _apply_thread = None
        try:
            _qt_win.apply_host_rules()
            _apply_thread = _qt_win.relay_thread
            check("中继未启动时点「确认生效」会真正启动中继",
                  _apply_thread is not None and _apply_thread.isRunning())
            _qt_win.apply_host_rules()
            check("已启动再点「确认生效」不重启中继（只热更新白名单）",
                  _qt_win.relay_thread is _apply_thread)
        finally:
            relay.detect_dst_ports = _orig_detect
            gui_qt.firewall.add_udp_rule = _orig_add_udp
            relay.DEFAULT_RELAY_BASE = _orig_base
            if _apply_thread is not None:
                _apply_thread.stop()
                _apply_thread.wait(3000)

        _qt_win.close()
        check("PyQt6 中继窗口能干净关闭", True)
    except Exception as exc:  # noqa: BLE001
        check("PyQt6 中继标签页", False, f"{type(exc).__name__}: {exc}")


# ==========================================================================
print("\n== 12. UDP 中继（纯转发，不解析协议）==")
import threading  # noqa: E402
import time  # noqa: E402

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

# 主世界端口选择：绝不能用 min()。
# DST 主世界默认 10999、洞穴 10998，取最小会选到洞穴，而客户端连不进洞穴分片。
check("主世界端口选 10999，而不是最小的 10998",
      config.pick_master_port([10998, 10999]) == 10999,
      f"min() 会得 {min([10998, 10999])}，选到洞穴")
check("只有洞穴时退回最小值", config.pick_master_port([10998]) == 10998)
check("端口改了也能选出结果", config.pick_master_port([20000, 30000]) == 20000)
check("空端口列表不报错", config.pick_master_port([]) == config.DEFAULT_MASTER_PORT)

# 直连指令统一由 config.join_command 生成（直连页 / 中继页 / 开服页共用一份）
check("join_command 生成 c_connect 指令",
      config.join_command("1.2.3.4", 10999) == 'c_connect("1.2.3.4", 10999)',
      config.join_command("1.2.3.4", 10999))
check("join_command 接受字符串端口",
      config.join_command("127.0.0.1", "10999") == 'c_connect("127.0.0.1", 10999)')

# 主机码必须携带主世界端口（加入方无法自行判断）。
# 旧版码没有该字段，只能退回 min() —— 这是兼容分支，不该出现在新码里。
_hc_session = relay.make_session_token()
_hc_new = relay.encode_host_code(
    ["2409:8a60:cc40::1"], 20000, [10998, 10999], 10999, _hc_session
)
_hc_info = relay.decode_host_code(_hc_new)
check("主机码往返带回主世界端口 10999",
      _hc_info["master_port"] == 10999, str(_hc_info["master_port"]))
check("主机码仍带回完整的端口映射",
      sorted(g for _, g in _hc_info["maps"]) == [10998, 10999], str(_hc_info["maps"]))
check("主机码仍带回校验值", _hc_info["session"] == _hc_session)

_hc_old = relay.CODE_HOST_PREFIX + relay._b64url_encode(
    json.dumps({
        "v": relay.CODE_VERSION,
        "addr": ["2409:8a60:cc40::1"],
        "base": 20000,
        "maps": [[20000, 10998], [20001, 10999]],
        "sid": _hc_session,
    }, separators=(",", ":")).encode("utf-8")
)
_hc_old_info = relay.decode_host_code(_hc_old)
check("旧版主机码（无 master 字段）能解析且不报错",
      bool(_hc_old_info["maps"]), str(_hc_old_info.get("master_port")))
check("伪装成主世界端口的垃圾值被忽略",
      relay.decode_host_code(relay.CODE_HOST_PREFIX + relay._b64url_encode(
          json.dumps({
              "v": relay.CODE_VERSION,
              "addr": ["2409:8a60:cc40::1"],
              "base": 20000,
              "maps": [[20000, 10998], [20001, 10999]],
              "master": 999999,
              "sid": _hc_session,
          }, separators=(",", ":")).encode("utf-8")
      ))["master_port"] == 10998)

# 加入方要为每个游戏端口都绑一条回环规则（主世界 + 洞穴都要通）
_guest_rules = relay.build_guest_rules(_hc_info)
check("加入方为每个游戏端口都生成回环规则",
      sorted(r[0] for r in _guest_rules) == ["127.0.0.1:10998", "127.0.0.1:10999"],
      str(_guest_rules))

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
print("\n== 12b. 空白名单启动 + 运行中热更新白名单（closed 守门）==")

# AddressAllowList 三态语义
check("closed=True → 拒绝所有人", not relay.AddressAllowList([], closed=True).allows("::1"))
check("closed 状态下 describe 提示未放行",
      "拒绝" in relay.AddressAllowList([], closed=True).describe())
_open_list = relay.AddressAllowList([])
check("空条目（未 closed）仍是旧行为 = 不限制", _open_list.allows("1.2.3.4"))
check("is_open 只认开放态", _open_list.is_open
      and not relay.AddressAllowList([], closed=True).is_open)
check("is_closed 只认关闭态", relay.AddressAllowList([], closed=True).is_closed
      and not _open_list.is_closed)
_filter_list = relay.AddressAllowList(["2001:db8::/32"])
check("有条目 = 过滤态", not _filter_list.is_open and not _filter_list.is_closed)

# 热更新：closed → 放行 → 关闭，引用同一实例
_hot = relay.AddressAllowList([], closed=True)
check("热更新前：包被拒", not _hot.allows("2409:8a60::1"))
_hot.set_entries(["2409:8a60::/32"])
check("热更新放行：CIDR 命中", _hot.allows("2409:8a60:cc40:8ea4::1"))
_hot.set_entries([], closed=True)
check("热更新收回：再次全拒", not _hot.allows("2409:8a60:cc40:8ea4::1"))

# 端到端：中继先以 closed 启动（空白名单）→ 探测 denied、数据包被拒 →
# 运行中热更新白名单 → 同一个 peer 立即放行（不重启、不换端口）
game2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
game2.bind(("127.0.0.1", 0))
game2.settimeout(3.0)
game2_port = game2.getsockname()[1]
rule_hot = relay.ForwardRule(
    "127.0.0.1:0", f"127.0.0.1:{game2_port}",
    allow=relay.AddressAllowList([], closed=True),
)
_, hot_port = rule_hot.actual_listen_endpoint()
relay_hot = relay.UdpRelay([rule_hot], idle_timeout=0, log=lambda _: None)
_relay_thread_hot = threading.Thread(
    target=relay_hot.run, kwargs={"max_seconds": 8}, daemon=True)
_relay_thread_hot.start()
client2 = None
try:
    time.sleep(0.4)
    # 空白名单时探测应回 denied（包到了，被守门拒）
    _probe_closed = relay.probe_endpoint("127.0.0.1", hot_port, timeout=2.0)
    check("空白名单启动：探测返回 denied（守门而非拒收探测）",
          _probe_closed["status"] == "denied", f"status={_probe_closed['status']}")
    check("空白名单启动：allow 报告已关闭", rule_hot.allow.is_closed)

    # 数据包同样被拒
    client2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client2.bind(("127.0.0.1", 0))
    client2.settimeout(2.0)
    client2.sendto(b"knock", ("127.0.0.1", hot_port))
    got_game = None
    try:
        got_game, _ = game2.recvfrom(4096)
    except socket.timeout:
        pass
    check("空白名单启动：数据包不进游戏", got_game is None)

    # 运行中热更新：放行 client2 的地址，无需重启
    allow_hot = rule_hot.allow
    allow_hot.set_entries([f"{client2.getsockname()[0]}/32"])
    check("热更新后 allow 转为过滤态", not allow_hot.is_closed and not allow_hot.is_open)
    client2.sendto(b"hello", ("127.0.0.1", hot_port))
    got2, from2 = game2.recvfrom(4096)
    check("热更新放行：同一端口立即接受新白名单", got2 == b"hello",
          f"got={got2!r}")
    check("热更新放行：回环地址池照常工作",
          from2[0].startswith("127.0.0.") and from2[0] != "127.0.0.1",
          f"来源 {from2[0]}")
    # 下行也通（peer 建立后双向转发）
    game2.sendto(b"welcome", from2)
    back2, _ = client2.recvfrom(4096)
    check("热更新放行：下行回包正常", back2 == b"welcome")

    # 运行中热更新：重新关闭 → 新包再被拒
    allow_hot.set_closed()
    check("运行中收回白名单：is_closed", allow_hot.is_closed)
    client2.sendto(b"bye", ("127.0.0.1", hot_port))
    got3 = None
    try:
        got3, _ = game2.recvfrom(4096)
    except socket.timeout:
        pass
    check("运行中收回白名单：数据包再次被拒", got3 is None)
except socket.timeout as exc:
    check("空白名单启动 + 热更新端到端", False, f"超时：{exc}")
except OSError as exc:
    check("空白名单启动 + 热更新端到端", False, f"{type(exc).__name__}: {exc}")
finally:
    relay_hot.stop()
    game2.close()
    if client2 is not None:
        client2.close()


# ==========================================================================
print("\n== 13. 专用服务器（存档 / 模组扫描）==")
from dst_ip_join import server  # noqa: E402

_found = server.find_dst_install()
if _found is None:
    skip("定位游戏安装目录", "本机未找到（Steam 库扫描无结果）")
else:
    _game_dir, _ugc_dir = _found
    check("定位游戏安装目录",
          server._nullrenderer(_game_dir) is not None,
          str(_game_dir))
    _content = server.workshop_content_dir(_ugc_dir)
    check("创意工坊内容目录存在", _content.is_dir(), str(_content))

_clusters = server.scan_clusters(
    workshop_content=server.workshop_content_dir(_ugc_dir) if _found else None,
    game_dir=_game_dir if _found else None,
)
check("扫描到至少一个集群", bool(_clusters), f"共 {len(_clusters)} 个")
if _clusters:
    _c = max(_clusters, key=lambda x: len(x.mods))
    check("集群识别出主分片", _c.master() is not None,
          f"{_c.name} 共 {len(_c.shards)} 个分片")
    _ports = _c.ports()
    check("分片端口已解析（10999/10998）", 10999 in _ports, str(_ports))
    check("主分片端口是 10999",
          _c.master() is not None and _c.master().port == 10999)
    check("解析出存档启用的模组", len(_c.mods) > 0,
          f"{len(_c.mods)} 个")
    _missing = _c.missing_mods()
    check("启用的模组均已本地下载", not _missing,
          ", ".join(m.id for m in _missing) or "无缺失")
    if _c.mods:
        _named = [m for m in _c.mods if m.name]
        check("能读到模组中文/英文名", bool(_named),
              _named[0].display_name if _named else "")

# modoverrides 解析的纯逻辑测试（不依赖本机环境）
_sample = '''return {
  ["workshop-1"]={ configuration_options={ A=true, B=false }, enabled=true },
  ["workshop-2"]={ enabled=false },
  ["workshop-3"]={ configuration_options={}, enabled=true },
}'''
_mods = server.parse_modoverrides(_sample)
check("modoverrides 只取 enabled=true", [m.id for m in _mods] == ["1", "3"],
      str([m.id for m in _mods]))
check("modoverrides 配置项计数",
      next(m for m in _mods if m.id == "1").config_count >= 1)


# ==========================================================================
print("\n== 14. 通用化（路径发现 / Token / 设置覆盖）==")
import tempfile  # noqa: E402

# 真实的「文档」目录（OneDrive 重定向也能拿到，不只是 home/Documents）
_docs = server.documents_dir()
check("documents_dir 存在且是目录", _docs.is_dir(), str(_docs))

# nullrenderer 变体定位（64 位 / 32 位 / 无后缀）
_g1 = Path(tempfile.mkdtemp(prefix="dst_g1_"))
(_g1 / "bin64").mkdir()
(_g1 / "bin64" / "dontstarve_dedicated_server_nullrenderer_x64.exe").write_bytes(b"MZ")
check("_nullrenderer 识别 bin64/_x64", server._nullrenderer(_g1) is not None)
_g2 = Path(tempfile.mkdtemp(prefix="dst_g2_"))
(_g2 / "bin").mkdir()
(_g2 / "bin" / "dontstarve_dedicated_server_nullrenderer.exe").write_bytes(b"MZ")
check("_nullrenderer 识别 32 位 bin/ 版本",
      server._nullrenderer(_g2) is not None
      and server._nullrenderer(_g2).parent.name == "bin")
_g3 = Path(tempfile.mkdtemp(prefix="dst_g3_"))
check("空目录返回 None", server._nullrenderer(_g3) is None)

# Token 校验
_ok, _ = server.validate_token("AbCdEfGhIjKlMnOpQrStUvWxYz0123456789")
check("合法令牌被接受", _ok)
_ok2, _msg = server.validate_token("")
check("空令牌被拒绝并给出原因", not _ok2 and bool(_msg))
_ok3, _tok3 = server.validate_token("  这是说明文字  abcdefgh1234567890ABCD  谢谢 ")
check("从一段文字里抠出令牌", _ok3 and _tok3 == "abcdefgh1234567890ABCD")

# write_token：二进制写入、冪等、不同则备份
_tdir = Path(tempfile.mkdtemp(prefix="dst_tok_"))
_fc = server.ClusterInfo(name="T", path=_tdir, ownerdir=_tdir.parent)
_p1 = server.write_token(_fc, "TOKEN_AAAA")
check("write_token 写入字节精确（无多余换行）",
      _p1.read_bytes() == b"TOKEN_AAAA")
server.write_token(_fc, "TOKEN_AAAA")
check("写入相同令牌是冪等的（不生成备份）",
      not (_tdir / "cluster_token.txt.bak").exists())
server.write_token(_fc, "TOKEN_BBBB")
check("换令牌时旧令牌被备份",
      (_tdir / "cluster_token.txt.bak").read_bytes() == b"TOKEN_AAAA")
check("写后集群标记为有令牌", _fc.has_token)

# 多存档根扫描（稳定版 + Beta 分支）
_klei = Path(tempfile.mkdtemp(prefix="dst_klei_")) / "Klei"
for _conf, _cname in (("DoNotStarveTogether", "Cluster_Stable"),
                      ("DoNotStarveTogetherBetaBranch", "Cluster_Beta")):
    _cc = _klei / _conf / "ownerX" / _cname
    (_cc / "Master").mkdir(parents=True)
    (_cc / "cluster.ini").write_text(
        "[NETWORK]\ncluster_name = " + _cname + "\n", encoding="utf-8")
    (_cc / "Master" / "server.ini").write_text(
        "[NETWORK]\nserver_port = 10999\n\n[SHARD]\nis_master = true\n",
        encoding="utf-8")
_found_clusters = server.scan_clusters(klei_root=_klei)
check("同时扫到稳定版与 Beta 分支", len(_found_clusters) == 2,
      str([c.name for c in _found_clusters]))
_beta = next((c for c in _found_clusters if c.name == "Cluster_Beta"), None)
check("Beta 存档标记了正确的 confdir",
      _beta is not None and _beta.confdir == "DoNotStarveTogetherBetaBranch")

# 设置覆盖：手动指定游戏目录
_saved = server.settings()
try:
    if _found:
        server.set_settings(server.Settings(game_dir=str(_game_dir)))
        _gi = server.find_dst_install()
        check("用户指定游戏目录后 find_dst_install 用该目录",
              _gi is not None and _gi[0] == _game_dir)
    server.set_settings(server.Settings(game_dir=str(_g3)))  # 无效路径
    try:
        server.find_dst_install()
        check("指定无效游戏目录时报错而非静默失败", False)
    except server.ServerError:
        check("指定无效游戏目录时报错而非静默失败", True)
finally:
    server.set_settings(_saved)

# Settings 序列化往返
_ss = server.Settings(game_dir="C:\\x", storage_root="D:\\saves", extra_args=["-lan"])
_round = server.Settings(
    game_dir=_ss.game_dir, storage_root=_ss.storage_root, extra_args=list(_ss.extra_args))
check("Settings 字段往返", _round.game_dir == "C:\\x" and _round.extra_args == ["-lan"])


# ==========================================================================
print("\n== 14b. 服务器控制台（stdin 指令 / console_enabled 补写）==")
_tmpdir = tempfile.mkdtemp(prefix="dst_selftest_console_")
_troot = Path(_tmpdir)
_cc = _troot / "DoNotStarveTogether" / "1000" / "Cluster_T"
_cc.mkdir(parents=True)
(_cc / "cluster.ini").write_text(
    "[GAMEPLAY]\ngame_mode = survival\n\n[SHARD]\nshard_enabled = true\n",
    encoding="utf-8")
(_cc / "Master").mkdir()
(_cc / "Master" / "server.ini").write_text(
    "[SERVER]\nport = 10999\nis_master = true\n", encoding="utf-8")
_tc = server.scan_cluster(_cc)
check("控制台：默认 console_enabled=False", server.console_enabled(_tc) is False)
_ok, _msg = server.enable_console(_tc)
_text = (_cc / "cluster.ini").read_text(encoding="utf-8")
check("控制台：enable_console 补写成功", _ok and server.console_enabled(_tc) is True, _msg)
check("控制台：原有段保留",
      "[GAMEPLAY]" in _text and "[SHARD]" in _text and "game_mode = survival" in _text)
check("控制台：备份生成", (_cc / "cluster.ini.bak").is_file())
_mtime = (_cc / "cluster.ini").stat().st_mtime_ns
_ok2, _msg2 = server.enable_console(_tc)
check("控制台：幂等且不动文件",
      _ok2 and "已开启" in _msg2
      and (_cc / "cluster.ini").stat().st_mtime_ns == _mtime)
# [MISC] 段存在但为 false → 改写
(_cc / "cluster.ini").write_text("[MISC]\nconsole_enabled = false\n", encoding="utf-8")
_ok3, _ = server.enable_console(_tc)
_text = (_cc / "cluster.ini").read_text(encoding="utf-8")
check("控制台：false 改写为 true 且不重复",
      _ok3 and _text.count("console_enabled") == 1
      and server.console_enabled(_tc) is True, repr(_text))


# —— stdin 指令管道（用桩对象，不起真实 DST） ——
class _FakeStdin:
    def __init__(self):
        self.written = []

    def write(self, s):
        self.written.append(s)
        return len(s)

    def flush(self):
        pass


class _FakeProc:
    def __init__(self):
        self.stdin = _FakeStdin()
        self.returncode = None

    def poll(self):
        return self.returncode

    def terminate(self):
        pass

    def kill(self):
        pass

    def wait(self, timeout=10):
        return 0


class _StubShard:
    def __init__(self, name, is_master, port=10999):
        self.name, self.is_master, self.port = name, is_master, port


class _StubShardProc:
    """只保留 ShardProcess 与 stdin 相关的接口。"""

    def __init__(self, name, is_master, port=10999):
        self.shard = _StubShard(name, is_master, port)
        self.proc = _FakeProc()
        self._stdin_lock = threading.Lock()

    @property
    def alive(self):
        return self.proc is not None and self.proc.poll() is None

    send_command = server.ShardProcess.send_command
    stop = server.ShardProcess.stop


_pm, _pc = _StubShardProc("Master", True), _StubShardProc("Caves", False, 10998)
_ok, _msg = _pm.send_command("c_listallplayers()")
check("控制台：指令写入 stdin（带换行）",
      _ok and _pm.proc.stdin.written == ["c_listallplayers()\n"], repr(_pm.proc.stdin.written))
_ok, _msg = _pm.send_command("   ")
check("控制台：空白指令拒绝", _ok is False, _msg)
_pm.proc.returncode = 0
_ok, _msg = _pm.send_command("c_save()")
check("控制台：进程退出后拒绝", _ok is False and "未在运行" in _msg, _msg)

# ServerManager.send_command：默认主世界 / 指定分片 / 未知分片
_mgr = server.ServerManager.__new__(server.ServerManager)
_mgr.cluster, _mgr.offline, _mgr.procs = None, False, [_pm, _pc]
_pm.proc.returncode = None
_ok, _msg = _mgr.send_command("c_save()")
check("控制台：Manager 默认发主世界",
      _ok and _pm.proc.stdin.written[-1] == "c_save()\n", _msg)
_ok, _msg = _mgr.send_command("c_rollback(1)", shard="Caves")
check("控制台：Manager 指定发洞穴",
      _ok and _pc.proc.stdin.written[-1] == "c_rollback(1)\n", _msg)
_ok, _msg = _mgr.send_command("x", shard="Nope")
check("控制台：未知分片报错", _ok is False and "Nope" in _msg, _msg)

# 接管句柄：一律拒绝并说明
_ok, _msg = server.AttachedServer(None, []).send_command("c_save()")
check("控制台：接管进程拒绝指令", _ok is False and "stdin" in _msg, _msg)

# —— 暂停/继续（TheSim:SetTimeScale + 打点回显解析） ——
# 打点模板必须是合法 Lua 单条语句（老坑：多语句挤一行会语法错误不执行）
check("暂停：打点模板是单条 print",
      server.SIM_TIMESCALE_PROBE_TEMPLATE.startswith('print("')
      and server.SIM_TIMESCALE_PROBE_TEMPLATE.endswith(")")
      and "\n" not in server.SIM_TIMESCALE_PROBE_TEMPLATE,
      server.SIM_TIMESCALE_PROBE_TEMPLATE)
check("暂停：暂停/继续命令是 TheSim:SetTimeScale（TheNet:SetServerPaused 在专用"
      "服务器上不停模拟）",
      server.PAUSE_ON_CMD == "TheSim:SetTimeScale(0)"
      and server.PAUSE_OFF_CMD == "TheSim:SetTimeScale(1)"
      and "TheSim:GetTimeScale()" in server.PAUSE_TOGGLE_CMD
      and "\n" not in server.PAUSE_TOGGLE_CMD,
      f"{server.PAUSE_ON_CMD!r} {server.PAUSE_OFF_CMD!r} {server.PAUSE_TOGGLE_CMD!r}")
# 回显样例（日志泵会加 [Master] 前缀）：打点 + 引擎原生 Sim paused/unpaused
_probe = ("[Master] [00:07:12]: DSTIPJ_SIM_TS=1\n"
          "[Master] [00:08:01]: DSTIPJ_SIM_TS=0\n"
          "[Master] [00:09:00]: Sim paused\n"
          "[Master] [00:09:10]: Sim unpaused\n")
check("暂停：解析打点/引擎行，取最后一条（unpaused=False）",
      server.parse_pause_state(_probe) is False)
check("暂停：打点 0=已暂停",
      server.parse_pause_state("[Master] [00:03:03]: DSTIPJ_SIM_TS=0") is True)
check("暂停：引擎行 Sim paused=True（pause_when_empty 自动暂停同源）",
      server.parse_pause_state("[00:00:50]: Sim paused") is True)
check("暂停：无线索返回 None",
      server.parse_pause_state("[OK] 启动") is None
      and server.parse_pause_state("") is None)
check("暂停：无效打点数值忽略", server.parse_pause_state(
    "DSTIPJ_SIM_TS=abc") is None)
# 引擎时间戳（回显基线，替代会因块数上限缩水的文本长度基线）
check("时间戳：解析引擎行 [HH:MM:SS]",
      server.engine_timestamp("[Master] [00:03:45]: [1] (KU_x) 名 <wilson>") == 225
      and server.engine_timestamp("[00:01:00]: Sim paused") == 60)
check("时间戳：无时间戳行返回 None",
      server.engine_timestamp("[OK] 已停止") is None
      and server.engine_timestamp("普通文本") is None)

# —— GUI 回归（2026-09-23 用户实测两 bug） ——
# ① 点「暂停世界」必须发目标动作 SetTimeScale(0)：首版按当前状态发，
#    未暂停时点了发 (1) = 保持现状，怎么点都没效果。
# ② 刷新列表基线必须是引擎时间戳：首版只改了消费端，记录端还在记字符数
#    （几万）＞时间戳（几百秒），回显全被当历史行丢弃。
_qtw = globals().get("_qt_win")
if _qtw is not None:  # PyQt6 缺失时 11b 节没建窗口，跳过
    _gp = _StubShardProc("Master", True)
    _gp.is_ready = lambda: True  # status() 会读；真类有，桩补一个
    _gp.exit_code = None         # status() 也会读
    _gm = server.ServerManager.__new__(server.ServerManager)
    _gm.cluster, _gm.offline, _gm.procs = None, False, [_gp]
    _qtw._server_manager = _gm
    _qtw._refresh_console_row()
    _qtw._server_paused = False  # 服务器运行中（时间刻度 1）
    _qtw.run_quick_command("pause")
    check("暂停：未暂停时点按发 SetTimeScale(0)（目标动作）",
          _gp.proc.stdin.written[-1].startswith("TheSim:SetTimeScale(0)"),
          repr(_gp.proc.stdin.written[-1]))
    check("暂停：点按附带时间刻度打点（自证生效）",
          "DSTIPJ_SIM_TS=" in _gp.proc.stdin.written[-1])
    _qtw._server_paused = True
    _qtw.run_quick_command("pause")
    check("暂停：已暂停时点按发 SetTimeScale(1)（恢复）",
          _gp.proc.stdin.written[-1].startswith("TheSim:SetTimeScale(1)"),
          repr(_gp.proc.stdin.written[-1]))
    _qtw._server_manager = None
    _qtw._refresh_console_row()
    _qtw.server_log_view.clear()
    _qtw.refresh_players()
    check("玩家：刷新基线是引擎时间戳或 None（绝不能是字符数）",
          _qtw._player_capture_after is None
          or _qtw._player_capture_after < 86400,
          str(_qtw._player_capture_after))


# ==========================================================================
print("\n== 14c. 玩家管理（在线列表解析 / 踢 / 拉黑）==")
_lines = (
    "[1] (KU_abCd1234) 张三 <wilson>\n"
    "[2] (KU_xyZw5678) 带空格 名字 <wolfgang>\n"
    "[Master] [3] (KU_缩进的) 缩进 <wx78>\n"
    # 2026-09-23 用户真实服务器的行：时间戳前缀 + OU_ 前缀 ID + 行尾制表符
    "[Master] [00:07:09]: [1] (OU_76561199032098747) SLDYK <wortox>\t\n"
    "不是玩家行\n"
)
_players = server.parse_player_lines(_lines)
check("玩家：解析出 4 个（容忍分片/时间戳前缀）", len(_players) == 4, str(len(_players)))
check("玩家：字段正确",
      _players[0]["userid"] == "KU_abCd1234" and _players[0]["prefab"] == "wilson"
      and _players[1]["name"] == "带空格 名字", str(_players[:2]))
_real = next(p for p in _players if p["userid"].startswith("OU_"))
check("玩家：OU_ 前缀与时间戳前缀可解析",
      _real == {"index": 1, "userid": "OU_76561199032098747",
                "name": "SLDYK", "prefab": "wortox"}, str(_real))
check("玩家：空文本/无玩家行返回空",
      server.parse_player_lines("") == []
      and server.parse_player_lines("[OK] 启动") == [])

_broot = Path(tempfile.mkdtemp(prefix="dst_selftest_ban_"))
_bc = server.ClusterInfo(name="Cluster_B", path=_broot, ownerdir=Path("1000"))
_ok, _msg = server.add_blocklist_userid(_bc, "KU_abCd1234")
check("拉黑：首次写入成功", _ok and "KU_abCd1234" in _msg, _msg)
_ok2, _msg2 = server.add_blocklist_userid(_bc, "KU_abCd1234")
check("拉黑：重复写入幂等", _ok2 and "已在黑名单" in _msg2, _msg2)
check("拉黑：文件仍一行", (_broot / "blocklist.txt").read_text().count("KU_") == 1)
_ok3, _msg3 = server.add_blocklist_userid(_bc, "KU_中文用户")
check("拉黑：中文 Klei ID 可写", _ok3 and "KU_中文用户" in
      (_broot / "blocklist.txt").read_text(encoding="utf-8"))
_ok4, _msg4 = server.add_blocklist_userid(_bc, "not-an-id")
check("拉黑：非法 ID 拒绝", _ok4 is False and "不像合法" in _msg4, _msg4)
shutil.rmtree(_broot, ignore_errors=True)


# ==========================================================================
print("\n== 15. 接管：进程发现与监控 ==")

# 命令行参数解析
_cl = ('-cluster Cluster_2 -shard Master -persistent_storage_root APP:Klei/ '
       '-conf_dir DoNotStarveTogether -ownerdir 1071833019 '
       '-sigprefix DST_Master -skip_update_server_mods')
check("_arg 解析 cluster", server._arg(_cl, "cluster") == "Cluster_2")
check("_arg 解析 ownerdir", server._arg(_cl, "ownerdir") == "1071833019")
check("_arg 缺失参数返回 None", server._arg(_cl, "token") is None)

# APP:Klei/ 别名解析
_root = server._resolve_storage_root("APP:Klei/")
check("APP:Klei/ 解析到 <文档>\\Klei",
      _root == server.documents_dir() / "Klei", str(_root))
check("绝对路径原样返回",
      server._resolve_storage_root("D:\\saves") == Path("D:\\saves"))

# 构造两个假分片进程（同一集群）+ 一个别的集群，验证分组取进程数最多的。
# 集群名动态取**真实存在**的第一个（曾经硬编码 Cluster_2，磁盘上没有该存档后
# 「匹配真实存档」一项就永久失败 —— 测试数据要跟着机器现状走）。
_all_clusters = server.scan_clusters(
    workshop_content=server.workshop_content_dir(_ugc_dir) if _found else None,
    game_dir=_game_dir if _found else None)
_cluster_name = _all_clusters[0].name if _all_clusters else "Cluster_X"
_p1 = server.ShardProcInfo(pid=999001, name="dontstarve_dedicated_server_nullrenderer_x64.exe",
                           cmdline=_cl.replace("Cluster_2", _cluster_name),
                           cluster_name=_cluster_name, shard_name="Master",
                           ownerdir="1071833019", is_master=True)
_cl2 = _cl.replace("Master", "Caves").replace("DST_Master", "DST_Secondary")
_p2 = server.ShardProcInfo(pid=999002, name="dontstarve_dedicated_server_nullrenderer_x64.exe",
                           cmdline=_cl2.replace("Cluster_2", _cluster_name),
                           cluster_name=_cluster_name, shard_name="Caves",
                           ownerdir="1071833019", is_master=False)
_p3 = server.ShardProcInfo(pid=999003, name="dontstarve_dedicated_server_nullrenderer_x64.exe",
                           cmdline=_cl.replace("Cluster_2", "Other"),
                           cluster_name="Other", shard_name="Master", ownerdir="1071833019")

# 真实存档用于匹配（复用上面已扫的列表）
_real = _all_clusters
_att = server.attach_running_procs(_real, procs=[_p1, _p2, _p3])
check("接管返回非空", _att is not None)
check("按进程数最多分组（选中同一集群的 2 个分片）",
      _att is not None and len(_att.shards) == 2)
if _att is not None:
    check("接管对象匹配到真实存档", _att.cluster is not None
          and _att.cluster.name == _cluster_name)
    check("识别主分片", any(s.is_master for s in _att.shards))
    check("标记为接管（attached）", _att.attached is True)
    _st = _att.status()
    check("status 形状与 ServerManager 对齐",
          all({"shard", "is_master", "port", "running"} <= set(s) for s in _st))
    check("status 带 pid 与 attached 标记",
          all(s.get("attached") and s.get("pid") for s in _st))

# RunningShard 日志增量（用真实存档的 server_log.txt）
if _att is not None and _att.cluster is not None:
    _ms = next((s for s in _att.shards if s.is_master), None)
    if _ms is not None and _ms._log_path is not None:
        _first = _ms.pump()
        _second = _ms.pump()
        check("pump 第二次不重复读（增量为空）", _second == "")
        check("tail 能返回最近日志", bool(_ms.tail(3)))
    else:
        skip("RunningShard 日志增量", "未定位到日志文件")

# 无匹配存档时也能接管（只能监控/停止）
_att2 = server.attach_running_procs([], procs=[_p3])
check("无匹配存档时 cluster 为 None 但仍可接管",
      _att2 is not None and _att2.cluster is None and len(_att2.shards) == 1)


# ==========================================================================
print("\n== 16. 连通性探测（区分「包没到」/「被白名单拒」）==")

# 主机端中继：监听 127.0.0.1:PORT，允许 127.0.0.1
_probe_host_rule = relay.ForwardRule(
    "127.0.0.1:0", "127.0.0.1:9",  # target 随便；探测包不会转发过去
    allow=relay.AddressAllowList(["127.0.0.1/32"]),
)
_, _probe_port = _probe_host_rule.actual_listen_endpoint()
_probe_relay = relay.UdpRelay([_probe_host_rule], idle_timeout=0, log=lambda _: None)
threading.Thread(target=_probe_relay.run, kwargs={"max_seconds": 8}, daemon=True).start()
time.sleep(0.4)

_r_ok = relay.probe_endpoint("127.0.0.1", _probe_port, timeout=2.0)
check("白名单内探测返回 ok（路通）", _r_ok["status"] == "ok",
      f"status={_r_ok['status']} rtt={_r_ok.get('rtt_ms')}")
_probe_relay.stop()

# 主机端中继：白名单里没有 127.0.0.1 → 应回 denied
_deny_rule = relay.ForwardRule(
    "127.0.0.1:0", "127.0.0.1:9",
    allow=relay.AddressAllowList(["10.99.99.99/32"]),
)
_, _deny_port = _deny_rule.actual_listen_endpoint()
_deny_relay = relay.UdpRelay([_deny_rule], idle_timeout=0, log=lambda _: None)
threading.Thread(target=_deny_relay.run, kwargs={"max_seconds": 8}, daemon=True).start()
time.sleep(0.4)
_r_deny = relay.probe_endpoint("127.0.0.1", _deny_port, timeout=2.0)
check("白名单外探测返回 denied（包到了但被拒）", _r_deny["status"] == "denied",
      f"status={_r_deny['status']}")
_deny_relay.stop()

# 无人监听 → timeout（包到不了）
_r_to = relay.probe_endpoint("127.0.0.1", 59999, timeout=0.6)
check("没人听时返回 refused/timeout（路径通但端口没开）",
      _r_to["status"] in ("refused", "timeout"),
      f"status={_r_to['status']}")

# 主机码 → 只探主世界那条映射
_probe_info = {
    "addresses": ["127.0.0.1"],
    "maps": [[20000, 10998], [20001, 10999]],
    "master_port": 10999,
}
_probe_relay2_rule = relay.ForwardRule(
    "127.0.0.1:20001", "127.0.0.1:9",
    allow=relay.AddressAllowList(["127.0.0.1/32"]),
)
_probe_relay2 = relay.UdpRelay([_probe_relay2_rule], idle_timeout=0, log=lambda _: None)
threading.Thread(target=_probe_relay2.run, kwargs={"max_seconds": 8}, daemon=True).start()
time.sleep(0.4)
_results = relay.probe_host_info(_probe_info, timeout=1.5)
check("probe_host_info 只探主世界那条（20001）",
      len(_results) == 1 and _results[0]["address"].endswith(":20001"),
      str([r["address"] for r in _results]))
check("探测结果有对应的人话说明", bool(relay.describe_probe(_results)))
_probe_relay2.stop()


# ==========================================================================
print("\n== 17. 主机端自检（端口 / 防火墙 / 自环）==")

# 端口推算：游戏没开时按典型规模估算
check("_relay_ports_for_check 空输入按 4 个估算",
      relay._relay_ports_for_check([]) == [20000, 20001, 20002, 20003],
      str(relay._relay_ports_for_check([])))
check("_relay_ports_for_check 按游戏端口数对齐",
      relay._relay_ports_for_check([10999, 10998]) == [20000, 20001],
      str(relay._relay_ports_for_check([10999, 10998])))

# 端口可绑定测试：空闲 → 可用；被占用 → 不可用
_bind_port = 58901
_ok_free, _why_free = relay.can_bind_port(_bind_port)
check("空闲端口可绑定", _ok_free, _why_free)
_holder = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
try:
    _holder.bind(("::", _bind_port))
    _ok_busy, _why_busy = relay.can_bind_port(_bind_port)
    check("被占用端口报告不可用", not _ok_busy, _why_busy)
    check("被占用时的说明提到占用", "占用" in _why_busy, _why_busy)
finally:
    _holder.close()

# 自环探测：本机没有中继在监听该端口 → refused（路径通、端口没人听）
_loop = relay.self_loop_probe(58902, timeout=0.6)
check("自环探测在无人监听时返回 refused/timeout/error",
      _loop["status"] in ("refused", "timeout", "error"),
      f"status={_loop['status']}")

# 完整自检：必须涵盖「防火墙」「白名单」「自环」这三类关键项
_res = relay.check_host_readiness([10999, 10998], session="SESS", join_entries=[])
_text = "\n".join(m for _, _, m in _res)
check("主机端自检覆盖防火墙项", "防火墙" in _text)
check("主机端自检覆盖白名单项", "加入码" in _text or "白名单" in _text)
check("主机端自检覆盖自环项", "自环测试" in _text)
check("主机端自检覆盖中继端口项", "中继端口" in _text)
check("无加入码时提示会被拒绝",
      any(level == "warn" and "加入码" in m for _, level, m in _res))

# 有「启用且 sid 匹配」的加入码时，白名单项应通过
_active_entries = [{
    "enabled": True,
    "session": "SESS",
    "addresses": ["2409:8a60:cc40::99"],
    "note": "测试",
}]
_res2 = relay.check_host_readiness([10999], session="SESS",
                                   join_entries=_active_entries, loopback=False)
check("有生效加入码时白名单项通过",
      any(level == "ok" and "白名单生效" in m for _, level, m in _res2),
      "\n".join(m for _, _, m in _res2 if "白名单" in m or "加入码" in m))

# 校验值不匹配时应判为不可用（防止把上一轮的旧码当成有效）
_stale_entries = [dict(_active_entries[0], session="OLD-SESSION")]
_res3 = relay.check_host_readiness([10999], session="SESS",
                                   join_entries=_stale_entries, loopback=False)
check("校验值不匹配的加入码不算生效",
      any(level == "warn" and "校验值匹配" in m for _, level, m in _res3))


# ==========================================================================
print("\n== 18. CLI 开服路径（用桩代替真实进程）==")

# 回归：曾因 `def log` 定义写在 --start-server 块之后，闭包引用未绑定的自由变量，
# 导致 `cli.py --start-server` 直接 NameError 崩溃。这里用桩跑一遍该代码路径。
import cli as _cli  # noqa: E402


class _StubManager:
    """假的 ServerManager：立刻回调、立刻结束监控循环，不起真实进程。"""

    def __init__(self, *args, **kwargs) -> None:
        self.started = False

    def start_all(self, *, wait_ready=True, timeout=150.0, callback=None):
        if callback:
            callback("info", "桩：正在启动主分片")   # 走 cli 的 note -> log
            callback("ready", "桩：就绪")
        self.started = True

    def pump_logs(self) -> str:
        return "[Master] 桩日志"

    def any_running(self) -> bool:
        return False          # 让监控循环立即结束

    def stop_all(self) -> None:
        pass


if _found and _real:
    _rc_cluster = next((c for c in _real if c.name == "Cluster_2"), _real[0])
    _orig_manager = server.ServerManager
    server.ServerManager = _StubManager  # type: ignore[assignment]
    try:
        _rc = _cli.main(["--start-server", _rc_cluster.name])
        check("CLI --start-server 能跑完（捕获闭包未绑定等错误）", _rc == 0,
              f"返回 {_rc}")
    except Exception as exc:  # noqa: BLE001
        check("CLI --start-server 能跑完（捕获闭包未绑定等错误）", False,
              f"{type(exc).__name__}: {exc}")
    finally:
        server.ServerManager = _orig_manager  # type: ignore[assignment]
else:
    skip("CLI --start-server 路径", "本机未扫到存档")


# ==========================================================================
print(f"\n结果：通过 {PASSED}，失败 {FAILED}，跳过 {SKIPPED}")
sys.exit(1 if FAILED else 0)
