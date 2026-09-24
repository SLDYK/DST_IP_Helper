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
"""PyQt6 图形界面。

布局：左侧检测项清单 + 右侧（直连地址卡片 / 操作 / 日志）。
耗时操作（网络探测、UPnP、netsh）放在 QThread 后台线程，
通过信号回主线程刷新界面。
"""

from __future__ import annotations

import re
import traceback
from typing import ClassVar

from PyQt6.QtCore import Qt, QThread, QTimer, pyqtSignal
from PyQt6.QtGui import QFont, QGuiApplication
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QRadioButton,
    QScrollArea,
    QSizePolicy,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
    QPlainTextEdit,
)

from . import config, diagnostics, firewall, netinfo, relay, server, winproc

# ---------------------------------------------------------------------------
# 主题
# ---------------------------------------------------------------------------
STYLE = """
* {
    font-family: "Microsoft YaHei UI", "Segoe UI", sans-serif;
    font-size: 13px;
    color: #1f2328;
}
QMainWindow, QWidget#root { background: #f4f5f7; }

/* ---------- 标题区 ---------- */
QLabel#appTitle { font-size: 19px; font-weight: 700; color: #1f2328; }
QLabel#adminBadge { padding: 3px 10px; border-radius: 9px; font-size: 12px; }
QLabel#adminBadge[admin="1"] { background: #dafbe1; color: #1a7f37; }
QLabel#adminBadge[admin="0"] { background: #fff8c5; color: #9a6700; }

/* ---------- 卡片 ---------- */
QFrame#card {
    background: #ffffff;
    border: 1px solid #e1e4e8;
    border-radius: 10px;
}
QLabel#cardTitle { color: #6b7280; font-size: 12px; font-weight: 600; }

/* ---------- 检测项 ---------- */
QLabel#checkIcon { font-size: 14px; font-weight: 700; }
QLabel#checkTitle { font-weight: 600; color: #24292f; }
QLabel#checkDetail { color: #6b7280; }

/* ---------- 地址展示 ---------- */
QLineEdit#addressView {
    background: #f6f8fa;
    border: 1px solid #d8dee4;
    border-radius: 8px;
    padding: 14px;
    font-family: Consolas, "Cascadia Mono", monospace;
    font-size: 22px;
    font-weight: 700;
    color: #0969da;
    selection-background-color: #b6dcff;
}
QLineEdit#commandView {
    background: #f6f8fa;
    border: 1px solid #d8dee4;
    border-radius: 6px;
    padding: 7px 10px;
    font-family: Consolas, "Cascadia Mono", monospace;
    font-size: 14px;
    color: #1a7f37;
    selection-background-color: #b6dcff;
}

/* ---------- 按钮 ---------- */
QPushButton {
    background: #f6f8fa;
    border: 1px solid #d0d7de;
    border-radius: 7px;
    padding: 8px 16px;
}
QPushButton:hover { background: #eef1f4; border-color: #b9c0c8; }
QPushButton:pressed { background: #e4e8ec; }
QPushButton:disabled { background: #f2f3f5; color: #a8b0b8; border-color: #e1e4e8; }
QPushButton#primary {
    background: #1f6feb;
    border-color: #1f6feb;
    color: #ffffff;
    font-weight: 600;
}
QPushButton#primary:hover { background: #3b82f6; border-color: #3b82f6; }
QPushButton#primary:pressed { background: #1a5fd0; }
QPushButton#primary:disabled { background: #a8c7fa; color: #ffffff; border-color: #a8c7fa; }
QPushButton#danger:hover { border-color: #cf222e; color: #cf222e; }

/* ---------- 输入 ---------- */
QLineEdit#portInput {
    background: #ffffff;
    border: 1px solid #d0d7de;
    border-radius: 6px;
    padding: 6px 10px;
}
QLineEdit#portInput:focus { border-color: #0969da; }
QCheckBox { spacing: 6px; }
QCheckBox::indicator {
    width: 15px; height: 15px; border-radius: 4px;
    border: 1px solid #b9c0c8; background: #ffffff;
}
QCheckBox::indicator:checked { background: #0969da; border-color: #0969da; }

/* ---------- 日志 ---------- */
QPlainTextEdit#logView {
    background: #ffffff;
    border: 1px solid #e1e4e8;
    border-radius: 8px;
    font-family: Consolas, "Cascadia Mono", monospace;
    font-size: 12px;
    color: #24292f;
    padding: 6px;
    selection-background-color: #b6dcff;
}

/* ---------- 进度条与状态栏 ---------- */
QProgressBar {
    background: #eaeef2;
    border: 1px solid #d0d7de;
    border-radius: 5px;
    height: 10px;
    text-align: center;
}
QProgressBar::chunk { background: #0969da; border-radius: 4px; }
QLabel#statusLabel { color: #57606a; }

/* ---------- 标签页 ---------- */
QTabWidget::pane {
    border: 1px solid #e1e4e8;
    border-radius: 8px;
    background: transparent;
    top: -1px;
}
QTabBar::tab {
    background: #eaeef2;
    border: 1px solid #e1e4e8;
    border-bottom: none;
    border-top-left-radius: 7px;
    border-top-right-radius: 7px;
    padding: 7px 20px;
    margin-right: 3px;
    color: #57606a;
}
QTabBar::tab:selected {
    background: #ffffff;
    border-color: #e1e4e8;
    color: #1f2328;
    font-weight: 600;
}
QTabBar::tab:hover:!selected { background: #dfe4ea; }

/* ---------- 滚动条 ---------- */
QScrollArea { border: none; background: transparent; }
QScrollBar:vertical {
    background: transparent; width: 10px; margin: 2px;
}
QScrollBar::handle:vertical {
    background: #c9d1d9; border-radius: 5px; min-height: 24px;
}
QScrollBar::handle:vertical:hover { background: #aeb7c0; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical { background: none; }

QToolTip { background: #ffffff; color: #24292f; border: 1px solid #c9d1d9; padding: 4px 8px; }
"""

LEVEL_STYLE = {
    diagnostics.LEVEL_OK: ("✓", "#1a7f37"),
    diagnostics.LEVEL_WARN: ("!", "#9a6700"),
    diagnostics.LEVEL_FAIL: ("×", "#cf222e"),
    diagnostics.LEVEL_INFO: ("i", "#57606a"),
}
LOG_COLORS = {"OK": "#1a7f37", "WARN": "#9a6700", "FAIL": "#cf222e", "INFO": "#57606a"}
LEVEL_LINE_RE = re.compile(r"^\[(OK|WARN|FAIL|INFO)\s*\]")

# 玩家行解析在 server.parse_player_lines（纯标准库，GUI/selftest/CLI 共用），这里只是引用
from .server import parse_player_lines  # noqa: E402


def _is_offscreen() -> bool:
    """是否离屏渲染。离屏（自动化测试）下模态 QMessageBox 会永久阻塞事件循环。"""
    try:
        return QGuiApplication.platformName().lower() == "offscreen"
    except Exception:  # noqa: BLE001
        return False


def split_address(address: str) -> tuple[str, str]:
    """把 ``ip:port`` 拆成 ``(ip, port)``；未带端口时端口返回空串。"""
    if not address:
        return "", ""
    if address.count(":") > 1:
        return address, ""   # IPv6 字面量，不能按最后一个冒号拆
    ip, sep, port = address.rpartition(":")
    if not sep or not port.isdigit():
        return address, ""
    return ip, port


# ---------------------------------------------------------------------------
# 后台工作线程
# ---------------------------------------------------------------------------
class Worker(QThread):
    log = pyqtSignal(str)
    check = pyqtSignal(object)  # diagnostics.CheckItem
    progress = pyqtSignal(str)
    done = pyqtSignal(object)  # diagnostics.Report
    cleanup_done = pyqtSignal(list)
    error = pyqtSignal(str)

    def __init__(self, mode: str, ports: list[int] | None = None) -> None:
        super().__init__()
        self._mode = mode  # "run" | "cleanup"
        self._ports = ports

    def run(self) -> None:  # noqa: D102
        try:
            if self._mode == "run":
                report = diagnostics.run_diagnosis(
                    ports=self._ports,
                    log=self.log.emit,
                    status=self._emit_check,
                    configure=True,
                )
                self.done.emit(report)
            else:
                messages = diagnostics.cleanup(
                    ports=self._ports,
                    log=self.log.emit,
                    status=self._emit_check,
                )
                self.cleanup_done.emit(messages)
        except Exception:  # noqa: BLE001
            self.error.emit(traceback.format_exc())

    def _emit_check(self, item: diagnostics.CheckItem) -> None:
        self.check.emit(item)


class RelayThread(QThread):
    """在后台跑 relay.UdpRelay，事件与日志通过信号回主线程。"""

    log = pyqtSignal(str)
    event = pyqtSignal(str, object)  # (kind, payload)
    failed = pyqtSignal(str)

    def __init__(self, rules: list[relay.ForwardRule], *, verbose: bool = False) -> None:
        super().__init__()
        self._rules = rules
        self._verbose = verbose
        self.relay: relay.UdpRelay | None = None

    def run(self) -> None:  # noqa: D102
        # relay 的 callback 只在中继线程里被调用，发信号是跨线程安全的
        # （Qt 会把信号排队交给主线程的槽），正好满足 relay 对回调的要求
        self.relay = relay.UdpRelay(
            self._rules,
            verbose=self._verbose,
            log=self.log.emit,
            callback=lambda kind, payload: self.event.emit(kind, payload),
        )
        try:
            self.relay.run()
        except Exception:  # noqa: BLE001
            self.failed.emit(traceback.format_exc())

    def stop(self) -> None:
        if self.relay is not None:
            self.relay.stop()

    def snapshot(self) -> dict:
        if self.relay is None:
            return {}
        return self.relay.snapshot()


class ReadinessThread(QThread):
    """在后台跑中继就绪自检（含 netsh 与自环探测，都是阻塞 IO）。"""

    done = pyqtSignal(object)   # list[(ok, level, message)]

    def __init__(self, role: str, *, session: str = "",
                 entries: list[dict] | None = None) -> None:
        super().__init__()
        self._role = role
        self._session = session
        self._entries = entries or []

    def run(self) -> None:  # noqa: D102
        try:
            if self._role == "host":
                results = relay.check_host_readiness(
                    relay.detect_dst_ports(),
                    session=self._session,
                    join_entries=self._entries,
                )
            else:
                results = relay.check_relay_readiness("join")
            self.done.emit(results)
        except Exception:  # noqa: BLE001
            self.done.emit([(False, "fail", f"自检出错：{traceback.format_exc(limit=1)}")])


class ServerThread(QThread):
    """后台扫描存档 / 拉起专用服务器，避免阻塞界面。"""

    scanned = pyqtSignal(object)      # list[server.ClusterInfo]
    scan_failed = pyqtSignal(str)
    started = pyqtSignal(object)      # server.ServerManager
    failed = pyqtSignal(str)

    def __init__(self, mode: str, cluster: server.ClusterInfo | None = None,
                 *, update_mods: bool = False,
                 extra_args: list[str] | None = None) -> None:
        super().__init__()
        self._mode = mode  # "scan" | "start"
        self._cluster = cluster
        self._update_mods = update_mods
        self._extra_args = list(extra_args or [])
        self.manager: server.ServerManager | None = None

    def run(self) -> None:  # noqa: D102
        try:
            if self._mode == "scan":
                found = server.default_install()
                game_dir, ugc_dir = found
                content = server.workshop_content_dir(ugc_dir)
                clusters = server.scan_clusters(
                    workshop_content=content, game_dir=game_dir)
                self.scanned.emit(clusters)
            else:
                assert self._cluster is not None
                self.manager = server.ServerManager(
                    self._cluster, update_mods=self._update_mods,
                    extra_args=self._extra_args)
                self.manager.start_all(
                    wait_ready=True,
                    callback=lambda stage, text: None,  # 日志靠定时器 pump
                )
                self.started.emit(self.manager)
        except Exception:  # noqa: BLE001
            if self._mode == "scan":
                self.scan_failed.emit(traceback.format_exc())
            else:
                self.failed.emit(traceback.format_exc())


class PublicAddressThread(QThread):
    """后台查本机公网 IPv4（要发 HTTP 请求，不能阻塞界面）。

    成功时 ``done(ip, 来源)``；失败时 ``done("", 失败原因)``。
    """

    done = pyqtSignal(str, str)

    def run(self) -> None:  # noqa: D102
        try:
            ip, source, via_proxy = netinfo.get_public_ip()
        except Exception:  # noqa: BLE001 - 网络异常种类很多，统一兜住
            self.done.emit("", f"查询公网地址出错：{traceback.format_exc(limit=1)}")
            return
        if not ip:
            self.done.emit("", "没能查到公网地址（接口都被挡了）")
            return
        kind = netinfo.classify_ip(ip)
        if kind == "public":
            origin = (f"{source}，经系统代理，可能不是真实出口"
                      if via_proxy else source)
            self.done.emit(ip, origin)
        elif kind == "cgnat":
            self.done.emit(
                "", f"出口地址 {ip} 属于运营商大内网（CGNAT），端口映射无效，请用「UDP 中继」页")
        else:
            self.done.emit("", f"出口地址 {ip} 不是公网地址（{kind}）")


# ---------------------------------------------------------------------------
# 主窗口
# ---------------------------------------------------------------------------
class MainWindow(QMainWindow):
    # 一键执行的常用指令。(key, 按钮文字, 提示)。回档有破坏性，执行前会先确认。
    QUICK_COMMANDS: ClassVar[list[tuple[str, str, str]]] = [
        ("save", "存档", "立即保存世界（c_save()）。随时可点，不影响玩家"),
        ("rollback", "回档一天", "回滚到上一个存档点（c_rollback(1)）。"
         "上一日的进度会丢失，玩家会被踢回主菜单/重进"),
        ("pause", "暂停世界", "暂停/继续服务器模拟（TheNet:SetServerPaused）。"
         "暂停时世界时间停止，已连接玩家保持在线但动不了"),
    ]

    def __init__(self, auto_run: bool = False, auto_scan: bool | None = None) -> None:
        """``auto_run=True`` 才会在窗口出现后自动跑网络检测（默认不跑）。

        检测会联网、改本机防火墙/UPnP 配置且要十几秒，所以默认交给用户点
        「开始检测并配置」触发；``auto_run`` 只留给自检这类特殊场景。
        ``auto_scan`` 控制「开服」标签页是否自动扫描本机存档（纯本地只读），
        默认跟随 ``auto_run``。
        """
        super().__init__()
        self.report: diagnostics.Report | None = None
        self.worker: Worker | None = None
        self.relay_thread: RelayThread | None = None
        self._closing = False
        self._auto_run = auto_run
        self._auto_scan = auto_run if auto_scan is None else auto_scan
        # 中继向导状态
        self._session = ""           # 本次主机/加入会话的校验值
        self._relay_ready = False    # 就绪检测是否全部通过
        self._relay_checked_once = False  # 中继就绪自检是否已跑过（切页再跑）
        self._relay_tab_index = 1
        self._host_info: dict | None = None  # 加入方解析出的主机码信息
        # 开服状态
        self._clusters: list = []
        self._server_thread: ServerThread | None = None
        self._server_scan_thread: ServerThread | None = None
        self._server_manager = None       # ServerManager 或 AttachedServer
        self._attached_pending = None     # 检测到待接管的 AttachedServer
        self._readiness_thread: ReadinessThread | None = None
        # 开服页「加入指令」用的地址（本地/公网）
        self._addr_probe_ip = ""
        self._addr_probe_note = ""
        self._public_addr_thread: PublicAddressThread | None = None
        # 开服页控制台：当前存档是否已开 console_enabled
        self._console_ready = False
        # 玩家管理：等待 c_listallplayers() 回显时记录日志长度基线（None=不在刷新中）
        self._player_capture_after: int | None = None
        # 服务器暂停状态（None=未知，按钮显示中性「暂停/继续」）
        self._server_paused: bool | None = None
        # 等暂停回显时的引擎时间戳基线（None=不在等待中；见 _chunk_fresh）
        self._pause_capture_at: int | None = None

        self.setWindowTitle(f"{config.APP_NAME}  v{config.APP_VERSION}")
        self.resize(900, 640)
        self.setMinimumSize(760, 560)

        root = QWidget(objectName="root")
        self.setCentralWidget(root)
        main = QVBoxLayout(root)
        main.setContentsMargins(16, 14, 16, 12)
        main.setSpacing(10)

        self._build_header(main)

        self.tabs = QTabWidget()
        main.addWidget(self.tabs, stretch=1)
        self.tabs.addTab(self._build_direct_tab(), "直连配置")
        self._relay_tab_index = self.tabs.addTab(self._build_relay_tab(), "UDP 中继")
        self.tabs.addTab(self._build_server_tab(), "开服")
        # 中继页的就绪自检要跑 netsh + 网络探测，启动时不做：
        # 等用户真的切到那一页（或点「重新检测」）再跑。
        self.tabs.currentChanged.connect(self._on_tab_changed)

        self._build_statusbar(main)

        # 中继流量刷新：不依赖中继主动推 stats（那样数据量随流量走），
        # 用定时器拉快照，节奏可控
        self._relay_timer = QTimer(self)
        self._relay_timer.setInterval(1000)
        self._relay_timer.timeout.connect(self._refresh_relay_stats)

        # 开服：日志增量刷新（服务器输出写进 <shard>/server_log.txt，按偏移增量读）
        self._server_timer = QTimer(self)
        self._server_timer.setInterval(800)
        self._server_timer.timeout.connect(self._pump_server_logs)

        # 默认不自动检测：等用户点「开始检测并配置」。
        # auto_run=True 时才在窗口出现后延迟触发（自检/回归用）。
        if self._auto_run:
            QTimer.singleShot(200, self.start_run)
        else:
            self._show_idle_state()

    # ------------------------------------------------------------------
    # 界面搭建
    # ------------------------------------------------------------------
    def _build_header(self, parent: QVBoxLayout) -> None:
        row = QHBoxLayout()
        parent.addLayout(row)

        title = QLabel(config.APP_NAME, objectName="appTitle")
        row.addWidget(title)
        row.addStretch(1)

        self.admin_badge = QLabel("", objectName="adminBadge")
        self.admin_badge.setProperty("admin", "0")
        self.admin_badge.setVisible(False)
        row.addWidget(self.admin_badge)
        # 徽标原先只在检测完成回调里显示；2026-09-23 起启动不再自动检测，
        # 徽标会一直藏着 → 改成搭界面时就显示。is_admin 是纯本地轻量调用
        # （IsUserAnAdmin，不联网不改系统），不需要等检测结果。
        self._refresh_admin_badge(winproc.is_admin())

    def _refresh_admin_badge(self, is_admin: bool) -> None:
        """按权限设置右上角徽标文案与配色并显示。"""
        if is_admin:
            self.admin_badge.setText("● 管理员模式")
            self.admin_badge.setProperty("admin", "1")
        else:
            self.admin_badge.setText("● 普通权限")
            self.admin_badge.setProperty("admin", "0")
        # 触发样式刷新
        self.admin_badge.style().unpolish(self.admin_badge)
        self.admin_badge.style().polish(self.admin_badge)
        self.admin_badge.setVisible(True)

    def _card(self, title: str) -> tuple[QFrame, QVBoxLayout]:
        card = QFrame(objectName="card")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(14, 10, 14, 12)
        layout.setSpacing(8)
        label = QLabel(title, objectName="cardTitle")
        layout.addWidget(label)
        return card, layout

    # ------------------------------------------------------------------
    # 弹窗封装：离屏（自动化测试）下不弹模态框，只记日志，避免阻塞事件循环
    # ------------------------------------------------------------------
    def _notify(self, kind: str, message: str) -> None:
        if _is_offscreen():
            self._append_relay_log(f"[{kind.upper():4}] {message}")
            return
        box = {
            "info": QMessageBox.information,
            "warn": QMessageBox.warning,
            "error": QMessageBox.critical,
        }.get(kind, QMessageBox.information)
        box(self, config.APP_NAME, message)

    def _build_direct_tab(self) -> QWidget:
        tab = QWidget()
        body = QHBoxLayout(tab)
        body.setContentsMargins(0, 10, 0, 0)
        body.setSpacing(10)

        self._build_checks_panel(body)

        right = QVBoxLayout()
        right.setSpacing(10)
        body.addLayout(right, stretch=3)
        self._build_address_card(right)
        self._build_actions(right)
        self._build_log_card(right)
        return tab

    def _build_checks_panel(self, parent: QHBoxLayout) -> None:
        card, layout = self._card("检 测 项")

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        self.checks_container = QWidget()
        self.checks_layout = QVBoxLayout(self.checks_container)
        self.checks_layout.setContentsMargins(2, 2, 2, 2)
        self.checks_layout.setSpacing(10)
        self.checks_layout.addStretch(1)
        scroll.setWidget(self.checks_container)
        layout.addWidget(scroll)

        card.setMinimumWidth(280)
        parent.addWidget(card, stretch=2)

    def _build_address_card(self, parent: QVBoxLayout) -> None:
        card, layout = self._card("把地址或指令发给朋友")

        self.address_view = QLineEdit(objectName="addressView")
        self.address_view.setReadOnly(True)
        self.address_view.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.address_view.setText("尚未检测")
        layout.addWidget(self.address_view)

        self.command_view = QLineEdit(objectName="commandView")
        self.command_view.setReadOnly(True)
        self.command_view.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.command_view.setPlaceholderText("控制台指令：尚未检测")
        layout.addWidget(self.command_view)

        row = QHBoxLayout()
        row.setSpacing(8)
        layout.addLayout(row)

        self.btn_copy_addr = QPushButton("复制指令")
        self.btn_copy_addr.setToolTip(
            "复制饥荒控制台直连指令，朋友粘贴到控制台回车即可加入"
        )
        self.btn_copy_addr.clicked.connect(self.copy_command)
        row.addWidget(self.btn_copy_addr)

        self.btn_copy_share = QPushButton("复制完整说明（发给朋友）")
        self.btn_copy_share.clicked.connect(self.copy_share_text)
        self.btn_copy_share.setEnabled(False)
        row.addWidget(self.btn_copy_share)
        row.addStretch(1)

        parent.addWidget(card)

    def _build_actions(self, parent: QVBoxLayout) -> None:
        card, layout = self._card("操 作")

        row = QHBoxLayout()
        row.setSpacing(8)
        layout.addLayout(row)

        self.btn_run = QPushButton("开始检测并配置", objectName="primary")
        self.btn_run.clicked.connect(self.start_run)
        row.addWidget(self.btn_run)

        self.btn_elevate = QPushButton("以管理员身份重启")
        self.btn_elevate.clicked.connect(self.elevate)
        row.addWidget(self.btn_elevate)

        self.btn_cleanup = QPushButton("撤销我的配置", objectName="danger")
        self.btn_cleanup.clicked.connect(self.start_cleanup)
        row.addWidget(self.btn_cleanup)
        row.addStretch(1)

        row2 = QHBoxLayout()
        row2.setSpacing(8)
        layout.addLayout(row2)

        self.autocopy = QCheckBox("完成后自动复制指令")
        self.autocopy.setChecked(True)
        row2.addWidget(self.autocopy)

        row2.addSpacing(12)
        row2.addWidget(QLabel("端口："))
        self.port_input = QLineEdit(objectName="portInput")
        self.port_input.setPlaceholderText("留空 = 自动识别")
        self.port_input.setFixedWidth(150)
        row2.addWidget(self.port_input)
        row2.addStretch(1)

        parent.addWidget(card)

    def _build_log_card(self, parent: QVBoxLayout) -> None:
        card, layout = self._card("日 志")

        self.log_view = QPlainTextEdit(objectName="logView")
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumBlockCount(3000)
        layout.addWidget(self.log_view)

        parent.addWidget(card, stretch=1)

    # ------------------------------------------------------------------
    # 中继标签页
    # ------------------------------------------------------------------
    def _build_relay_tab(self) -> QWidget:
        tab = QWidget()
        outer = QVBoxLayout(tab)
        outer.setContentsMargins(0, 10, 0, 0)
        outer.setSpacing(0)

        # 内容整体放进滚动区：窗口不够高时出滚动条，
        # 而不是把「确认生效并启动中继」这类按钮压扁成一条线
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        outer.addWidget(scroll)

        content = QWidget()
        scroll.setWidget(content)
        body = QVBoxLayout(content)
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(10)

        # 第 1 步：就绪检测 + 第 2 步：角色
        top = QHBoxLayout()
        top.setSpacing(10)
        body.addLayout(top)

        rcard, rlay = self._card("第 1 步 · 检测本机能否中继")
        self.relay_ready_view = QPlainTextEdit(objectName="logView")
        self.relay_ready_view.setReadOnly(True)
        self.relay_ready_view.setMaximumBlockCount(50)
        self.relay_ready_view.setFixedHeight(110)
        rlay.addWidget(self.relay_ready_view)
        rbtn = QHBoxLayout()
        self.btn_relay_check = QPushButton("重新检测")
        self.btn_relay_check.clicked.connect(self.refresh_relay_readiness)
        rbtn.addWidget(self.btn_relay_check)
        rbtn.addStretch(1)
        rlay.addLayout(rbtn)
        top.addWidget(rcard, stretch=3)

        ccard, clay = self._card("第 2 步 · 我是")
        self.role_group = QButtonGroup(self)
        self.rb_host = QRadioButton("主机（我开世界，别人连我）")
        self.rb_join = QRadioButton("加入方（我连别人的世界）")
        self.rb_host.setChecked(True)
        self.role_group.addButton(self.rb_host)
        self.role_group.addButton(self.rb_join)
        clay.addWidget(self.rb_host)
        clay.addWidget(self.rb_join)
        self.rb_host.toggled.connect(self._on_role_changed)
        top.addWidget(ccard, stretch=2)

        # 角色面板（host / join 两张，切换显隐）
        # 不设 stretch、给最小高度：让操作区按自然高度布局，
        # 剩余空间全留给底部「实时 + 日志」，按钮不再被压扁
        self.host_panel = self._build_host_panel()
        self.host_panel.setMinimumHeight(220)
        body.addWidget(self.host_panel)
        self.join_panel = self._build_join_panel()
        self.join_panel.setMinimumHeight(220)
        body.addWidget(self.join_panel)
        self.join_panel.setVisible(False)

        # 实时 + 日志
        bottom = QHBoxLayout()
        bottom.setSpacing(10)
        body.addLayout(bottom, stretch=1)
        scard, slay = self._card("实 时")
        self.relay_stats_label = QLabel("—", objectName="checkDetail")
        self.relay_stats_label.setWordWrap(True)
        slay.addWidget(self.relay_stats_label)
        bottom.addWidget(scard, stretch=1)
        lcard, llay = self._card("中继日志")
        self.relay_log_view = QPlainTextEdit(objectName="logView")
        self.relay_log_view.setReadOnly(True)
        self.relay_log_view.setMaximumBlockCount(2000)
        llay.addWidget(self.relay_log_view)
        bottom.addWidget(lcard, stretch=2)

        self.relay_ready_view.setPlainText("尚未检测（切到本页会自动开始，也可点下面「重新检测」）")
        return tab

    def _build_host_panel(self) -> QWidget:
        panel = QWidget()
        col = QVBoxLayout(panel)
        col.setContentsMargins(0, 0, 0, 0)
        col.setSpacing(10)

        hcard, hlay = self._card("第 3 步 · 我的主机码（发给加入方）")
        hrow = QHBoxLayout()
        self.host_code_view = QLineEdit(objectName="commandView")
        self.host_code_view.setReadOnly(True)
        self.host_code_view.setPlaceholderText("检测通过后自动生成")
        hrow.addWidget(self.host_code_view, stretch=1)
        self.btn_host_code_copy = QPushButton("复制主机码")
        self.btn_host_code_copy.clicked.connect(self.copy_host_code)
        self.btn_host_code_copy.setEnabled(False)
        hrow.addWidget(self.btn_host_code_copy)
        self.btn_host_code_regen = QPushButton("重新生成")
        self.btn_host_code_regen.setToolTip("换一个新的校验值；旧的加入码将作废")
        self.btn_host_code_regen.clicked.connect(self.regen_host_code)
        hrow.addWidget(self.btn_host_code_regen)
        hlay.addLayout(hrow)
        self.host_status_label = QLabel("", objectName="statusLabel")
        self.host_status_label.setWordWrap(True)
        hlay.addWidget(self.host_status_label)
        col.addWidget(hcard)

        mcard, mlay = self._card("第 4 步 · 管理加入码（白名单）")
        arow = QHBoxLayout()
        self.join_code_input = QLineEdit(objectName="portInput")
        self.join_code_input.setPlaceholderText("粘贴加入方发来的 JOIN… 码")
        arow.addWidget(self.join_code_input, stretch=1)
        self.join_note_input = QLineEdit(objectName="portInput")
        self.join_note_input.setPlaceholderText("备注（谁）")
        self.join_note_input.setFixedWidth(120)
        arow.addWidget(self.join_note_input)
        self.btn_join_add = QPushButton("添加")
        self.btn_join_add.clicked.connect(self.add_join_code)
        arow.addWidget(self.btn_join_add)
        mlay.addLayout(arow)

        self.join_list_layout = QVBoxLayout()
        self.join_list_layout.setSpacing(4)
        mlay.addLayout(self.join_list_layout)

        btnrow = QHBoxLayout()
        self.btn_join_apply = QPushButton("确认生效并启动中继", objectName="primary")
        self.btn_join_apply.setToolTip(
            "未启动：绑定端口、放行防火墙并启动中继（没有加入码也能启动，"
            "先以「拒绝所有人」守门）；\n已启动：只把当前加入码热更新进去，立即生效、不重启")
        self.btn_join_apply.clicked.connect(self.apply_host_rules)
        btnrow.addWidget(self.btn_join_apply)
        self.btn_host_stop = QPushButton("停止")
        self.btn_host_stop.clicked.connect(self.stop_relay)
        self.btn_host_stop.setEnabled(False)
        btnrow.addWidget(self.btn_host_stop)
        btnrow.addStretch(1)
        mlay.addLayout(btnrow)
        col.addWidget(mcard)

        self._reload_join_list()
        return panel

    def _build_join_panel(self) -> QWidget:
        panel = QWidget()
        col = QVBoxLayout(panel)
        col.setContentsMargins(0, 0, 0, 0)
        col.setSpacing(10)

        # 第 3 步：填入主机码（一粘贴就解析，立刻生成下面的加入码）
        kcard, klay = self._card("第 3 步 · 填入主机码")
        krow = QHBoxLayout()
        self.host_code_input = QLineEdit(objectName="portInput")
        self.host_code_input.setPlaceholderText("粘贴主机发来的 HOST… 码")
        self.host_code_input.textChanged.connect(self._on_host_code_changed)
        krow.addWidget(self.host_code_input, stretch=1)
        klay.addLayout(krow)
        self.host_parse_label = QLabel("", objectName="statusLabel")
        self.host_parse_label.setWordWrap(True)
        klay.addWidget(self.host_parse_label)
        col.addWidget(kcard)

        # 第 4 步：我的加入码（先发给主机加白名单，等确认后再启动）
        jcard, jlay = self._card("第 4 步 · 我的加入码（发给主机）")
        jrow = QHBoxLayout()
        self.join_code_view = QLineEdit(objectName="commandView")
        self.join_code_view.setReadOnly(True)
        self.join_code_view.setPlaceholderText("填入主机码后自动生成")
        jrow.addWidget(self.join_code_view, stretch=1)
        self.btn_join_code_copy = QPushButton("复制加入码")
        self.btn_join_code_copy.clicked.connect(self.copy_join_code)
        self.btn_join_code_copy.setEnabled(False)
        jrow.addWidget(self.btn_join_code_copy)
        jlay.addLayout(jrow)
        jhint = QLabel("发给主机，等 TA 添加并确认生效后，再进行下一步。",
                       objectName="checkDetail")
        jhint.setWordWrap(True)
        jlay.addWidget(jhint)
        col.addWidget(jcard)

        # 第 5 步：启动中继
        scard, slay = self._card("第 5 步 · 启动中继")
        srow = QHBoxLayout()
        self.btn_join_start = QPushButton("启动中继", objectName="primary")
        self.btn_join_start.clicked.connect(self.apply_and_start)
        srow.addWidget(self.btn_join_start)
        self.btn_join_stop = QPushButton("停止")
        self.btn_join_stop.clicked.connect(self.stop_relay)
        self.btn_join_stop.setEnabled(False)
        srow.addWidget(self.btn_join_stop)
        self.btn_join_probe = QPushButton("测试到主机的连通性")
        self.btn_join_probe.setToolTip(
            "向主机中继端口发探测包。能区分「包没到主机」与「到了但被白名单拒」，"
            "不必先启动中继")
        self.btn_join_probe.clicked.connect(self.probe_host)
        srow.addWidget(self.btn_join_probe)
        srow.addStretch(1)
        slay.addLayout(srow)

        crow = QHBoxLayout()
        self.join_cmd_view = QLineEdit(objectName="commandView")
        self.join_cmd_view.setReadOnly(True)
        self.join_cmd_view.setPlaceholderText("启动后自动生成 c_connect 指令")
        crow.addWidget(self.join_cmd_view, stretch=1)
        self.btn_join_cmd_copy = QPushButton("复制指令")
        self.btn_join_cmd_copy.clicked.connect(self.copy_join_cmd)
        self.btn_join_cmd_copy.setEnabled(False)
        crow.addWidget(self.btn_join_cmd_copy)
        slay.addLayout(crow)

        self.join_status_label = QLabel("", objectName="statusLabel")
        self.join_status_label.setWordWrap(True)
        slay.addWidget(self.join_status_label)
        col.addWidget(scard)
        return panel

    # ------------------------------------------------------------------
    # 开服标签页
    # ------------------------------------------------------------------
    def _build_server_tab(self) -> QWidget:
        tab = QWidget()
        outer = QVBoxLayout(tab)
        outer.setContentsMargins(0, 10, 0, 0)
        outer.setSpacing(0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        outer.addWidget(scroll)

        content = QWidget()
        scroll.setWidget(content)
        body = QVBoxLayout(content)
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(10)

        # 第 1 步：选存档
        pick = QHBoxLayout()
        pick.setSpacing(10)
        body.addLayout(pick)

        scard, slay = self._card("第 1 步 · 选择一个存档")
        srow = QHBoxLayout()
        self.cluster_combo = QComboBox()
        self.cluster_combo.currentIndexChanged.connect(self._on_cluster_changed)
        srow.addWidget(self.cluster_combo, stretch=1)
        self.btn_cluster_refresh = QPushButton("刷新")
        self.btn_cluster_refresh.clicked.connect(self.refresh_clusters)
        srow.addWidget(self.btn_cluster_refresh)
        slay.addLayout(srow)
        self.cluster_summary = QLabel("", objectName="checkDetail")
        self.cluster_summary.setWordWrap(True)
        slay.addWidget(self.cluster_summary)
        self.server_update_mods = QCheckBox("启动前更新模组（连 Steam，较慢；不勾则跳过）")
        slay.addWidget(self.server_update_mods)

        # 缺令牌时的粘贴区（默认隐藏，仅当前存档缺令牌时显示）
        self.token_row = QWidget()
        tlay = QHBoxLayout(self.token_row)
        tlay.setContentsMargins(0, 0, 0, 0)
        tlay.setSpacing(6)
        self.token_input = QLineEdit(objectName="portInput")
        self.token_input.setPlaceholderText("粘贴 Klei 开服令牌（cluster_token）")
        tlay.addWidget(self.token_input, stretch=1)
        self.btn_token_save = QPushButton("保存令牌")
        self.btn_token_save.clicked.connect(self._on_save_token)
        tlay.addWidget(self.btn_token_save)
        self.token_row.setVisible(False)
        slay.addWidget(self.token_row)

        # 高级设置（默认收起）：路径覆盖，解决环境探测不到的边界情况
        self.btn_adv_toggle = QPushButton("高级设置 ▸")
        self.btn_adv_toggle.setFlat(True)
        self.btn_adv_toggle.clicked.connect(self._on_toggle_adv)
        slay.addWidget(self.btn_adv_toggle)

        self.adv_panel = QWidget()
        alay = QVBoxLayout(self.adv_panel)
        alay.setContentsMargins(8, 4, 8, 4)
        alay.setSpacing(6)

        grow = QHBoxLayout()
        grow.addWidget(QLabel("游戏目录："))
        self.game_dir_input = QLineEdit(objectName="portInput")
        self.game_dir_input.setPlaceholderText("留空 = 自动从 Steam 库探测")
        grow.addWidget(self.game_dir_input, stretch=1)
        btn_g = QPushButton("浏览…")
        btn_g.clicked.connect(self._on_browse_game_dir)
        grow.addWidget(btn_g)
        alay.addLayout(grow)

        srow2 = QHBoxLayout()
        srow2.addWidget(QLabel("存档根：  "))
        self.storage_root_input = QLineEdit(objectName="portInput")
        self.storage_root_input.setPlaceholderText("留空 = <文档>\\Klei")
        srow2.addWidget(self.storage_root_input, stretch=1)
        btn_s = QPushButton("浏览…")
        btn_s.clicked.connect(self._on_browse_storage_root)
        srow2.addWidget(btn_s)
        alay.addLayout(srow2)

        crow2 = QHBoxLayout()
        crow2.addWidget(QLabel("conf_dir："))
        self.conf_dir_input = QLineEdit(objectName="portInput")
        self.conf_dir_input.setPlaceholderText("留空 = 自动（稳定版/Beta 各用各的）")
        crow2.addWidget(self.conf_dir_input, stretch=1)
        alay.addLayout(crow2)

        erow = QHBoxLayout()
        erow.addWidget(QLabel("额外参数："))
        self.extra_args_input = QLineEdit(objectName="portInput")
        self.extra_args_input.setPlaceholderText("如  -lan -players 6（留空）")
        erow.addWidget(self.extra_args_input, stretch=1)
        alay.addLayout(erow)

        srow3 = QHBoxLayout()
        self.btn_save_settings = QPushButton("保存设置")
        self.btn_save_settings.clicked.connect(self._on_save_settings)
        srow3.addWidget(self.btn_save_settings)
        srow3.addStretch(1)
        alay.addLayout(srow3)

        self.adv_panel.setVisible(False)
        slay.addWidget(self.adv_panel)
        pick.addWidget(scard, stretch=3)

        # 模组清单
        mcard, mlay = self._card("存档启用的模组")
        self.mod_list = QPlainTextEdit(objectName="logView")
        self.mod_list.setReadOnly(True)
        self.mod_list.setMaximumBlockCount(200)
        mlay.addWidget(self.mod_list)
        pick.addWidget(mcard, stretch=2)

        # 第 2 步：启动 / 停止 + 状态；第 3 步：明文显示的加入指令。
        # 两者放在同一列，指令就跟在「启动」按钮下面，不用去别的标签页找。
        row = QHBoxLayout()
        row.setSpacing(10)
        body.addLayout(row)

        left = QVBoxLayout()
        left.setSpacing(10)
        row.addLayout(left, stretch=1)

        acard, alay = self._card("第 2 步 · 启动专用服务器")
        arow = QHBoxLayout()
        self.btn_server_start = QPushButton("启动服务器", objectName="primary")
        self.btn_server_start.clicked.connect(self.start_server)
        self.btn_server_start.setEnabled(False)
        arow.addWidget(self.btn_server_start)
        self.btn_server_attach = QPushButton("接管运行中的服务器")
        self.btn_server_attach.clicked.connect(self.attach_server)
        self.btn_server_attach.setEnabled(False)
        arow.addWidget(self.btn_server_attach)
        self.btn_server_stop = QPushButton("停止服务器", objectName="danger")
        self.btn_server_stop.clicked.connect(self.stop_server)
        self.btn_server_stop.setEnabled(False)
        arow.addWidget(self.btn_server_stop)
        arow.addStretch(1)
        alay.addLayout(arow)
        self.server_status_label = QLabel("尚未选择存档", objectName="statusLabel")
        self.server_status_label.setWordWrap(True)
        alay.addWidget(self.server_status_label)
        self.server_shards_label = QLabel("", objectName="checkDetail")
        self.server_shards_label.setWordWrap(True)
        alay.addWidget(self.server_shards_label)

        # 服务器控制台：直接向专用服务器进程的 stdin 发 Lua 指令
        crow = QHBoxLayout()
        crow.setSpacing(6)
        self.server_cmd_input = QLineEdit(objectName="portInput")
        self.server_cmd_input.setPlaceholderText(
            "服务器控制台：输入 Lua 指令回车执行，如 c_listallplayers()")
        self.server_cmd_input.returnPressed.connect(self.send_server_command)
        crow.addWidget(self.server_cmd_input, stretch=1)
        self.server_cmd_target = QComboBox()
        self.server_cmd_target.setToolTip("指令发给哪个分片（洞穴是独立进程）")
        crow.addWidget(self.server_cmd_target)
        self.btn_server_cmd_send = QPushButton("执行")
        self.btn_server_cmd_send.setToolTip(
            "把指令写进服务器进程 stdin。需要本工具启动的服务器；"
            "接管的外部进程拿不到 stdin")
        self.btn_server_cmd_send.clicked.connect(self.send_server_command)
        self.btn_server_cmd_send.setEnabled(False)
        crow.addWidget(self.btn_server_cmd_send)
        self.btn_console_fix = QPushButton("开启控制台")
        self.btn_console_fix.setToolTip(
            "向该存档的 cluster.ini 写入 [MISC] console_enabled = true\n"
            "（自动备份为 cluster.ini.bak）。不开启时服务器可能不受理 stdin 指令")
        self.btn_console_fix.clicked.connect(self._on_fix_console)
        self.btn_console_fix.setVisible(False)
        crow.addWidget(self.btn_console_fix)
        alay.addLayout(crow)

        # 常用指令一键执行（回档有破坏性，会先确认；看玩家在下面的玩家管理卡里）
        qrow = QHBoxLayout()
        qrow.setSpacing(6)
        self.quick_cmd_buttons: dict[str, QPushButton] = {}
        for key, label, tip in self.QUICK_COMMANDS:
            btn = QPushButton(label)
            btn.setToolTip(tip)
            btn.clicked.connect(lambda _c=False, k=key: self.run_quick_command(k))
            btn.setEnabled(False)
            qrow.addWidget(btn)
            self.quick_cmd_buttons[key] = btn
        qrow.addStretch(1)
        alay.addLayout(qrow)
        left.addWidget(acard)
        self._refresh_console_row()  # 初始「未运行」态：禁用输入框并给出引导占位

        # 玩家管理：在线列表 + 踢/拉黑（解析「看玩家」的输出行）
        pcard, play = self._card("玩家管理")
        prow = QHBoxLayout()
        prow.setSpacing(6)
        self.btn_player_refresh = QPushButton("刷新列表")
        self.btn_player_refresh.setToolTip(
            "向服务器发 c_listallplayers() 并解析日志得到在线玩家")
        self.btn_player_refresh.clicked.connect(self.refresh_players)
        self.btn_player_refresh.setEnabled(False)
        prow.addWidget(self.btn_player_refresh)
        self.player_autorefresh = QCheckBox("自动 5s")
        self.player_autorefresh.setToolTip("每 5 秒自动刷新在线玩家列表")
        self.player_autorefresh.toggled.connect(self._on_player_autorefresh_toggled)
        self.player_autorefresh.setEnabled(False)
        prow.addWidget(self.player_autorefresh)
        self.btn_player_kick = QPushButton("踢出", objectName="danger")
        self.btn_player_kick.setToolTip("把选中玩家踢下线（TheNet:Kick），不拉黑")
        self.btn_player_kick.clicked.connect(lambda: self.player_kick_ban(kick=True))
        self.btn_player_kick.setEnabled(False)
        prow.addWidget(self.btn_player_kick)
        self.btn_player_ban = QPushButton("拉黑", objectName="danger")
        self.btn_player_ban.setToolTip(
            "把选中玩家写进存档的 blocklist.txt 并踢下线（重启后仍生效）")
        self.btn_player_ban.clicked.connect(lambda: self.player_kick_ban(kick=False))
        self.btn_player_ban.setEnabled(False)
        prow.addWidget(self.btn_player_ban)
        prow.addStretch(1)
        play.addLayout(prow)

        self.player_table = QTableWidget(0, 3)
        self.player_table.setHorizontalHeaderLabels(["玩家", "角色", "Klei ID"])
        self.player_table.verticalHeader().setVisible(False)
        self.player_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.player_table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows)
        self.player_table.setSelectionMode(
            QAbstractItemView.SelectionMode.SingleSelection)
        self.player_table.itemSelectionChanged.connect(self._on_player_selection_changed)
        self.player_table.setMinimumHeight(110)
        self.player_table.setMaximumHeight(170)
        header = self.player_table.horizontalHeader()
        header.setStretchLastSection(True)
        play.addWidget(self.player_table)
        self.player_hint_label = QLabel(
            "服务器未运行时不可用；启动后点「刷新列表」或勾选自动刷新。",
            objectName="checkDetail")
        self.player_hint_label.setWordWrap(True)
        play.addWidget(self.player_hint_label)
        left.addWidget(pcard)

        # 自动刷新定时器（默认 5s；服务器启动并勾选后才转）
        self._player_timer = QTimer(self)
        self._player_timer.setInterval(5000)
        self._player_timer.timeout.connect(self._player_timer_tick)

        # 第 3 步：明文显示的加入指令（直接发给朋友）
        jcard, jlay = self._card("第 3 步 · 把加入指令发给朋友")
        self.server_cmd_view = QLineEdit(objectName="commandView")
        self.server_cmd_view.setReadOnly(True)
        self.server_cmd_view.setPlaceholderText("选择存档后自动生成 c_connect 指令")
        jlay.addWidget(self.server_cmd_view)
        jrow = QHBoxLayout()
        jrow.setSpacing(8)
        self.btn_server_cmd_copy = QPushButton("复制指令")
        self.btn_server_cmd_copy.clicked.connect(self.copy_server_command)
        self.btn_server_cmd_copy.setEnabled(False)
        jrow.addWidget(self.btn_server_cmd_copy)
        self.btn_server_cmd_probe = QPushButton("获取公网地址")
        self.btn_server_cmd_probe.setToolTip(
            "查本机公网 IPv4 并换到指令里；跨网络联机需要它 + 端口映射")
        self.btn_server_cmd_probe.clicked.connect(self.probe_server_address)
        jrow.addWidget(self.btn_server_cmd_probe)
        jrow.addStretch(1)
        jlay.addLayout(jrow)
        self.server_cmd_hint = QLabel("", objectName="checkDetail")
        self.server_cmd_hint.setWordWrap(True)
        jlay.addWidget(self.server_cmd_hint)
        left.addWidget(jcard)
        left.addStretch(1)

        # 服务器日志
        lcard, llay = self._card("服务器日志")
        self.server_log_view = QPlainTextEdit(objectName="logView")
        self.server_log_view.setReadOnly(True)
        self.server_log_view.setMaximumBlockCount(2000)
        llay.addWidget(self.server_log_view)
        row.addWidget(lcard, stretch=2)

        # auto_scan=False（离屏测试）时不自动扫描，避免后台线程去碰真实文件系统
        if self._auto_scan:
            self.refresh_clusters()
        else:
            self.cluster_combo.addItem("（未扫描）", None)
        self._refresh_server_join_command()
        return tab

    # -- 开服：扫描 -----------------------------------------------------------

    def refresh_clusters(self) -> None:
        if getattr(self, "_server_scan_thread", None) is not None \
                and self._server_scan_thread.isRunning():
            return
        self.cluster_combo.clear()
        self.cluster_combo.addItem("扫描中…", None)
        self.mod_list.clear()
        self._server_scan_thread = ServerThread("scan")
        self._server_scan_thread.scanned.connect(self._on_clusters_scanned)
        self._server_scan_thread.scan_failed.connect(self._on_scan_failed)
        self._server_scan_thread.finished.connect(
            lambda: setattr(self, "_server_scan_thread", None))
        self._server_scan_thread.start()

    def _on_scan_failed(self, tb: str) -> None:
        self.cluster_combo.clear()
        self.cluster_combo.addItem("扫描失败", None)
        self._append_server_log(f"[FAIL] 扫描存档失败：\n{tb}")

    def _on_clusters_scanned(self, clusters: list) -> None:
        self._clusters = clusters or []
        self.cluster_combo.blockSignals(True)
        self.cluster_combo.clear()
        if not self._clusters:
            self.cluster_combo.addItem("未发现存档", None)
            self.cluster_combo.setEnabled(False)
            self.btn_server_start.setEnabled(False)
        else:
            self.cluster_combo.setEnabled(True)
            for c in self._clusters:
                self.cluster_combo.addItem(f"{c.name} · {c.cluster_name}", c)
            self.btn_server_start.setEnabled(True)
            # 默认选模组最多的那个（通常是活跃存档）
            best = max(range(len(self._clusters)),
                       key=lambda i: len(self._clusters[i].mods))
            self.cluster_combo.setCurrentIndex(best)
        self.cluster_combo.blockSignals(False)
        self._on_cluster_changed(self.cluster_combo.currentIndex())
        self._check_running_server()

    def _check_running_server(self) -> None:
        """扫描后检测是否已有服务器在跑，有则提示可接管。"""
        if self._server_manager is not None:
            return  # 已经在管理一个服务器了
        attached = server.attach_running_procs(self._clusters)
        if attached is None:
            self.btn_server_attach.setEnabled(False)
            self._attached_pending = None
            return
        self._attached_pending = attached
        n = len(attached.shards)
        cname = attached.cluster.name if attached.cluster else "(未知存档)"
        self.btn_server_attach.setEnabled(True)
        self.server_status_label.setText(
            f"检测到已有 {n} 个分片在运行（{cname}），可点击「接管」纳入管理")
        self._append_server_log(f"[INFO] 检测到运行中的服务器：{cname}（{n} 个分片）")

    def attach_server(self) -> None:
        """接管检测到的运行中服务器（只监控/停止，不重复启动）。"""
        attached = getattr(self, "_attached_pending", None)
        if attached is None:
            return
        self._server_manager = attached
        self._attached_pending = None
        self.btn_server_attach.setEnabled(False)
        self.btn_server_start.setEnabled(False)
        self.btn_server_stop.setEnabled(True)
        self.server_status_label.setText("已接管运行中的服务器（监控中）")
        self._append_server_log("[OK] 已接管运行中的服务器")
        self._server_paused = None  # 外部进程，状态未知且无法主动查询
        self._pause_capture_at = None
        self._server_timer.start()
        self._pump_server_logs()
        self._refresh_console_row()
        self._on_player_autorefresh_manage()
        self._refresh_server_join_command()

    def _on_cluster_changed(self, _index: int) -> None:
        cluster = self._current_cluster()
        self._pump_server_logs()  # 切换存档时清掉旧 manager 的引用即可
        if cluster is None:
            self.cluster_summary.setText("")
            self.mod_list.clear()
            self.server_shards_label.setText("")
            self._refresh_server_join_command()
            return
        missing = cluster.missing_mods()
        token_mark = "✓ 有令牌" if cluster.has_token else "✗ 缺令牌"
        summary = cluster.summary()
        if missing:
            summary += f"\n⚠ 有 {len(missing)} 个模组未下载：{', '.join(m.id for m in missing)}"
        self.cluster_summary.setText(f"{summary}\n{token_mark}")

        lines = []
        for m in cluster.mods:
            mark = "" if m.installed else " ✗未下载"
            cfg = f"（{m.config_count} 项配置）" if m.config_count else ""
            ver = f" v{m.version}" if m.version else ""
            lines.append(f"• {m.display_name}{ver}{cfg}{mark}")
        self.mod_list.setPlainText("\n".join(lines) if lines else "（无存档启用的模组）")

        self.token_row.setVisible(not cluster.has_token)
        if not cluster.has_token:
            self.server_status_label.setText("⚠ 该存档缺 cluster_token.txt，请粘贴令牌后保存")
        elif missing:
            self.server_status_label.setText("⚠ 有模组未下载，可用启动前更新模组补齐")
        else:
            self.server_status_label.setText("就绪，可以启动")
        # 控制台需要 cluster.ini 的 [MISC] console_enabled=true（缺则给一键补写按钮）
        console_ok = server.console_enabled(cluster)
        self._console_ready = console_ok
        self.btn_console_fix.setVisible(not console_ok)
        self._refresh_server_join_command()

    def _on_fix_console(self) -> None:
        """给当前存档补写 [MISC] console_enabled = true。"""
        cluster = self._current_cluster()
        if cluster is None:
            return
        ok, msg = server.enable_console(cluster)
        self._append_server_log(("[OK] " if ok else "[FAIL] ") +
                                f"{cluster.name}: {msg}")
        if ok:
            self.btn_console_fix.setVisible(False)
            self._console_ready = True
            self._notify("info",
                         f"已开启服务器控制台（{msg}）。\n"
                         "对已运行的服务器不生效，需下次启动。")
        else:
            self._notify("warn", msg)

    def _current_cluster(self):
        data = self.cluster_combo.currentData()
        return data if isinstance(data, server.ClusterInfo) else None

    # -- 开服：加入指令 ---------------------------------------------------------

    def _server_join_address(self) -> tuple[str, str]:
        """挑一个写进 ``c_connect`` 的地址，返回 ``(ip, 说明)``。

        优先用「获取公网地址」的结果（或「直连配置」页已跑出的检测结果），
        否则退回本机局域网地址。**不联网**（公网查询在按钮/后台线程里做）。
        """
        if self._addr_probe_ip:
            return self._addr_probe_ip, self._addr_probe_note
        if self.report is not None:
            ip, _ = split_address(self.report.shareable_ip)
            if ip:
                return ip, "「直连配置」页检测出的公网地址"
            ip, _ = split_address(self.report.primary_address or self.report.lan_address)
            if ip:
                return ip, "「直连配置」页的检测结果"
        ips = netinfo.get_local_ips()
        if ips:
            return ips[0], "本机局域网地址，同一个 WiFi 的朋友可用"
        return "", "没能确定本机地址"

    def _refresh_server_join_command(self) -> None:
        """刷新开服页的加入指令（选存档、启停服务器后都要跟一下）。"""
        cluster = self._current_cluster()
        if cluster is None:
            self.server_cmd_view.clear()
            self.btn_server_cmd_copy.setEnabled(False)
            self.server_cmd_hint.setText("先在上面选一个存档，这里会给出可发给朋友的指令。")
            return
        ip, note = self._server_join_address()
        if not ip:
            self.server_cmd_view.clear()
            self.btn_server_cmd_copy.setEnabled(False)
            self.server_cmd_hint.setText(note)
            return
        # 端口固定用主世界（10999）：客户端连不进洞穴分片
        master = config.pick_master_port(cluster.ports())
        self.server_cmd_view.setText(config.join_command(ip, master))
        self.btn_server_cmd_copy.setEnabled(True)

        running = (self._server_manager is not None
                   and self._server_manager.any_running())
        head = (f"地址 {ip}（{note}）；主世界端口 {master}。"
                if running else
                f"地址 {ip}（{note}）；主世界端口 {master}，服务器尚未运行，"
                "朋友现在连不上。")
        lines = [
            head,
            "朋友在主菜单按 ` 打开控制台，粘贴上面指令回车即可加入。",
            "跨网络需公网地址 + 端口映射；双重 NAT / 只有 IPv6 请用「UDP 中继」页。",
        ]
        if self._addr_probe_note and not self._addr_probe_ip:
            lines.insert(1, f"上次查询公网地址：{self._addr_probe_note}")
        self.server_cmd_hint.setText("\n".join(lines))

    def copy_server_command(self) -> None:
        command = self.server_cmd_view.text().strip()
        if not command:
            self._notify("info", "还没有可复制的加入指令")
            return
        if winproc.set_clipboard_text(command):
            self._set_status("加入指令已复制，发给朋友即可")
            self._append_server_log(f"[OK] 加入指令已复制：{command}")
        else:
            self._notify("warn", "写入剪贴板失败，请手动选中复制")

    def probe_server_address(self) -> None:
        """查本机公网 IPv4 并换到加入指令里（后台线程，避免卡界面）。"""
        if self._public_addr_thread is not None and self._public_addr_thread.isRunning():
            return
        if _is_offscreen():
            # 离屏（自动化测试）不联网，避免拖慢测试 / 留下未结束的线程
            self._append_server_log("[INFO] 离屏模式跳过公网地址查询")
            return
        self.btn_server_cmd_probe.setEnabled(False)
        self._addr_probe_note = "正在查询…"
        self._refresh_server_join_command()
        thread = PublicAddressThread()
        thread.done.connect(self._on_public_address)
        thread.finished.connect(self._on_public_address_finished)
        self._public_addr_thread = thread
        thread.start()

    def _on_public_address_finished(self) -> None:
        self._public_addr_thread = None
        self.btn_server_cmd_probe.setEnabled(True)

    def _on_public_address(self, ip: str, note: str) -> None:
        self._addr_probe_ip = ip
        self._addr_probe_note = f"公网地址，来自 {note}" if ip else note
        if ip:
            self._append_server_log(f"[OK] 已获取公网地址 {ip}（来自 {note}）")
        else:
            self._append_server_log(f"[WARN] {note}")
        self._refresh_server_join_command()

    # -- 开服：令牌与高级设置 ---------------------------------------------

    def _on_save_token(self) -> None:
        cluster = self._current_cluster()
        if cluster is None:
            return
        ok, result = server.validate_token(self.token_input.text())
        if not ok:
            self._notify("warn", f"令牌无效：{result}")
            return
        try:
            server.write_token(cluster, result)
        except OSError as exc:
            self._notify("error", f"写入令牌失败：{exc}")
            return
        self.token_input.clear()
        self.token_row.setVisible(False)
        self.server_status_label.setText("令牌已保存，可以启动")
        self._append_server_log(f"[OK] 已为 {cluster.name} 保存令牌")
        self._on_cluster_changed(self.cluster_combo.currentIndex())

    def _on_toggle_adv(self) -> None:
        vis = not self.adv_panel.isVisible()
        self.adv_panel.setVisible(vis)
        self.btn_adv_toggle.setText("高级设置 ▾" if vis else "高级设置 ▸")
        if vis:
            self._load_settings_to_ui()

    def _load_settings_to_ui(self) -> None:
        s = server.settings()
        self.game_dir_input.setText(s.game_dir)
        self.storage_root_input.setText(s.storage_root)
        self.conf_dir_input.setText(s.conf_dir)
        self.extra_args_input.setText(" ".join(s.extra_args))

    def _on_browse_game_dir(self) -> None:
        path = QFileDialog.getExistingDirectory(
            self, "选择饥荒联机版游戏目录（含 bin64\\）", "")
        if path:
            self.game_dir_input.setText(path)

    def _on_browse_storage_root(self) -> None:
        path = QFileDialog.getExistingDirectory(
            self, "选择存档根目录（含 DoNotStarveTogether\\ 的那层）", "")
        if path:
            self.storage_root_input.setText(path)

    def _on_save_settings(self) -> None:
        extra = self.extra_args_input.text().split()
        s = server.Settings(
            game_dir=self.game_dir_input.text().strip(),
            storage_root=self.storage_root_input.text().strip(),
            conf_dir=self.conf_dir_input.text().strip(),
            extra_args=extra,
        )
        server.set_settings(s)
        try:
            server.save_settings(s)
        except OSError as exc:
            self._notify("warn", f"设置保存失败：{exc}")
            return
        self._notify("info", "已保存。重新扫描或启动服务器后生效。")
        self.refresh_clusters()

    # -- 开服：启动 / 停止 ------------------------------------------------------

    def start_server(self) -> None:
        cluster = self._current_cluster()
        if cluster is None:
            return
        if self._server_thread is not None and self._server_thread.isRunning():
            return
        if self._server_manager is not None and self._server_manager.any_running():
            self._notify("warn", "服务器已在运行中")
            return
        if not cluster.has_token:
            self._notify("error", f"{cluster.name} 缺少 cluster_token.txt，无法启动")
            return

        self.server_log_view.clear()
        self.server_status_label.setText("正在启动…")
        self.btn_server_start.setEnabled(False)
        self.btn_server_stop.setEnabled(True)

        update = self.server_update_mods.isChecked()
        self._append_server_log(
            f"[INFO] 启动 {cluster.name} · {cluster.cluster_name}"
            f"（{'更新' if update else '跳过'}模组）")
        extra = self.extra_args_input.text().split()
        self._server_thread = ServerThread("start", cluster, update_mods=update,
                                           extra_args=extra)
        self._server_thread.started.connect(self._on_server_started)
        self._server_thread.failed.connect(self._on_server_failed)
        self._server_thread.finished.connect(self._on_server_thread_finished)
        self._server_timer.start()
        self._server_thread.start()

    def _on_server_started(self, manager) -> None:
        self._server_manager = manager
        self.server_status_label.setText("运行中")
        self._append_server_log("[OK] 全部分片已就绪")
        self._server_paused = None  # 新的一次运行，暂停状态未知
        self._pause_capture_at = None
        self._player_capture_after = None  # 引擎时钟归零，旧时间戳基线作废
        self._refresh_console_row()
        self._on_player_autorefresh_manage()
        self._refresh_server_join_command()

    def _on_server_failed(self, tb: str) -> None:
        self.server_status_label.setText("启动失败")
        self.btn_server_start.setEnabled(True)
        self.btn_server_stop.setEnabled(False)
        self._append_server_log(f"[FAIL] {tb}")
        self._notify("error", "服务器启动失败，详见日志")

    def _on_server_thread_finished(self) -> None:
        if self._server_manager is None or not self._server_manager.any_running():
            self.btn_server_start.setEnabled(True)
            self.btn_server_stop.setEnabled(False)
        self._refresh_console_row()

    def stop_server(self) -> None:
        if self._server_manager is None:
            return
        attached = getattr(self._server_manager, "attached", False)
        self._append_server_log(
            "[INFO] 正在停止服务器…" + ("（接管的外部进程）" if attached else ""))
        self._server_manager.stop_all()
        self._server_manager = None
        self._attached_pending = None
        self._server_timer.stop()
        self._server_paused = None  # 新的一次运行，暂停状态未知
        self._pause_capture_at = None
        pause_btn = self.quick_cmd_buttons.get("pause")
        if pause_btn is not None:
            pause_btn.setText("暂停世界")
        self.server_status_label.setText("已停止")
        self.btn_server_start.setEnabled(True)
        self.btn_server_attach.setEnabled(False)
        self.btn_server_stop.setEnabled(False)
        self._append_server_log("[OK] 已停止")
        self._refresh_console_row()
        self._on_player_autorefresh_manage()
        self._refresh_server_join_command()

    # -- 开服：服务器控制台 -----------------------------------------------------

    def _refresh_console_row(self) -> None:
        """按当前 manager 形态更新控制台行（分片下拉 + 执行按钮）。

        - 本工具启动的：分片下拉列出全部运行中的分片，按钮可用；
        - 接管的外部进程：stdin 不在手里，按钮禁用并说明原因；
        - 没有服务器：占位提示。
        """
        manager = self._server_manager
        self.server_cmd_target.blockSignals(True)
        self.server_cmd_target.clear()
        console_ready = False
        if manager is None:
            self.server_cmd_target.addItem("未运行", "")
            self.server_cmd_input.setPlaceholderText(
                "服务器控制台：启动服务器后可在此输入 Lua 指令，如 c_listallplayers()")
        elif getattr(manager, "attached", False):
            self.server_cmd_target.addItem("外部进程", "")
            self.server_cmd_input.setPlaceholderText(
                "接管的外部服务器无法接收指令（stdin 不在本工具手里）")
        else:
            for s in manager.status():
                if s["running"]:
                    mark = "★ " if s["is_master"] else ""
                    self.server_cmd_target.addItem(f"{mark}{s['shard']}", s["shard"])
            console_ready = self.server_cmd_target.count() > 0
            if not console_ready:
                self.server_cmd_target.addItem("未运行", "")
            self.server_cmd_input.setPlaceholderText(
                "服务器控制台：输入 Lua 指令回车执行，如 c_listallplayers()")
        self.server_cmd_target.blockSignals(False)
        self.btn_server_cmd_send.setEnabled(console_ready)
        self.server_cmd_input.setEnabled(console_ready)
        for btn in self.quick_cmd_buttons.values():
            btn.setEnabled(console_ready)

    def _send_console_command(self, command: str, *, note: str = "") -> bool:
        """把一条 Lua 指令写进所选分片的 stdin。返回是否成功。"""
        manager = self._server_manager
        if manager is None:
            self._append_server_log("[WARN] 服务器未运行，没有可接收指令的进程")
            return False
        command = command.strip()
        if not command:
            self._append_server_log("[WARN] 指令为空")
            return False
        ok, msg = manager.send_command(command, self.server_cmd_target.currentData() or "")
        self._append_server_log(("[OK] " if ok else "[WARN] ") + msg)
        if ok:
            self._append_server_log(
                "[INFO] 指令已送入 stdin；服务器不回显输入，"
                + (f"{note}，" if note else "") + "稍候在下面日志里看执行结果")
        return ok

    def send_server_command(self) -> None:
        """把输入框里的 Lua 指令写进所选分片的 stdin。"""
        command = self.server_cmd_input.text().strip()
        if not command:
            self._append_server_log("[WARN] 指令为空")
            return
        if self._send_console_command(command):
            self.server_cmd_input.clear()

    def run_quick_command(self, key: str) -> None:
        """一键执行常用指令。破坏性的（回档）先弹确认。"""
        entry = next((q for q in self.QUICK_COMMANDS if q[0] == key), None)
        if entry is None:
            return
        _, label, _tip = entry

        command = {
            "save": "c_save()",
            "rollback": "c_rollback(1)",
            "pause": server.SIM_TIMESCALE_PROBE_TEMPLATE,
        }[key]

        if key == "pause":
            # 🔴 专用服务器的暂停 = 时间刻度 0（TheNet:SetServerPaused 只切
            # 客户端暂停菜单语义，世界照跑——2026-09-23 用户实测无效）。
            # 点按发的是「目标动作」：当前没暂停 → 发 SetTimeScale(0) 去暂停；
            # 已暂停 → 发 (1) 去恢复。（首版按当前状态发，正好发反，
            # 点一下等于保持现状——用户实测两连点都发 (1) 无效果。）
            # 未知 → 单表达式取反（两条语句挤一行会是 Lua 语法错误）。
            # 每次都带打点：暂停时 stdin 控制台仍处理指令，回显能自证生效。
            paused = self._server_paused
            toggle = (server.PAUSE_TOGGLE_CMD
                      if paused is None else
                      (server.PAUSE_OFF_CMD if paused else server.PAUSE_ON_CMD))
            self._send_console_command(f"{toggle} {server.SIM_TIMESCALE_PROBE_TEMPLATE}")
            self._pause_capture_at = self._last_engine_ts()
            self._append_server_log(
                "[INFO] 已发送暂停/继续指令（TheSim:SetTimeScale），"
                "等服务器回显当前时间刻度…")
            return
        # 破坏性操作先确认；离屏（自动化测试）不能弹模态框，直接放行
        if key == "rollback" and not _is_offscreen():
            answer = QMessageBox.question(
                self,
                config.APP_NAME,
                f"确定要「{label}」吗？\n\n"
                "回滚到上一个存档点（丢失最近进度，玩家会被断开）。\n\n"
                f"将对分片「{self.server_cmd_target.currentText()}」执行 {command}",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                self._append_server_log(f"[INFO] 已取消：{label}")
                return

        self._send_console_command(command)

    # -- 开服：玩家管理（在线列表 / 踢 / 拉黑） -----------------------------------

    def refresh_players(self) -> None:
        """刷新在线玩家：发 c_listallplayers()，让日志泵解析回显。"""
        if self._server_manager is None:
            self._append_server_log("[WARN] 服务器未运行，先启动再刷新玩家列表")
            return
        # 记下发指令时的基线：只认**这之后**的回显。
        # 🔴 基线必须是引擎时间戳（_chunk_fresh 按秒比较），不能是日志字符数
        # ——首版只改了消费端、这里还记长度（几万）＞时间戳（几百秒），
        # 所有回显被判成历史行，列表永远不更新（2026-09-23 用户实测）。
        self._player_capture_after = self._last_engine_ts()
        self._send_console_command("c_listallplayers()")

    def _last_engine_ts(self) -> int | None:
        """日志视图里最后一条引擎时间戳（发指令时刻的基线）。"""
        ts = None
        for line in self.server_log_view.toPlainText().splitlines():
            value = server.engine_timestamp(line)
            if value is not None:
                ts = value
        return ts

    def _chunk_fresh(self, chunk: str, baseline: int | None) -> bool:
        """这批日志增量是否发生在基线之后。

        🔴 不能用日志文本长度当基线：日志视图有 ``setMaximumBlockCount``，
        长会话下旧块被驱逐、``toPlainText()`` 长度不增反缩，「新回显」会被
        误判成历史行而丢弃（2026-09-23 用户实测玩家列表/暂停回显全部失灵
        的根因）。引擎行自带 ``[HH:MM:SS]`` 时间戳，用它判断先后。
        """
        if baseline is None:
            return True
        for line in chunk.splitlines():
            ts = server.engine_timestamp(line)
            if ts is not None and ts >= baseline:
                return True
        return False

    def _maybe_capture_players(self, chunk: str) -> None:
        """日志泵增量里出现玩家行时填表（只认发出刷新指令之后新增的日志）。"""
        if self._player_capture_after is None:
            return
        players = parse_player_lines(chunk)
        if not players:
            return
        if not self._chunk_fresh(chunk, self._player_capture_after):
            # 这批行是发出刷新指令**之前**就在日志里的（历史回显），不认。
            return
        self._player_capture_after = None
        self._populate_player_table(players)

    def _maybe_apply_pause_probe(self, chunk: str) -> None:
        """日志泵增量里出现暂停线索时校准「暂停世界」按钮。

        线索两种：打点回显 DSTIPJ_SIM_TS=（权威），引擎行 Sim paused/unpaused
        （pause_when_empty 自动暂停也会打）。只认发出指令**之后**的新增日志
        （引擎时间戳基线），解析出值才更新状态与文案。
        """
        value = server.parse_pause_state(chunk)
        if value is None:
            return
        if not self._chunk_fresh(chunk, self._pause_capture_at):
            return
        self._pause_capture_at = None
        self._server_paused = value
        btn = self.quick_cmd_buttons.get("pause")
        if btn is not None:
            btn.setText("继续世界" if value else "暂停世界")
        self._append_server_log(
            "[OK] 服务器当前" + ("已暂停（点「继续世界」恢复）" if value else "运行中（未暂停）"))

    def _populate_player_table(self, players: list[dict]) -> None:
        self.player_table.setRowCount(0)
        self.player_table.setRowCount(len(players))
        for row, p in enumerate(players):
            for col, key in enumerate(("name", "prefab", "userid")):
                item = QTableWidgetItem(str(p[key]))
                if key == "userid":
                    item.setData(Qt.ItemDataRole.UserRole, p["userid"])
                self.player_table.setItem(row, col, item)
        self.player_table.resizeColumnsToContents()
        self.player_hint_label.setText(f"在线 {len(players)} 人；选中后可踢出或拉黑。")
        self._on_player_selection_changed()

    def _selected_player(self) -> dict | None:
        # 用 selectedItems 而不是 currentRow：QTableView 的 currentRow 与选中
        # 状态是两套，删行后 currentRow 可能变 -1，导致明明选中了却取不到。
        items = self.player_table.selectedItems()
        if not items:
            return None
        row = items[0].row()

        def col(c: int) -> str:
            item = self.player_table.item(row, c)
            return item.text() if item is not None else ""
        return {"name": col(0), "prefab": col(1), "userid": col(2)}

    def _on_player_selection_changed(self) -> None:
        ok = self._selected_player() is not None
        self.btn_player_kick.setEnabled(ok)
        self.btn_player_ban.setEnabled(ok)

    def _on_player_autorefresh_toggled(self, checked: bool) -> None:
        if checked:
            self.refresh_players()
            self._player_timer.start()
        else:
            self._player_timer.stop()

    def _player_timer_tick(self) -> None:
        if self._server_manager is None or not self._server_manager.any_running():
            self._player_timer.stop()
            self.player_autorefresh.setChecked(False)
            return
        self.refresh_players()

    def player_kick_ban(self, *, kick: bool) -> None:
        """踢出（TheNet:Kick）或拉黑（写 blocklist.txt + 踢）选中玩家。"""
        player = self._selected_player()
        if player is None:
            self._append_server_log("[WARN] 先在列表里选中一个玩家")
            return
        manager = self._server_manager
        if manager is None:
            self._append_server_log("[WARN] 服务器未运行")
            return
        userid, name = player["userid"], player["name"]
        action = "踢出" if kick else "拉黑（写入 blocklist.txt）"

        if not _is_offscreen():
            answer = QMessageBox.question(
                self, config.APP_NAME,
                f"确定要{action}玩家 {name}（{userid}）吗？"
                + ("" if kick else "\n\n拉黑后会写入存档的 blocklist.txt，重启服务器仍生效。"),
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                self._append_server_log(f"[INFO] 已取消{action} {name}")
                return

        if not kick:
            cluster = self._current_cluster()
            if cluster is None:
                self._append_server_log("[WARN] 拉黑需要知道当前存档，但没有选中存档")
                return
            ok, msg = server.add_blocklist_userid(cluster, userid)
            self._append_server_log(("[OK] " if ok else "[WARN] ") +
                                    f"blocklist.txt: {msg}")

        # ⚠️ 必须是**单条语句**。曾经写成「local u=... or ... TheNet:Kick(u)」，
        # 两条语句挤一行没有分隔符 → Lua 语法错误 → 指令根本没执行，
        # 玩家没被踢、下次刷新又回到列表里（stdin 写入成功不代表执行成功）。
        command = f'TheNet:Kick(UserToClientID("{userid}") or "{userid}")'
        ok, msg = manager.send_command(command, self.server_cmd_target.currentData() or "")
        self._append_server_log(("[OK] " if ok else "[WARN] ") + msg)
        if ok:
            self._append_server_log(f"[INFO] 已{action} {name}；列表稍后自动刷新")
            # 把人从表里移除，避免误以为还在线
            sel = self.player_table.selectedItems()
            if sel:
                self.player_table.removeRow(sel[0].row())
            self._on_player_selection_changed()

    def _on_player_autorefresh_manage(self) -> None:
        """服务器启停/接管时同步玩家管理行的可用状态。"""
        manager = self._server_manager
        ready = (manager is not None and manager.any_running()
                 and not getattr(manager, "attached", False))
        self.btn_player_refresh.setEnabled(ready)
        self.player_autorefresh.setEnabled(ready)
        if not ready:
            self._player_timer.stop()
            self.player_autorefresh.setChecked(False)
            self.player_table.setRowCount(0)
            self.btn_player_kick.setEnabled(False)
            self.btn_player_ban.setEnabled(False)
            self.player_hint_label.setText(
                "接管的外部服务器拿不到 stdin，无法刷新在线列表；"
                if manager is not None else
                "服务器未运行时不可用；启动后点「刷新列表」或勾选自动刷新。")

    def _pump_server_logs(self) -> None:
        manager = getattr(self, "_server_manager", None)
        if manager is None:
            return
        chunk = manager.pump_logs()
        if chunk:
            self.server_log_view.appendPlainText(chunk)
            self._maybe_capture_players(chunk)
            self._maybe_apply_pause_probe(chunk)
        # 刷新分片状态行
        parts = []
        for s in manager.status():
            state = "运行中" if s["running"] else "已停止"
            if s["running"]:
                state = "就绪" if s["ready"] else "启动中"
            mark = "★" if s["is_master"] else " "
            parts.append(f"{mark}{s['shard']} :{s['port']} · {state}")
        self.server_shards_label.setText("　".join(parts))

    def _append_server_log(self, text: str) -> None:
        for line in text.splitlines():
            self.server_log_view.appendPlainText(line)

    def _build_statusbar(self, parent: QVBoxLayout) -> None:
        row = QHBoxLayout()
        parent.addLayout(row)

        self.status_label = QLabel("就绪", objectName="statusLabel")
        row.addWidget(self.status_label)
        row.addStretch(1)

        self.progress = QProgressBar()
        self.progress.setRange(0, 0)  # 无限滚动
        self.progress.setFixedWidth(160)
        self.progress.setVisible(False)
        row.addWidget(self.progress)

    # ------------------------------------------------------------------
    # 状态刷新（只在主线程）
    # ------------------------------------------------------------------
    def _add_check(self, item: diagnostics.CheckItem) -> None:
        icon_text, color = LEVEL_STYLE.get(item.level, ("i", "#57606a"))

        row_widget = QWidget()
        row = QHBoxLayout(row_widget)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(8)

        icon = QLabel(icon_text, objectName="checkIcon")
        icon.setStyleSheet(f"color: {color};")
        icon.setFixedWidth(16)
        icon.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignHCenter)
        row.addWidget(icon)

        text_col = QVBoxLayout()
        text_col.setSpacing(1)
        title = QLabel(item.title, objectName="checkTitle")
        text_col.addWidget(title)
        if item.detail:
            detail = QLabel(item.detail, objectName="checkDetail")
            detail.setWordWrap(True)
            text_col.addWidget(detail)
        row.addLayout(text_col, stretch=1)

        # 插在底部 stretch 之前
        self.checks_layout.insertWidget(self.checks_layout.count() - 1, row_widget)

    def _clear_checks(self) -> None:
        while self.checks_layout.count() > 1:  # 保留末尾 stretch
            item = self.checks_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()

    def _show_idle_state(self) -> None:
        """启动后、用户点击检测之前的初始界面（不做任何网络/系统动作）。"""
        self._clear_checks()
        hint = QLabel(
            "尚未检测。\n\n点右侧「开始检测并配置」按钮开始。",
            objectName="checkDetail",
        )
        hint.setWordWrap(True)
        self.checks_layout.insertWidget(self.checks_layout.count() - 1, hint)
        self.address_view.setText("尚未检测")
        self.command_view.clear()
        self.command_view.setPlaceholderText("控制台指令：尚未检测")
        self.btn_copy_share.setEnabled(False)
        self._set_status("就绪，等待开始检测")

    def _append_log(self, message: str) -> None:
        match = LEVEL_LINE_RE.match(message)
        color = LOG_COLORS.get(match.group(1), "#24292f") if match else "#24292f"
        if not message:
            self.log_view.appendPlainText("")
            return
        escaped = (
            message.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        )
        self.log_view.appendHtml(f'<span style="color:{color}">{escaped}</span>')

    def _set_status(self, text: str) -> None:
        self.status_label.setText(text)

    def _set_running(self, running: bool) -> None:
        for btn in (self.btn_run, self.btn_cleanup, self.btn_elevate):
            btn.setEnabled(not running)
        self.progress.setVisible(running)

    # ------------------------------------------------------------------
    # 中继
    # ------------------------------------------------------------------
    # ------------------------------------------------------------------
    # 中继：就绪检测 / 角色 / 码
    # ------------------------------------------------------------------
    def _on_tab_changed(self, index: int) -> None:
        """切到「UDP 中继」页时才跑就绪自检，避免启动即碰网络。"""
        if index == self._relay_tab_index and not self._relay_checked_once:
            self._relay_checked_once = True
            self.refresh_relay_readiness()

    def refresh_relay_readiness(self) -> None:
        """在后台线程跑就绪自检（netsh + 自环探测是阻塞 IO）。"""
        if _is_offscreen():
            # 离屏（自动化测试）下不去碰 netsh / 网络探测：既拖慢测试，
            # 又容易让 QThread 在窗口销毁时仍在运行（仓库里记录过的坑）。
            self.relay_ready_view.setPlainText("（离屏模式跳过自检）")
            self._relay_ready = True
            return
        if self._readiness_thread is not None and self._readiness_thread.isRunning():
            return
        role = "host" if self.rb_host.isChecked() else "join"
        self.relay_ready_view.setPlainText("检测中…")
        thread = ReadinessThread(
            role,
            session=self._session,
            entries=relay.load_join_codes(),
        )
        thread.done.connect(self._on_readiness_done)
        thread.finished.connect(self._on_readiness_finished)
        self._readiness_thread = thread
        thread.start()

    def _on_readiness_finished(self) -> None:
        self._readiness_thread = None

    def _on_readiness_done(self, results: list) -> None:
        lines = []
        self._relay_ready = True
        for ok, level, msg in results:
            mark = {"ok": "✓", "warn": "!", "fail": "×"}[level]
            lines.append(f"{mark} {msg}")
            if level == "fail":
                self._relay_ready = False
        self.relay_ready_view.setPlainText("\n".join(lines))
        if self.rb_host.isChecked():
            self._refresh_host_code()

    def _on_role_changed(self) -> None:
        is_host = self.rb_host.isChecked()
        self.host_panel.setVisible(is_host)
        self.join_panel.setVisible(not is_host)
        self.refresh_relay_readiness()
        if not is_host:
            # 切到加入方时，若主机码输入框已有内容，立刻解析一遍
            self._on_host_code_changed()

    # ---- 主机码 ----
    def _refresh_host_code(self) -> None:
        ports = relay.detect_dst_ports()
        globals_v6 = relay.global_ipv6_addresses()
        v4, _ = relay.list_local_addresses()
        addresses = globals_v6 + v4
        if not ports or not addresses:
            self.host_code_view.clear()
            self.btn_host_code_copy.setEnabled(False)
            self.host_status_label.setText(
                "需要：有公网地址 + 已开世界（识别到监听端口）"
            )
            return
        if not self._session:
            self._session = relay.make_session_token()
        # 主世界端口必须写进主机码：加入方看端口列表无法分辨哪个是主世界。
        # DST 默认主世界 10999、洞穴 10998，若按最小端口取会拿到洞穴，
        # 而客户端是连不进洞穴分片的。
        master = config.pick_master_port(ports)
        code = relay.encode_host_code(
            addresses, relay.DEFAULT_RELAY_BASE, sorted(ports), master, self._session
        )
        self.host_code_view.setText(code)
        self.btn_host_code_copy.setEnabled(True)
        self.host_status_label.setText(
            f"中继端口 {relay.DEFAULT_RELAY_BASE} 起，共 {len(ports)} 条映射；"
            f"主世界 {master}；校验 {self._session}"
        )

    def regen_host_code(self) -> None:
        self._session = relay.make_session_token()
        self._refresh_host_code()
        self._append_relay_log("[INFO] 已更换校验值，旧的加入码将作废")
        self._sync_host_allow()

    def copy_host_code(self) -> None:
        self._copy_code(self.host_code_view.text(), "主机码")

    # ---- 加入码管理（主机端）----
    def _sync_host_allow(self) -> None:
        """把当前加入码状态热更新到运行中的中继（不用重启）。

        四个入口共用：添加 / 启停勾选 / 删除加入码、更换校验值。
        主机端的多条规则共用**同一个** ``AddressAllowList`` 实例，
        整体替换一次即可同时作用于所有端口。
        """
        thread = self.relay_thread
        if thread is None or not thread.isRunning() or thread.relay is None:
            return
        allow = (thread.relay.rules[0].allow if thread.relay.rules else None)
        if allow is None:
            return
        entries = relay.allow_entries_from_codes(
            relay.load_join_codes(), self._session
        )
        allow.set_entries(entries, closed=not entries)
        if entries:
            shown = "、".join(entries[:3]) + ("…" if len(entries) > 3 else "")
            self._append_relay_log(
                f"[OK  ] 白名单已更新（立即生效）：{len(entries)} 个地址（{shown}）")
        else:
            self._append_relay_log(
                "[INFO] 白名单已清空：所有外部加入将被拒绝，添加加入码后立即放行")

    def _reload_join_list(self) -> None:
        while self.join_list_layout.count():
            item = self.join_list_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
        entries = relay.load_join_codes()
        if not entries:
            hint = QLabel("（还没有加入码；可以先启动中继，添加后立即生效）",
                          objectName="checkDetail")
            hint.setWordWrap(True)
            self.join_list_layout.addWidget(hint)
            return
        for index, item in enumerate(entries):
            self._add_join_row(index, item)

    def _add_join_row(self, index: int, item: dict) -> None:
        row_widget = QWidget()
        row = QHBoxLayout(row_widget)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(6)

        enabled = QCheckBox()
        enabled.setChecked(bool(item.get("enabled", True)))
        enabled.setToolTip("勾选 = 允许该加入方连入")
        enabled.toggled.connect(
            lambda checked, i=index: self._toggle_join(i, checked)
        )
        row.addWidget(enabled)

        addrs = "、".join(item.get("addresses", []))
        note = item.get("note", "")
        session = item.get("session", "")
        label_text = (f"{note}  " if note else "") + addrs
        if session and session != self._session:
            label_text += "  （校验不符，不生效）"
        label = QLabel(label_text, objectName="checkDetail")
        label.setWordWrap(True)
        row.addWidget(label, stretch=1)

        btn_del = QPushButton("删除", objectName="danger")
        btn_del.setFixedWidth(56)
        btn_del.clicked.connect(lambda _c=False, i=index: self._delete_join(i))
        row.addWidget(btn_del)
        self.join_list_layout.addWidget(row_widget)

    def add_join_code(self) -> None:
        text = self.join_code_input.text().strip()
        if not text:
            self._notify("info", "先粘贴加入方发来的 JOIN… 码")
            return
        try:
            info = relay.decode_join_code(text)
        except ValueError as exc:
            self._notify("warn", str(exc))
            return
        entries = relay.load_join_codes()
        # 同地址 + 同校验视为重复
        for item in entries:
            if (item.get("addresses") == info["addresses"]
                    and item.get("session") == info["session"]):
                self._notify("info", "这个加入码已经在列表里")
                return
        entries.append({
            "addresses": info["addresses"],
            "session": info["session"],
            "note": self.join_note_input.text().strip(),
            "enabled": True,
        })
        relay.save_join_codes(entries)
        self.join_code_input.clear()
        self.join_note_input.clear()
        self._reload_join_list()
        warn = ""
        if self._session and info["session"] != self._session:
            warn = "\n注意：该加入码的校验与当前主机码不一致，不会生效（请朋友用最新主机码重新生成加入码）"
        self._append_relay_log(
            f"[OK  ] 已添加加入码：{'、'.join(info['addresses'])}{warn}"
        )
        if warn:
            self._notify("warn", warn.strip())
        self._sync_host_allow()

    def _toggle_join(self, index: int, enabled: bool) -> None:
        entries = relay.load_join_codes()
        if 0 <= index < len(entries):
            entries[index]["enabled"] = bool(enabled)
            relay.save_join_codes(entries)
            self._reload_join_list()
            self._sync_host_allow()

    def _delete_join(self, index: int) -> None:
        entries = relay.load_join_codes()
        if 0 <= index < len(entries):
            removed = entries.pop(index)
            relay.save_join_codes(entries)
            self._reload_join_list()
            self._append_relay_log(
                f"[INFO] 已删除加入码：{'、'.join(removed.get('addresses', []))}"
            )
            self._sync_host_allow()

    # ---- 启动 / 停止 ----
    def probe_host(self) -> None:
        """探测到主机的连通性（不依赖中继是否已启动）。"""
        info = self._host_info
        if info is None:
            text = self.host_code_input.text().strip()
            if not text:
                self._notify("warn", "请先粘贴主机发来的 HOST… 码。")
                return
            try:
                info = relay.decode_host_code(text)
            except ValueError as exc:
                self._notify("warn", str(exc))
                return
            self._host_info = info

        self._append_relay_log("[INFO] 开始连通性测试（向主机中继端口发探测包）…")
        try:
            results = relay.probe_host_info(info, timeout=1.5)
        except OSError as exc:
            self._append_relay_log(f"[FAIL] 探测出错：{exc}")
            return
        if not results:
            self._append_relay_log("[WARN] 主机码里没有可探测的地址或端口")
            return
        for line in relay.describe_probe(results):
            self._append_relay_log(line)

        statuses = {r["status"] for r in results}
        if "ok" in statuses:
            self._append_relay_log("[OK  ] 主机可达，可以启动中继进游戏。")
            self.join_status_label.setText("连通性：通")
        elif "denied" in statuses:
            self._append_relay_log(
                "[WARN] 包能到主机，但被白名单拒绝 —— "
                "把你的加入码重新发给主机添加后再试。")
            self.join_status_label.setText("连通性：被白名单拒绝")
        else:
            self._append_relay_log(
                "[FAIL] 主机无响应。常见原因：主机中继没启动；"
                "主机 Windows 防火墙未放行中继端口；主机路由器/光猫的"
                "IPv6 防火墙拦了入站；或主机码里的地址已失效。")
            self.join_status_label.setText("连通性：不通（包到不了主机）")

    def apply_and_start(self) -> None:
        if self.rb_host.isChecked():
            rules, error = self._build_host_rules()
        else:
            rules, error = self._build_join_rules()
        if rules is None:
            self._notify("warn", error)
            return

        # 先清空日志，再放行防火墙 —— 否则 _auto_firewall 写的
        # [OK]/[WARN] 结果会被后面的 clear() 抹掉，用户根本看不到到底放行成没成功。
        self.relay_log_view.clear()

        # 主机端：自动放行防火墙（需管理员，失败仅提示）
        if self.rb_host.isChecked():
            self._auto_firewall(rules)

        # 若已在运行则先停（确认生效 = 重启）
        thread = self.relay_thread
        if thread is not None and thread.isRunning():
            thread.stop()
            thread.wait(3000)

        self._append_relay_log(f"[INFO] 启动 {len(rules)} 条转发规则")
        for rule in rules:
            self._append_relay_log(
                f"[INFO] {rule.listen_text_full}  <->  {rule.target_text_full}"
                f"（白名单：{rule.allow.describe()}）"
            )

        new_thread = RelayThread(rules)
        new_thread.log.connect(self._append_relay_log)
        new_thread.event.connect(self._on_relay_event)
        new_thread.failed.connect(self._on_relay_failed)
        new_thread.finished.connect(self._on_relay_finished)
        self.relay_thread = new_thread
        new_thread.start()

        self._set_relay_running(True)
        self._relay_timer.start()
        self._after_relay_started()

    def _build_host_rules(self):
        ports = relay.detect_dst_ports()
        if not ports:
            return None, "未识别到饥荒监听端口。请先在游戏里开好世界，再点「重新检测」。"
        entries = relay.allow_entries_from_codes(
            relay.load_join_codes(), self._session
        )
        # 空白名单不再阻拦启动：先用「拒绝所有人」守门（端口/防火墙/探测都正常，
        # 只是外部加入会被拒）。添加加入码后由 _sync_host_allow 即时放行，
        # 不用重启中继。
        allow = relay.AddressAllowList(entries, closed=not entries)
        rules = []
        for i, port in enumerate(sorted(ports)):
            rules.append(relay.ForwardRule(
                relay.format_endpoint("::", relay.DEFAULT_RELAY_BASE + i),
                relay.format_endpoint("127.0.0.1", port),
                allow=allow,
            ))
        return rules, ""

    def _build_join_rules(self):
        text = self.host_code_input.text().strip()
        if not text:
            return None, "请先粘贴主机发来的 HOST… 码。"
        try:
            info = relay.decode_host_code(text)
        except ValueError as exc:
            return None, str(exc)
        self._host_info = info
        rules = []
        for listen, target in relay.build_guest_rules(info):
            try:
                rules.append(relay.ForwardRule(listen, target))
            except OSError as exc:
                return None, f"绑定失败：{exc}"
        # 记住校验值，用于生成加入码
        self._session = info["session"]
        self._refresh_join_code()
        return rules, ""

    def _auto_firewall(self, rules) -> None:
        for rule in rules:
            port = rule._configured_listen_port or rule.actual_listen_endpoint()[1]
            ok, msg = firewall.add_udp_rule(port)
            self._append_relay_log(
                ("[OK  ] " if ok else "[WARN] ") + f"防火墙 UDP {port}：{msg}"
            )

    def _after_relay_started(self) -> None:
        if self.rb_host.isChecked():
            # 主机端：空白名单也能先启动（closed 守门）；这里把当前状态说清楚
            thread = self.relay_thread
            allow = (thread.relay.rules[0].allow
                     if thread is not None and thread.relay is not None
                     and thread.relay.rules else None)
            if allow is not None and allow.is_closed:
                self._append_relay_log(
                    "[INFO] 还没有生效的加入码：中继已启动，所有外部加入会被拒绝；"
                    "添加加入码后**立即生效**（无需重启中继）")
            return
        if not self._host_info:
            return
        # 加入方：生成游戏内连接指令。
        # 必须连**主世界**端口（主机在主机码里告知），不能取最小端口 ——
        # DST 默认主世界 10999、洞穴 10998，连洞穴端口进不去。
        master = self._host_info["master_port"]
        cmd = config.join_command("127.0.0.1", master)
        self.join_cmd_view.setText(cmd)
        self.btn_join_cmd_copy.setEnabled(True)
        local_ports = "、".join(
            str(g) for _, g in sorted(self._host_info["maps"], key=lambda m: m[1])
        )
        self.join_status_label.setText(
            f"已连接主机的 {len(self._host_info['maps'])} 条映射"
            f"（本地监听 {local_ports}，主世界 {master}）；"
            "在饥荒控制台粘贴上面指令即可加入"
        )

    def stop_relay(self) -> None:
        thread = self.relay_thread
        if thread is None:
            return
        self._append_relay_log("[INFO] 正在停止……")
        thread.stop()
        if not thread.wait(3000):
            self._append_relay_log("[WARN] 等待中继线程退出超时")

    def _set_relay_running(self, running: bool) -> None:
        self.btn_join_apply.setEnabled(not running)
        self.btn_host_stop.setEnabled(running)
        self.btn_join_start.setEnabled(not running)
        self.btn_join_stop.setEnabled(running)
        if not running:
            self._relay_timer.stop()

    def _on_relay_finished(self) -> None:
        self._set_relay_running(False)
        self._append_relay_log("[INFO] 中继已停止")
        self.relay_thread = None
        self._refresh_relay_stats()

    def _on_relay_failed(self, detail: str) -> None:
        self._append_relay_log("[FAIL] 中继运行出错：")
        for line in detail.rstrip().splitlines():
            self._append_relay_log("    " + line)

    def _on_relay_event(self, kind: str, payload: object) -> None:
        if not isinstance(payload, dict):
            return
        target = (self.host_status_label if self.rb_host.isChecked()
                  else self.join_status_label)
        if kind == "connect":
            remote = payload.get("remote", "?")
            bound = payload.get("bound_ip", "")
            suffix = f"（本机 {bound}）" if bound else ""
            target.setText(f"已连入 {payload.get('peers', 0)} 路：{remote}{suffix}")
        elif kind == "drop":
            target.setText(
                f"断开 {payload.get('remote', '?')}，当前 {payload.get('peers', 0)} 路")
        elif kind == "reject":
            target.setText(
                f"白名单拦截 {payload.get('remote', '?')}（累计 {payload.get('count', 0)}）")
        elif kind == "busy":
            target.setText(
                f"已达最大并发，忽略 {payload.get('remote', '?')}")

    def apply_host_rules(self) -> None:
        """主机端「确认生效并启动中继」按钮。

        未启动：走原启动流程（绑定端口、放行防火墙并启动中继）；
        已启动：不重启，只把当前加入码白名单热更新进去。
        回归（2026-09-24）：此前主机端无条件只做热更新，而中继还没启动时
        ``_sync_host_allow`` 发现线程为空会静默返回，按钮点了毫无反应。
        """
        thread = self.relay_thread
        if (self.rb_host.isChecked()
                and thread is not None and thread.isRunning()):
            self._sync_host_allow()
            return
        self.apply_and_start()

    def _append_relay_log(self, message: str) -> None:
        if not message:
            self.relay_log_view.appendPlainText("")
            return
        match = LEVEL_LINE_RE.match(message)
        color = LOG_COLORS.get(match.group(1), "#24292f") if match else "#24292f"
        escaped = (
            message.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        )
        self.relay_log_view.appendHtml(f'<span style="color:{color}">{escaped}</span>')

    def _refresh_relay_stats(self) -> None:
        thread = self.relay_thread
        if thread is None:
            self.relay_stats_label.setText("—")
            return
        snap = thread.snapshot()
        rules = snap.get("rules", [])
        if not rules:
            self.relay_stats_label.setText("—")
            return
        lines = [f"已运行 {snap.get('uptime', 0)} 秒"]
        for rule in rules:
            lines.append(
                f"{rule['listen']} -> {rule['target']}：peer {rule['peer_count']}，"
                f"上行 {rule['to_game_packets']}，下行 {rule['to_remote_packets']}"
                + (f"，拒收 {rule['dropped_untrusted']}" if rule.get("dropped_untrusted") else "")
            )
        self.relay_stats_label.setText("\n".join(lines))

    # ---- 加入方：加入码 / 指令 ----
    def _on_host_code_changed(self, *_args) -> None:
        """主机码一粘贴就解析，立刻生成加入码（不用等启动）。"""
        text = self.host_code_input.text().strip()
        if not text:
            self._host_info = None
            self.host_parse_label.setText("")
            self.join_code_view.clear()
            self.btn_join_code_copy.setEnabled(False)
            return
        try:
            info = relay.decode_host_code(text)
        except ValueError as exc:
            self._host_info = None
            self.host_parse_label.setText(f"× {exc}")
            self.join_code_view.clear()
            self.btn_join_code_copy.setEnabled(False)
            return
        self._host_info = info
        self._session = info["session"]
        addr0 = info["addresses"][0]
        self.host_parse_label.setText(
            f"✓ 已识别 {len(info['maps'])} 条端口映射，校验 {info['session']}；\n"
            f"主机地址 {addr0}"
        )
        self._refresh_join_code()

    def _refresh_join_code(self) -> None:
        globals_v6 = relay.global_ipv6_addresses()
        v4, _ = relay.list_local_addresses()
        addresses = globals_v6 + v4
        if not addresses or not self._session:
            self.join_code_view.clear()
            self.btn_join_code_copy.setEnabled(False)
            return
        code = relay.encode_join_code(addresses, self._session)
        self.join_code_view.setText(code)
        self.btn_join_code_copy.setEnabled(True)

    def copy_join_code(self) -> None:
        self._copy_code(self.join_code_view.text(), "加入码")

    def copy_join_cmd(self) -> None:
        self._copy_code(self.join_cmd_view.text(), "连接指令")

    def _copy_code(self, text: str, what: str) -> None:
        text = (text or "").strip()
        if not text:
            QMessageBox.information(self, config.APP_NAME, f"还没有可复制的{what}")
            return
        if winproc.set_clipboard_text(text):
            self._set_status(f"{what}已复制")
            self._append_relay_log(f"[OK  ] {what}已复制")
        else:
            QMessageBox.warning(self, config.APP_NAME, "写入剪贴板失败")

    def closeEvent(self, event) -> None:  # noqa: N802
        if self._closing:
            event.accept()
            return
        # 直连诊断 Worker 不可中断，且总时长可达十几秒；若在主线程同步 wait，
        # 窗口会卡住无响应。改为：先隐藏（用户感觉已关闭），等它结束后自动真正关闭。
        worker = self.worker
        if worker is not None and worker.isRunning():
            event.ignore()
            self.hide()
            worker.finished.connect(self.close)
            return
        # 关窗时若服务器在运行，无论本工具启动还是接管的，都先问用户怎么处理：
        # 「停止并退出 / 只退出（服务器继续跑）/ 取消」。
        manager = self._server_manager
        if manager is not None and manager.any_running():
            choice = self._ask_stop_server_on_close(
                attached=bool(getattr(manager, "attached", False)))
            if choice == "cancel":
                event.ignore()
                return
            if choice == "stop":
                manager.stop_all()
            # "leave"：只退出，服务器继续跑（下次可用「接管」重新纳入管理）
        self._closing = True
        self._relay_timer.stop()
        self._server_timer.stop()
        # readiness 自检是短任务（netsh + 一次探测），等它收尾再销毁窗口，
        # 否则会报 QThread: Destroyed while thread is still running
        readiness = self._readiness_thread
        if readiness is not None and readiness.isRunning():
            readiness.wait(4000)
            self._readiness_thread = None
        # 公网地址查询也是短任务，同样等它收尾再销毁窗口
        probe = self._public_addr_thread
        if probe is not None and probe.isRunning():
            probe.wait(9000)
            self._public_addr_thread = None
        if manager is not None:
            self._server_manager = None
        thread = self.relay_thread
        if thread is not None and thread.isRunning():
            thread.stop()
            thread.wait(3000)
        event.accept()

    def _ask_stop_server_on_close(self, *, attached: bool = False) -> str:
        """关窗前确认服务器去留。返回 "stop" / "leave" / "cancel"。

        attached=True 表示这是接管的外部服务器（用户自己起的），
        文案会明确提示「停止」会结束那个外部进程。

        离屏（自动化测试）下 QMessageBox 模态框会永久阻塞事件循环，
        所以走默认行为：停止并退出（与旧行为一致，测试可控）。
        """
        if _is_offscreen():
            return "stop"
        box = QMessageBox(self)
        box.setWindowTitle(config.APP_NAME)
        box.setIcon(QMessageBox.Icon.Question)
        if attached:
            box.setText("检测到你接管的外部专用服务器仍在运行。关闭程序时要怎么处理？")
            box.setInformativeText(
                "注意：该服务器不是本工具启动的。「停止并退出」会结束那个外部进程；"
                "「只退出」仅脱离监控，服务器继续跑。")
        else:
            box.setText("专用服务器仍在运行。关闭程序时要怎么处理？")
            box.setInformativeText(
                "「停止并退出」会先关停所有分片；"
                "「只退出」让服务器继续跑，下次打开本工具可用「接管」重新管理。")
        btn_stop = box.addButton("停止并退出", QMessageBox.ButtonRole.AcceptRole)
        btn_leave = box.addButton("只退出（服务器继续跑）", QMessageBox.ButtonRole.DestructiveRole)
        btn_cancel = box.addButton("取消", QMessageBox.ButtonRole.RejectRole)
        box.setDefaultButton(btn_stop)
        box.exec()
        clicked = box.clickedButton()
        if clicked is btn_leave:
            return "leave"
        if clicked is btn_cancel:
            return "cancel"
        return "stop"

    # ------------------------------------------------------------------
    # 动作
    # ------------------------------------------------------------------
    def start_run(self) -> None:
        if self.worker is not None and self.worker.isRunning():
            return

        ok, ports = self._parse_ports()
        if not ok:
            return

        self._clear_checks()
        self.log_view.clear()
        self._append_log(f"{config.APP_NAME} v{config.APP_VERSION} 开始检测……")
        self.address_view.setText("检测中……")
        self.command_view.clear()
        self.command_view.setPlaceholderText("控制台指令：检测中……")
        self.btn_copy_share.setEnabled(False)
        self._set_running(True)
        self._set_status("正在检测……")

        self.worker = Worker("run", ports)
        self.worker.log.connect(self._append_log)
        self.worker.check.connect(self._add_check)
        self.worker.done.connect(self._on_done)
        self.worker.error.connect(self._on_error)
        self.worker.start()

    def start_cleanup(self) -> None:
        if self.worker is not None and self.worker.isRunning():
            return

        answer = QMessageBox.question(
            self,
            config.APP_NAME,
            "将删除本工具添加的防火墙放行规则和 UPnP 端口映射，继续吗？",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return

        self._set_running(True)
        self._set_status("正在撤销配置……")

        ports = None
        if self.report and self.report.target_ports:
            ports = self.report.target_ports

        self.worker = Worker("cleanup", ports)
        self.worker.log.connect(self._append_log)
        self.worker.check.connect(self._add_check)
        self.worker.cleanup_done.connect(self._on_cleanup_done)
        self.worker.error.connect(self._on_error)
        self.worker.start()

    def elevate(self) -> None:
        answer = QMessageBox.question(
            self,
            config.APP_NAME,
            "将以管理员权限重新启动本工具（会弹出 UAC 授权框），继续吗？",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return

        result = winproc.request_admin_restart_detailed(hwnd=int(self.winId()))
        if result.started:
            QApplication.instance().quit()
            return

        # 失败原因要原样告诉用户，否则「取消或失败」根本没法排查
        if result.declined:
            QMessageBox.information(
                self,
                config.APP_NAME,
                f"{result.message}\n\n"
                "如果 UAC 授权框没弹出来，可能是被安全软件拦了；\n"
                "也可以直接右键程序选「以管理员身份运行」。",
            )
            self._append_log(f"[WARN] 提权未完成：{result.message}（错误码 {result.code}）")
        else:
            QMessageBox.warning(
                self,
                config.APP_NAME,
                f"{result.message}\n"
                f"错误码：{result.code}\n\n"
                f"启动命令：\n{result.exe}\n{result.params}\n\n"
                "可以直接右键程序选「以管理员身份运行」绕过。",
            )
            self._append_log(
                f"[FAIL] 提权失败：{result.message}（错误码 {result.code}）"
            )

    # ------------------------------------------------------------------
    # 完成回调
    # ------------------------------------------------------------------
    def _on_done(self, report: diagnostics.Report) -> None:
        self.report = report
        self._set_running(False)
        self.address_view.setText(report.primary_address or "未能确定可用地址")
        self.command_view.setText(report.connect_command)
        if not report.connect_command:
            self.command_view.setPlaceholderText("没有可用的直连指令")

        level_text = {
            diagnostics.LEVEL_OK: "配置完成",
            diagnostics.LEVEL_WARN: "需要一步手动操作",
            diagnostics.LEVEL_FAIL: "当前网络无法直连",
            diagnostics.LEVEL_INFO: "检测结束",
        }.get(report.level, "检测结束")
        self._set_status(level_text)
        self.btn_copy_share.setEnabled(True)

        self._refresh_admin_badge(report.is_admin)

        if self.autocopy.isChecked() and report.connect_command:
            self.copy_command(quiet=True)

        if report.level == diagnostics.LEVEL_FAIL:
            self._append_log("")
            self._append_log("[FAIL] 当前网络条件无法让别人通过 IP 直连")

    def _on_cleanup_done(self, messages: list[str]) -> None:
        self._set_running(False)
        self._set_status("已撤销配置")
        self._append_log("[OK  ] 撤销完成")
        QMessageBox.information(
            self,
            config.APP_NAME,
            "撤销完成：\n" + "\n".join(f"· {m}" for m in messages[:8]),
        )

    def _on_error(self, detail: str) -> None:
        self._set_running(False)
        self._set_status("出错了")
        self._append_log("")
        self._append_log("[FAIL] 检测过程中发生未预期的错误：")
        for line in detail.rstrip().splitlines():
            self._append_log("    " + line)
        QMessageBox.critical(
            self, config.APP_NAME, f"检测出错：\n{detail.splitlines()[-1]}"
        )

    # ------------------------------------------------------------------
    # 复制
    # ------------------------------------------------------------------
    def copy_command(self, quiet: bool = False) -> None:
        command = self.command_view.text().strip()
        if not command:
            if not quiet:
                QMessageBox.information(self, config.APP_NAME, "还没有可复制的指令")
            return

        if winproc.set_clipboard_text(command):
            self._set_status("指令已复制，粘贴到控制台即可")
            if not quiet:
                self._append_log(f"[OK  ] 指令已复制到剪贴板：{command}")
        elif not quiet:
            QMessageBox.warning(self, config.APP_NAME, "写入剪贴板失败，请手动选中复制")

    def copy_share_text(self) -> None:
        if not self.report or not self.report.share_text:
            QMessageBox.information(
                self, config.APP_NAME, "还没有可分享的内容，先跑一次检测"
            )
            return

        if winproc.set_clipboard_text(self.report.share_text):
            self._set_status("完整说明已复制")
            self._append_log("[OK  ] 完整说明已复制到剪贴板")
        else:
            QMessageBox.warning(self, config.APP_NAME, "写入剪贴板失败，请手动选中复制")

    # ------------------------------------------------------------------
    # 辅助
    # ------------------------------------------------------------------
    def _parse_ports(self) -> tuple[bool, list[int] | None]:
        text = self.port_input.text().strip()
        if not text:
            return True, None

        ports: list[int] = []
        for chunk in re.split(r"[,，\s]+", text):
            if not chunk:
                continue
            if not chunk.isdigit():
                QMessageBox.warning(
                    self,
                    config.APP_NAME,
                    f"端口格式不对：{chunk}\n请填数字，多个用逗号分隔",
                )
                return False, None
            port = int(chunk)
            if not (1 <= port <= 65535):
                QMessageBox.warning(self, config.APP_NAME, f"端口超出范围：{port}")
                return False, None
            ports.append(port)

        if not ports:
            return True, None
        return True, list(dict.fromkeys(ports))


def main() -> int:
    import sys

    # Qt 自己会设置 Per-Monitor V2 DPI 感知，不要提前调用
    # winproc.enable_dpi_awareness()，否则 Qt 初始化时会报「拒绝访问」警告

    app = QApplication(sys.argv)
    app.setApplicationName(config.APP_NAME)
    app.setStyleSheet(STYLE)

    # 启动即静默：不自动开始检测（检测要联网、还会改本机防火墙/UPnP 配置），
    # 等用户点「开始检测并配置」。开服页的存档扫描是纯本地只读操作，照旧自动跑。
    window = MainWindow(auto_scan=True)
    window.show()
    return app.exec()


if __name__ == "__main__":
    import sys

    sys.exit(main())
