# -*- coding: utf-8 -*-
"""PyQt6 图形界面。

布局：左侧检测项清单 + 右侧（直连地址卡片 / 操作 / 日志）。
耗时操作（网络探测、UPnP、netsh）放在 QThread 后台线程，
通过信号回主线程刷新界面。
"""

from __future__ import annotations

import re
import traceback

from PyQt6.QtCore import Qt, QThread, QTimer, pyqtSignal
from PyQt6.QtGui import QFont, QGuiApplication
from PyQt6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QCheckBox,
    QComboBox,
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
    QVBoxLayout,
    QWidget,
    QPlainTextEdit,
)

from . import config, diagnostics, firewall, relay, winproc

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


def _is_offscreen() -> bool:
    """是否离屏渲染。离屏（自动化测试）下模态 QMessageBox 会永久阻塞事件循环。"""
    try:
        return QGuiApplication.platformName().lower() == "offscreen"
    except Exception:  # noqa: BLE001
        return False


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


# ---------------------------------------------------------------------------
# 主窗口
# ---------------------------------------------------------------------------
class MainWindow(QMainWindow):
    def __init__(self, auto_run: bool = True) -> None:
        super().__init__()
        self.report: diagnostics.Report | None = None
        self.worker: Worker | None = None
        self.relay_thread: RelayThread | None = None
        self._closing = False
        self._auto_run = auto_run
        # 中继向导状态
        self._session = ""           # 本次主机/加入会话的校验值
        self._relay_ready = False    # 就绪检测是否全部通过
        self._host_info: dict | None = None  # 加入方解析出的主机码信息

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
        self.tabs.addTab(self._build_relay_tab(), "UDP 中继")

        self._build_statusbar(main)

        # 中继流量刷新：不依赖中继主动推 stats（那样数据量随流量走），
        # 用定时器拉快照，节奏可控
        self._relay_timer = QTimer(self)
        self._relay_timer.setInterval(1000)
        self._relay_timer.timeout.connect(self._refresh_relay_stats)

        # 窗口一出来就先跑一次检测；测试可关掉这个开关，避免离屏时也去碰真实网络
        if self._auto_run:
            QTimer.singleShot(200, self.start_run)

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
        self.address_view.setText("检测中……")
        layout.addWidget(self.address_view)

        self.command_view = QLineEdit(objectName="commandView")
        self.command_view.setReadOnly(True)
        self.command_view.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.command_view.setPlaceholderText("控制台指令：检测中……")
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

        self.refresh_relay_readiness()
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
        self.btn_join_apply.clicked.connect(self.apply_and_start)
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
    def refresh_relay_readiness(self) -> None:
        role = "host" if self.rb_host.isChecked() else "join"
        results = relay.check_relay_readiness(role)
        lines = []
        self._relay_ready = True
        for ok, level, msg in results:
            mark = {"ok": "✓", "warn": "!", "fail": "×"}[level]
            lines.append(f"{mark} {msg}")
            if level == "fail":
                self._relay_ready = False
        self.relay_ready_view.setPlainText("\n".join(lines))
        if role == "host":
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
        code = relay.encode_host_code(
            addresses, relay.DEFAULT_RELAY_BASE, sorted(ports), self._session
        )
        self.host_code_view.setText(code)
        self.btn_host_code_copy.setEnabled(True)
        self.host_status_label.setText(
            f"中继端口 {relay.DEFAULT_RELAY_BASE} 起，共 {len(ports)} 条映射；"
            f"校验 {self._session}"
        )

    def regen_host_code(self) -> None:
        self._session = relay.make_session_token()
        self._refresh_host_code()
        self._append_relay_log("[INFO] 已更换校验值，旧的加入码将作废")

    def copy_host_code(self) -> None:
        self._copy_code(self.host_code_view.text(), "主机码")

    # ---- 加入码管理（主机端）----
    def _reload_join_list(self) -> None:
        while self.join_list_layout.count():
            item = self.join_list_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
        entries = relay.load_join_codes()
        if not entries:
            hint = QLabel("（还没有加入码；把朋友发来的 JOIN… 粘贴到上面添加）",
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

    def _toggle_join(self, index: int, enabled: bool) -> None:
        entries = relay.load_join_codes()
        if 0 <= index < len(entries):
            entries[index]["enabled"] = bool(enabled)
            relay.save_join_codes(entries)
            self._reload_join_list()

    def _delete_join(self, index: int) -> None:
        entries = relay.load_join_codes()
        if 0 <= index < len(entries):
            removed = entries.pop(index)
            relay.save_join_codes(entries)
            self._reload_join_list()
            self._append_relay_log(
                f"[INFO] 已删除加入码：{'、'.join(removed.get('addresses', []))}"
            )

    # ---- 启动 / 停止 ----
    def apply_and_start(self) -> None:
        if self.rb_host.isChecked():
            rules, error = self._build_host_rules()
        else:
            rules, error = self._build_join_rules()
        if rules is None:
            self._notify("warn", error)
            return

        # 主机端：自动放行防火墙（需管理员，失败仅提示）
        if self.rb_host.isChecked():
            self._auto_firewall(rules)

        # 若已在运行则先停（确认生效 = 重启）
        thread = self.relay_thread
        if thread is not None and thread.isRunning():
            thread.stop()
            thread.wait(3000)

        self.relay_log_view.clear()
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
        if not entries:
            return None, (
                "白名单为空：请先把加入方发来的 JOIN… 码添加到列表并启用，"
                "否则任何人扫到端口都能连。"
            )
        allow = relay.AddressAllowList(entries)
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
        if not self.rb_host.isChecked() and self._host_info:
            # 加入方：生成游戏内连接指令（主世界端口 = 最小的游戏端口）
            game_ports = [g for _, g in self._host_info["maps"]]
            master = min(game_ports)
            cmd = f'c_connect("127.0.0.1", {master})'
            self.join_cmd_view.setText(cmd)
            self.btn_join_cmd_copy.setEnabled(True)
            self.join_status_label.setText(
                f"已连接主机的 {len(self._host_info['maps'])} 条映射；"
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
        self._closing = True
        self._relay_timer.stop()
        thread = self.relay_thread
        if thread is not None and thread.isRunning():
            thread.stop()
            thread.wait(3000)
        event.accept()

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
        if winproc.request_admin_restart():
            QApplication.instance().quit()
        else:
            QMessageBox.warning(self, config.APP_NAME, "提权请求被取消或失败")

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

        if report.is_admin:
            self.admin_badge.setText("● 管理员模式")
            self.admin_badge.setProperty("admin", "1")
        else:
            self.admin_badge.setText("● 普通权限")
            self.admin_badge.setProperty("admin", "0")
        # 触发样式刷新
        self.admin_badge.style().unpolish(self.admin_badge)
        self.admin_badge.style().polish(self.admin_badge)
        self.admin_badge.setVisible(True)

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

    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    import sys

    sys.exit(main())
