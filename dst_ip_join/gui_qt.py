# -*- coding: utf-8 -*-
"""PyQt6 图形界面。

布局：左侧检测项清单 + 右侧（直连地址卡片 / 操作 / 日志）。
耗时操作（网络探测、UPnP、netsh）放在 QThread 后台线程，
通过信号回主线程刷新界面。
"""

from __future__ import annotations

import re
import traceback

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QGuiApplication
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
    QPlainTextEdit,
)

from . import config, diagnostics, winproc

# ---------------------------------------------------------------------------
# 主题
# ---------------------------------------------------------------------------
STYLE = """
* {
    font-family: "Microsoft YaHei UI", "Segoe UI", sans-serif;
    font-size: 13px;
    color: #e6e8eb;
}
QMainWindow, QWidget#root { background: #16181d; }

/* ---------- 标题区 ---------- */
QLabel#appTitle { font-size: 19px; font-weight: 700; color: #f2f4f7; }
QLabel#adminBadge { padding: 3px 10px; border-radius: 9px; font-size: 12px; }
QLabel#adminBadge[admin="1"] { background: #1e3a28; color: #7fd693; }
QLabel#adminBadge[admin="0"] { background: #3d3220; color: #e5b567; }

/* ---------- 卡片 ---------- */
QFrame#card {
    background: #1f2229;
    border: 1px solid #2c313a;
    border-radius: 10px;
}
QLabel#cardTitle { color: #8b93a1; font-size: 12px; font-weight: 600; }

/* ---------- 检测项 ---------- */
QLabel#checkIcon { font-size: 14px; font-weight: 700; }
QLabel#checkTitle { font-weight: 600; color: #d3d7dd; }
QLabel#checkDetail { color: #8b93a1; }
QLabel#emptyHint { color: #5b626e; padding: 18px; }

/* ---------- 地址展示 ---------- */
QLineEdit#addressView {
    background: #12151a;
    border: 1px solid #2c313a;
    border-radius: 8px;
    padding: 14px;
    font-family: Consolas, "Cascadia Mono", monospace;
    font-size: 22px;
    font-weight: 700;
    color: #6cb6ff;
    selection-background-color: #2d5a88;
}
QLineEdit#commandView {
    background: #12151a;
    border: 1px solid #2c313a;
    border-radius: 6px;
    padding: 7px 10px;
    font-family: Consolas, "Cascadia Mono", monospace;
    font-size: 14px;
    color: #8fd6a8;
    selection-background-color: #2d5a88;
}

/* ---------- 按钮 ---------- */
QPushButton {
    background: #2a2f38;
    border: 1px solid #3a4150;
    border-radius: 7px;
    padding: 8px 16px;
}
QPushButton:hover { background: #343b47; border-color: #4a5468; }
QPushButton:pressed { background: #22262e; }
QPushButton:disabled { background: #22252b; color: #5b626e; border-color: #2c313a; }
QPushButton#primary {
    background: #2d6cdf;
    border-color: #2d6cdf;
    color: #ffffff;
    font-weight: 600;
}
QPushButton#primary:hover { background: #3d7bec; border-color: #3d7bec; }
QPushButton#primary:pressed { background: #2459b8; }
QPushButton#primary:disabled { background: #2a3850; color: #7a8699; border-color: #2a3850; }
QPushButton#danger:hover { border-color: #a4474d; color: #e89090; }

/* ---------- 输入 ---------- */
QLineEdit#portInput {
    background: #12151a;
    border: 1px solid #2c313a;
    border-radius: 6px;
    padding: 6px 10px;
}
QLineEdit#portInput:focus { border-color: #2d6cdf; }
QCheckBox { spacing: 6px; }
QCheckBox::indicator {
    width: 15px; height: 15px; border-radius: 4px;
    border: 1px solid #4a5468; background: #12151a;
}
QCheckBox::indicator:checked { background: #2d6cdf; border-color: #2d6cdf; }

/* ---------- 日志 ---------- */
QPlainTextEdit#logView {
    background: #101216;
    border: 1px solid #2c313a;
    border-radius: 8px;
    font-family: Consolas, "Cascadia Mono", monospace;
    font-size: 12px;
    color: #b9c0ca;
    padding: 6px;
    selection-background-color: #2d5a88;
}

/* ---------- 进度条与状态栏 ---------- */
QProgressBar {
    background: #12151a;
    border: 1px solid #2c313a;
    border-radius: 5px;
    height: 10px;
    text-align: center;
}
QProgressBar::chunk { background: #2d6cdf; border-radius: 4px; }
QLabel#statusLabel { color: #8b93a1; }

/* ---------- 滚动条 ---------- */
QScrollArea { border: none; background: transparent; }
QScrollBar:vertical {
    background: transparent; width: 10px; margin: 2px;
}
QScrollBar::handle:vertical {
    background: #3a4150; border-radius: 5px; min-height: 24px;
}
QScrollBar::handle:vertical:hover { background: #4a5468; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical { background: none; }

QToolTip { background: #2a2f38; color: #e6e8eb; border: 1px solid #3a4150; padding: 4px 8px; }
"""

LEVEL_STYLE = {
    diagnostics.LEVEL_OK: ("✓", "#7fd693"),
    diagnostics.LEVEL_WARN: ("!", "#e5b567"),
    diagnostics.LEVEL_FAIL: ("×", "#e57373"),
    diagnostics.LEVEL_INFO: ("i", "#8b93a1"),
}
LOG_COLORS = {"OK": "#7fd693", "WARN": "#e5b567", "FAIL": "#e57373", "INFO": "#8b93a1"}
LEVEL_LINE_RE = re.compile(r"^\[(OK|WARN|FAIL|INFO)\s*\]")


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


# ---------------------------------------------------------------------------
# 主窗口
# ---------------------------------------------------------------------------
class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.report: diagnostics.Report | None = None
        self.worker: Worker | None = None

        self.setWindowTitle(f"{config.APP_NAME}  v{config.APP_VERSION}")
        self.resize(900, 640)
        self.setMinimumSize(760, 560)

        root = QWidget(objectName="root")
        self.setCentralWidget(root)
        main = QVBoxLayout(root)
        main.setContentsMargins(16, 14, 16, 12)
        main.setSpacing(10)

        self._build_header(main)

        body = QHBoxLayout()
        body.setSpacing(10)
        main.addLayout(body, stretch=1)

        self._build_checks_panel(body)

        right = QVBoxLayout()
        right.setSpacing(10)
        body.addLayout(right, stretch=3)
        self._build_address_card(right)
        self._build_actions(right)
        self._build_log_card(right)

        self._build_statusbar(main)

        # 窗口一出来就先跑一次检测
        from PyQt6.QtCore import QTimer

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
        icon_text, color = LEVEL_STYLE.get(item.level, ("i", "#8b93a1"))

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
        color = LOG_COLORS.get(match.group(1), "#b9c0ca") if match else "#b9c0ca"
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
