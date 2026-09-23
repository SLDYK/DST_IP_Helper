# -*- coding: utf-8 -*-
"""Tkinter 图形界面。

界面分四块：检测项清单 / 大号直连地址 / 操作按钮 / 日志。
所有耗时操作（网络探测、UPnP、netsh）都放在后台线程里跑，
通过 queue + after() 回主线程刷新，避免界面卡死。
"""

from __future__ import annotations

import queue
import re
import threading
import tkinter as tk
import tkinter.font as tkfont
import traceback
from tkinter import messagebox, ttk

from . import config, diagnostics, winproc

# 状态图标与配色
ICONS = {"ok": "✓", "warn": "!", "fail": "×", "info": "i"}
COLORS = {"ok": "#1a7f37", "warn": "#9a6700", "fail": "#cf222e", "info": "#57606a"}
# 浅色（白色）主题：语义色统一用白底可读的深色版，与 PyQt6 界面保持一致
LOG_COLORS = {"OK": "#1a7f37", "WARN": "#9a6700", "FAIL": "#cf222e", "INFO": "#57606a"}

_LEVEL_LINE_RE = re.compile(r"^\[(OK|WARN|FAIL|INFO)\s*\]")

FONT_FAMILY = "Microsoft YaHei UI"
MONO_FAMILY = "Consolas"


class DstIpJoinApp:
    def __init__(self, root: tk.Tk, scale: float = 1.0) -> None:
        self.root = root
        self.scale = scale
        self.queue: queue.Queue = queue.Queue()
        self.report: diagnostics.Report | None = None
        self.running = False
        self._check_row = 0

        self._setup_fonts()
        self._build_ui()
        self._poll_queue()

        # 启动后不自动检测（检测要联网、还会改本机防火墙/UPnP 配置），
        # 等用户点「开始检测并配置」再动作。
        self._show_idle_state()

    # ------------------------------------------------------------------
    # 界面搭建
    # ------------------------------------------------------------------
    def _setup_fonts(self) -> None:
        for name in ("TkDefaultFont", "TkTextFont", "TkMenuFont", "TkHeadingFont"):
            try:
                font = tkfont.nametofont(name)
                font.configure(family=FONT_FAMILY)
            except tk.TclError:
                continue

    def _build_ui(self) -> None:
        self.root.title(f"{config.APP_NAME}  v{config.APP_VERSION}")

        try:
            ttk.Style().theme_use("vista")
        except tk.TclError:
            pass

        outer = ttk.Frame(self.root, padding=12)
        outer.pack(fill="both", expand=True)

        self._build_header(outer)
        self._build_checks(outer)
        self._build_address(outer)
        self._build_actions(outer)
        self._build_log(outer)
        self._build_statusbar(outer)
        self._fit_window()

    def _fit_window(self) -> None:
        """按内容实际尺寸定窗口大小，并保证不超出屏幕。

        两个要点：
          * 高 DPI（如 175% 缩放）下不能按比例放大固定尺寸，否则窗口会高出屏幕，
            所以直接用控件自己算出的需求尺寸。
          * 检测项是运行时才一条条加进去的，得提前预留它们的高度，
            不然行数变多会把下面的日志区挤出去。
        """
        self.root.update_idletasks()
        screen_w = self.root.winfo_screenwidth()
        screen_h = self.root.winfo_screenheight()

        try:
            row_height = tkfont.nametofont("TkDefaultFont").metrics("linespace") + 6
        except tk.TclError:
            row_height = 20
        reserve = int(row_height * 16)

        width = min(max(self.root.winfo_reqwidth(), 620), screen_w - 60)
        height = min(
            max(self.root.winfo_reqheight() + reserve, 480),
            screen_h - 120,
        )

        self.root.geometry(f"{width}x{height}")
        self.root.minsize(min(540, width), min(400, height))

    def _build_header(self, parent: ttk.Frame) -> None:
        header = ttk.Frame(parent)
        header.pack(fill="x")

        ttk.Label(
            header,
            text=config.APP_NAME,
            font=(FONT_FAMILY, 15, "bold"),
        ).pack(side="left")

        self.admin_badge = tk.Label(header, text="", font=(FONT_FAMILY, 9))
        self.admin_badge.pack(side="right")
        # 徽标原先只在检测完成回调里显示；启动不再自动检测后会一直空着，
        # 改成搭界面时就显示（winproc.is_admin 是纯本地轻量调用）。
        if winproc.is_admin():
            self.admin_badge.configure(text="● 管理员模式", fg="#1a7f37")
        else:
            self.admin_badge.configure(text="● 普通权限", fg="#9a6700")

    def _build_checks(self, parent: ttk.Frame) -> None:
        box = ttk.LabelFrame(parent, text=" 检测项 ", padding=8)
        box.pack(fill="x", pady=(10, 0))

        self.checks_frame = ttk.Frame(box)
        self.checks_frame.pack(fill="x")
        self.checks_frame.columnconfigure(2, weight=1)

    def _build_address(self, parent: ttk.Frame) -> None:
        box = ttk.LabelFrame(parent, text=" 把地址或指令发给朋友 ", padding=10)
        box.pack(fill="x", pady=(10, 0))

        self.address_var = tk.StringVar(value="尚未检测")
        self.address_entry = tk.Entry(
            box,
            textvariable=self.address_var,
            state="readonly",
            font=(MONO_FAMILY, 20, "bold"),
            justify="center",
            readonlybackground="#f2f6fb",
            relief="flat",
            bd=8,
        )
        self.address_entry.pack(fill="x")

        self.command_var = tk.StringVar(value="")
        self.command_entry = tk.Entry(
            box,
            textvariable=self.command_var,
            state="readonly",
            font=(MONO_FAMILY, 11),
            justify="center",
            readonlybackground="#f4faf5",
            foreground="#1a7f37",
            relief="flat",
            bd=5,
        )
        self.command_entry.pack(fill="x", pady=(6, 0))

        buttons = ttk.Frame(box)
        buttons.pack(fill="x", pady=(8, 0))
        self.btn_copy_addr = ttk.Button(
            buttons, text="复制指令", command=self.copy_command
        )
        self.btn_copy_addr.pack(side="left")
        self.btn_copy_share = ttk.Button(
            buttons, text="复制完整说明（发给朋友）", command=self.copy_share_text
        )
        self.btn_copy_share.pack(side="left", padx=(8, 0))
        self.btn_copy_share.state(["disabled"])

    def _build_actions(self, parent: ttk.Frame) -> None:
        # 拆成两行，否则高 DPI 下这一行会宽到把窗口撑爆
        box = ttk.Frame(parent)
        box.pack(fill="x", pady=(10, 0))

        first_row = ttk.Frame(box)
        first_row.pack(fill="x")

        self.btn_run = ttk.Button(
            first_row, text="开始检测并配置", command=self.start_run
        )
        self.btn_run.pack(side="left")

        self.btn_elevate = ttk.Button(
            first_row, text="以管理员身份重启", command=self.elevate
        )
        self.btn_elevate.pack(side="left", padx=(8, 0))

        self.btn_cleanup = ttk.Button(
            first_row, text="撤销我的配置", command=self.start_cleanup
        )
        self.btn_cleanup.pack(side="left", padx=(8, 0))

        second_row = ttk.Frame(box)
        second_row.pack(fill="x", pady=(6, 0))

        self.autocopy_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            second_row, text="完成后自动复制指令", variable=self.autocopy_var
        ).pack(side="left")

        ttk.Label(second_row, text="端口：").pack(side="left", padx=(16, 0))
        self.port_var = tk.StringVar()
        ttk.Entry(second_row, textvariable=self.port_var, width=12).pack(side="left")
        ttk.Label(second_row, text="（留空 = 自动识别）", foreground="#57606a").pack(
            side="left", padx=(4, 0)
        )

    def _build_log(self, parent: ttk.Frame) -> None:
        box = ttk.LabelFrame(parent, text=" 日志 ", padding=6)
        box.pack(fill="both", expand=True, pady=(10, 0))

        self.log_text = tk.Text(
            box,
            height=12,
            width=1,  # 故意设得很小：宽度由外层拼开，不让日志框反过来撑大窗口
            wrap="word",
            font=(MONO_FAMILY, 9),
            state="disabled",
            background="#ffffff",
            foreground="#24292f",
            insertbackground="#24292f",
            relief="flat",
            padx=6,
            pady=4,
        )
        scroll = ttk.Scrollbar(box, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        self.log_text.pack(side="left", fill="both", expand=True)

        for level, color in LOG_COLORS.items():
            self.log_text.tag_configure(level, foreground=color)
        # 默认正文 tag：白底必须用深色，否则几乎不可见
        self.log_text.tag_configure("title", foreground="#24292f")

    def _build_statusbar(self, parent: ttk.Frame) -> None:
        bar = ttk.Frame(parent)
        bar.pack(fill="x", pady=(6, 0))

        self.progress = ttk.Progressbar(bar, mode="indeterminate", length=140)
        self.progress.pack(side="right")

        self.status_var = tk.StringVar(value="就绪")
        ttk.Label(bar, textvariable=self.status_var, foreground="#57606a").pack(
            side="left"
        )

    # ------------------------------------------------------------------
    # 日志与状态刷新（只在主线程调用）
    # ------------------------------------------------------------------
    def _append_log(self, message: str) -> None:
        self.log_text.configure(state="normal")
        tag = "title"
        match = _LEVEL_LINE_RE.match(message)
        if match:
            tag = match.group(1)
        self.log_text.insert("end", message + "\n", tag)

        # 限制日志长度，避免长时间运行后内存膨胀
        if int(self.log_text.index("end-1c").split(".")[0]) > 3000:
            self.log_text.delete("1.0", "500.0")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _clear_checks(self) -> None:
        for child in self.checks_frame.winfo_children():
            child.destroy()
        self._check_row = 0

    def _show_idle_state(self) -> None:
        """启动后、用户点击检测之前的初始界面（不做任何网络/系统动作）。"""
        self._clear_checks()
        ttk.Label(
            self.checks_frame,
            text="尚未检测，点「开始检测并配置」开始。",
            foreground="#57606a",
            font=(FONT_FAMILY, 10),
        ).grid(row=0, column=1, columnspan=2, sticky="w", pady=2)
        self.address_var.set("尚未检测")
        self.command_var.set("")
        self.btn_copy_share.state(["disabled"])
        self._set_status("就绪，等待开始检测")

    def _add_check(self, item: diagnostics.CheckItem) -> None:
        row = self._check_row
        self._check_row += 1

        tk.Label(
            self.checks_frame,
            text=ICONS.get(item.level, "i"),
            fg=COLORS.get(item.level, "#57606a"),
            font=(FONT_FAMILY, 11, "bold"),
            width=2,
        ).grid(row=row, column=0, sticky="w", pady=1)

        ttk.Label(
            self.checks_frame,
            text=item.title,
            width=14,
            anchor="w",
            font=(FONT_FAMILY, 10),
        ).grid(row=row, column=1, sticky="w", pady=1)

        ttk.Label(
            self.checks_frame,
            text=item.detail,
            anchor="w",
            foreground="#57606a",
            wraplength=int(400 * self.scale),
            font=(FONT_FAMILY, 10),
        ).grid(row=row, column=2, sticky="w", pady=1)

    def _set_status(self, text: str) -> None:
        self.status_var.set(text)

    def _set_running(self, running: bool) -> None:
        self.running = running
        for widget in (self.btn_run, self.btn_cleanup, self.btn_elevate):
            if running:
                widget.state(["disabled"])
            else:
                widget.state(["!disabled"])
        if running:
            self.progress.start(12)
        else:
            self.progress.stop()

    # ------------------------------------------------------------------
    # 线程间通信
    # ------------------------------------------------------------------
    def _poll_queue(self) -> None:
        try:
            while True:
                kind, payload = self.queue.get_nowait()
                if kind == "log":
                    self._append_log(payload)
                elif kind == "status":
                    self._add_check(payload)
                elif kind == "progress":
                    self._set_status(payload)
                elif kind == "done":
                    self._on_done(payload)
                elif kind == "cleanup_done":
                    self._on_cleanup_done(payload)
                elif kind == "error":
                    self._on_error(payload)
        except queue.Empty:
            pass
        self.root.after(80, self._poll_queue)

    # 下面两个回调在后台线程里执行，只允许往队列里塞东西
    def _log_from_thread(self, message: str) -> None:
        self.queue.put(("log", message))

    def _status_from_thread(self, item: diagnostics.CheckItem) -> None:
        self.queue.put(("status", item))

    # ------------------------------------------------------------------
    # 动作
    # ------------------------------------------------------------------
    def start_run(self) -> None:
        if self.running:
            return

        ok, ports = self._parse_ports()
        if not ok:
            return

        self._clear_checks()
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")
        self._append_log(f"{config.APP_NAME} v{config.APP_VERSION} 开始检测……")
        self.address_var.set("检测中……")
        self.command_var.set("")
        self.btn_copy_share.state(["disabled"])
        self._set_running(True)
        self._set_status("正在检测……")

        thread = threading.Thread(
            target=self._run_worker, args=(ports,), daemon=True
        )
        thread.start()

    def _run_worker(self, ports: list[int] | None) -> None:
        try:
            report = diagnostics.run_diagnosis(
                ports=ports,
                log=self._log_from_thread,
                status=self._status_from_thread,
                configure=True,
            )
        except Exception:  # noqa: BLE001
            self.queue.put(("error", traceback.format_exc()))
            return
        self.queue.put(("done", report))

    def _on_done(self, report: diagnostics.Report) -> None:
        self.report = report
        self._set_running(False)
        self.address_var.set(report.primary_address or "未能确定可用地址")
        self.command_var.set(report.connect_command or "没有可用的直连指令")

        level_text = {
            diagnostics.LEVEL_OK: "配置完成",
            diagnostics.LEVEL_WARN: "需要一步手动操作",
            diagnostics.LEVEL_FAIL: "当前网络无法直连",
            diagnostics.LEVEL_INFO: "检测结束",
        }.get(report.level, "检测结束")
        self._set_status(level_text)

        self.btn_copy_share.state(["!disabled"])

        if report.is_admin:
            self.admin_badge.configure(text="● 管理员模式", fg="#1a7f37")
        else:
            self.admin_badge.configure(text="● 普通权限", fg="#9a6700")

        if self.autocopy_var.get() and report.connect_command:
            self.copy_command(quiet=True)

        if report.level == diagnostics.LEVEL_FAIL:
            self._append_log("")
            self._append_log("[FAIL] 当前网络条件无法让别人通过 IP 直连")

    def _on_error(self, detail: str) -> None:
        self._set_running(False)
        self._set_status("出错了")
        self._append_log("")
        self._append_log("[FAIL] 检测过程中发生未预期的错误：")
        for line in detail.rstrip().splitlines():
            self._append_log("    " + line)
        messagebox.showerror(config.APP_NAME, f"检测出错：\n{detail.splitlines()[-1]}")

    def start_cleanup(self) -> None:
        if self.running:
            return
        if not messagebox.askyesno(
            config.APP_NAME,
            "将删除本工具添加的防火墙放行规则和 UPnP 端口映射，继续吗？",
        ):
            return

        self._set_running(True)
        self._set_status("正在撤销配置……")
        thread = threading.Thread(target=self._cleanup_worker, daemon=True)
        thread.start()

    def _cleanup_worker(self) -> None:
        try:
            ports = None
            if self.report and self.report.target_ports:
                ports = self.report.target_ports
            messages = diagnostics.cleanup(
                ports=ports,
                log=self._log_from_thread,
                status=self._status_from_thread,
            )
        except Exception:  # noqa: BLE001
            self.queue.put(("error", traceback.format_exc()))
            return
        self.queue.put(("cleanup_done", messages))

    def _on_cleanup_done(self, messages: list[str]) -> None:
        self._set_running(False)
        self._set_status("已撤销配置")
        self._append_log("[OK  ] 撤销完成")
        messagebox.showinfo(
            config.APP_NAME,
            "撤销完成：\n" + "\n".join(f"· {m}" for m in messages[:8]),
        )

    def elevate(self) -> None:
        if not messagebox.askyesno(
            config.APP_NAME,
            "将以管理员权限重新启动本工具（会弹出 UAC 授权框），继续吗？",
        ):
            return
        result = winproc.request_admin_restart_detailed(
            hwnd=self.root.winfo_id()
        )
        if result.started:
            self.root.destroy()
            return
        # 失败时必须给出具体原因，否则「取消或失败」没法排查
        if result.declined:
            messagebox.showinfo(
                config.APP_NAME,
                f"{result.message}\n\n"
                "如果 UAC 授权框没弹出来，可能是被安全软件拦了；\n"
                "也可以直接右键程序选「以管理员身份运行」。",
            )
        else:
            messagebox.showwarning(
                config.APP_NAME,
                f"{result.message}\n"
                f"错误码：{result.code}\n\n"
                "可以直接右键程序选「以管理员身份运行」绕过。",
            )

    # ------------------------------------------------------------------
    # 复制
    # ------------------------------------------------------------------
    def copy_command(self, quiet: bool = False) -> None:
        command = self.command_var.get().strip()
        if not command or command == "没有可用的直连指令":
            if not quiet:
                messagebox.showinfo(config.APP_NAME, "还没有可复制的指令")
            return

        if winproc.set_clipboard_text(command):
            self._set_status("指令已复制，粘贴到控制台即可")
            if not quiet:
                self._append_log(f"[OK  ] 指令已复制到剪贴板：{command}")
        elif not quiet:
            messagebox.showwarning(config.APP_NAME, "写入剪贴板失败，请手动选中复制")

    def copy_share_text(self) -> None:
        if not self.report or not self.report.share_text:
            messagebox.showinfo(config.APP_NAME, "还没有可分享的内容，先跑一次检测")
            return

        if winproc.set_clipboard_text(self.report.share_text):
            self._set_status("完整说明已复制")
            self._append_log("[OK  ] 完整说明已复制到剪贴板")
        else:
            messagebox.showwarning(config.APP_NAME, "写入剪贴板失败，请手动选中复制")

    # ------------------------------------------------------------------
    # 辅助
    # ------------------------------------------------------------------
    def _parse_ports(self) -> tuple[bool, list[int] | None]:
        """读取手动端口输入。

        返回 ``(是否继续, 端口列表)``：
          * ``(False, None)`` —— 输入非法，已弹窗提示，调用方应中止
          * ``(True, None)``  —— 未填，交给自动识别
          * ``(True, [...])`` —— 使用手动指定的端口
        """
        text = self.port_var.get().strip()
        if not text:
            return True, None

        ports: list[int] = []
        for chunk in re.split(r"[,，\s]+", text):
            if not chunk:
                continue
            if not chunk.isdigit():
                messagebox.showerror(
                    config.APP_NAME, f"端口格式不对：{chunk}\n请填数字，多个用逗号分隔"
                )
                return False, None
            port = int(chunk)
            if not (1 <= port <= 65535):
                messagebox.showerror(config.APP_NAME, f"端口超出范围：{port}")
                return False, None
            ports.append(port)

        if not ports:
            return True, None
        # 去重并保持顺序
        unique = list(dict.fromkeys(ports))
        return True, unique


def main() -> int:
    scale = winproc.enable_dpi_awareness()

    root = tk.Tk()
    # 显式按真实 DPI 设置缩放，保证高分屏下字号正确
    try:
        root.tk.call("tk", "scaling", scale * 96.0 / 72.0)
    except tk.TclError:
        pass

    DstIpJoinApp(root, scale=scale)
    root.mainloop()
    return 0
