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
"""GUI 启动入口。

双击本文件（或运行 `python main.py`）直接打开图形界面。
所有逻辑都在 dst_ip_join.gui 中，这里只负责兜底异常弹窗。
"""

from __future__ import annotations

import os
import sys
import traceback


def _bootstrap() -> None:
    """确保项目根目录在 sys.path 上，双击启动也能正常导入包。"""
    here = os.path.dirname(os.path.abspath(__file__))
    if here not in sys.path:
        sys.path.insert(0, here)


def _show_fatal(message: str) -> None:
    """无控制台（打包后的 windowed exe）时，出错要弹窗显示堆栈。

    优先 PyQt6：打包时会排除 tkinter（省体积），只用 tkinter 的话
    窗口模式下启动失败就什么都看不到。
    """
    try:
        sys.stderr.write(message + "\n")
    except Exception:
        pass

    try:
        from PyQt6.QtWidgets import QApplication, QMessageBox

        app = QApplication.instance() or QApplication([])
        QMessageBox.critical(None, "饥荒联机版 IP 联机助手", message)
        del app
        return
    except Exception:
        pass

    try:
        import tkinter as tk
        from tkinter import messagebox

        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("饥荒联机版 IP 联机助手", message)
        root.destroy()
    except Exception:
        pass


def _dump_elevation_probe() -> int | None:
    """诊断用：设置环境变量 ``DSTIP_ELEVATION_PROBE=<文件路径>`` 时，
    把「提权重启会启动什么」写进该文件并直接退出，不开界面。

    打包成无控制台的 windowed exe 后，提权路径到底解析成了什么完全看不到，
    而这一步很易错（单文件模式下 ``sys.executable`` 是解包副本，甚至不存在）。
    有了它就能在**不触发 UAC**的情况下核实，避免直接弹授权框干扰测试。
    """
    target = os.environ.get("DSTIP_ELEVATION_PROBE", "").strip()
    if not target:
        return None
    lines: list[str] = []
    try:
        from dst_ip_join import winproc

        exe, params, workdir = winproc.build_elevation_command()
        lines = [
            f"sys.executable = {sys.executable}",
            f"sys.argv = {sys.argv}",
            f"is_frozen = {winproc.is_frozen()}",
            f"frozen_attr = {getattr(sys, 'frozen', None)}",
            f"compiled = {'__compiled__' in globals()}",
            f"{winproc._ONEFILE_PARENT_ENV} = "
            f"{os.environ.get(winproc._ONEFILE_PARENT_ENV, '(未设置)')}",
            f"original_exe = {winproc.onefile_original_executable()}",
            f"elevate_exe = {exe}",
            f"elevate_exe_exists = {os.path.isfile(exe) if exe else False}",
            f"elevate_params = {params}",
            f"elevate_workdir = {workdir}",
            f"workdir_is_dir = {os.path.isdir(workdir) if workdir else False}",
        ]
    except Exception:  # noqa: BLE001 - 诊断代码本身出错也要留下痕迹
        lines = ["probe failed:"] + traceback.format_exc().splitlines()
    try:
        with open(target, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
    except OSError:
        pass
    return 0


def main() -> int:
    _bootstrap()
    probe = _dump_elevation_probe()
    if probe is not None:
        return probe
    try:
        from dst_ip_join import gui_qt as gui
    except ImportError:
        # PyQt6 未安装时退回 Tkinter 界面
        try:
            from dst_ip_join import gui
        except Exception:
            _show_fatal("依赖加载失败：\n\n" + traceback.format_exc())
            return 1
    except Exception:
        _show_fatal("依赖加载失败：\n\n" + traceback.format_exc())
        return 1

    try:
        return gui.main()
    except Exception:
        _show_fatal("程序异常退出：\n\n" + traceback.format_exc())
        return 1


if __name__ == "__main__":
    sys.exit(main())
