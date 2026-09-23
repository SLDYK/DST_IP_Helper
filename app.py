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
"""图形界面入口。

用 pythonw.exe 启动时没有控制台，任何未捕获的异常都会「静默消失」，
所以这里把启动逻辑整体包起来，出错时弹一个对话框把堆栈显示出来。
"""

from __future__ import annotations

import os
import sys
import traceback


def _bootstrap() -> None:
    """确保包目录在 sys.path 上（直接从任意工作目录双击启动也能用）。"""
    here = os.path.dirname(os.path.abspath(__file__))
    if here not in sys.path:
        sys.path.insert(0, here)


def _show_fatal(message: str) -> None:
    try:
        sys.stderr.write(message + "\n")
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


def main() -> int:
    _bootstrap()
    try:
        from dst_ip_join import gui
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
