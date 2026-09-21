# -*- coding: utf-8 -*-
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
    """用 pythonw 启动时没有控制台，出错时弹窗显示堆栈。"""
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
