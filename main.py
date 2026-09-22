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
