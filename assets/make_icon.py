# -*- coding: utf-8 -*-
"""生成 assets/icon.ico（仅在打包前运行一次，运行时不需要）。

用项目 venv 里现成的 PyQt6 画一个简单的「地球」图标，
并手工封装成标准 ICO 容器（16/32/48 用 BMP，256 用 PNG）。
"""

from __future__ import annotations

import struct
from pathlib import Path

from PyQt6.QtCore import QPointF, QRectF, Qt
from PyQt6.QtGui import (
    QBrush,
    QColor,
    QGuiApplication,
    QImage,
    QLinearGradient,
    QPainter,
    QPen,
    QPixmap,
)

OUT = Path(__file__).resolve().parent / "icon.ico"
BASE = 256  # 画布基准尺寸，内部按比例缩放

_app = QGuiApplication([])  # QPixmap 必须在 QGuiApplication 之后使用


def render(size: int) -> QImage:
    """绘制 size x size 的图标位图（深蓝圆角底 + 白色地球线稿）。"""
    pm = QPixmap(size, size)
    pm.fill(Qt.GlobalColor.transparent)

    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    s = size / BASE
    m = 14 * s  # 外边距

    # 圆角方块背景（对角线渐变）
    grad = QLinearGradient(0, 0, size, size)
    grad.setColorAt(0.0, QColor("#3b82f6"))
    grad.setColorAt(1.0, QColor("#1e3a8a"))
    p.setBrush(QBrush(grad))
    p.setPen(Qt.PenStyle.NoPen)
    p.drawRoundedRect(QRectF(m, m, size - 2 * m, size - 2 * m), 52 * s, 52 * s)

    # 白色地球：外圆 + 赤道 + 一条经线椭圆
    pen = QPen(QColor("#ffffff"))
    pen.setWidthF(11 * s)
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    p.setPen(pen)
    p.setBrush(Qt.BrushStyle.NoBrush)

    cx = cy = size / 2.0
    r = 72 * s
    p.drawEllipse(QPointF(cx, cy), r, r)
    p.drawLine(QPointF(cx - r, cy), QPointF(cx + r, cy))
    p.drawEllipse(QPointF(cx, cy), r * 0.45, r)

    p.end()
    return pm.toImage()


def png_bytes(img: QImage) -> bytes:
    from PyQt6.QtCore import QBuffer, QIODevice

    buf = QBuffer()
    buf.open(QIODevice.OpenModeFlag.WriteOnly)
    img.save(buf, "PNG")
    return bytes(buf.data())


def build_ico() -> None:
    # 全部尺寸用 PNG 编码：Windows Vista+ 的 ICO 容器支持任意尺寸内嵌 PNG，
    # 避免手工封装 BMP（XOR/AND mask）的坑。
    sizes = [256, 48, 32, 16]
    images = [(size, png_bytes(render(size))) for size in sizes]

    count = len(images)
    out = bytearray()
    out += struct.pack("<HHH", 0, 1, count)  # ICONDIR

    offset = 6 + 16 * count
    entries = bytearray()
    for size, data in images:
        # 宽/高为 0 表示 256
        b = 0 if size >= 256 else size
        entries += struct.pack(
            "<BBBBHHII", b, b, 0, 0, 1, 32, len(data), offset
        )
        offset += len(data)

    out += entries
    for _, data in images:
        out += data

    OUT.write_bytes(bytes(out))
    print(f"OK: {OUT} ({OUT.stat().st_size} bytes)")


if __name__ == "__main__":
    build_ico()
