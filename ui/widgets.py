"""Shared UI widgets: stat cards, honest placeholders, severity bar chart, status LED."""
import time

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor, QPainter, QPainterPath
from PySide6.QtWidgets import (QFrame, QLabel, QPlainTextEdit, QPushButton,
                                QVBoxLayout, QWidget)

from ui.theme import (BG, LINE, MUTED, NEON, PANEL, SEVERITY_COLORS, TEXT)


class StatCard(QFrame):
    """Dashboard metric card. The value is whatever real data the caller supplies."""

    def __init__(self, title, value="0", accent=NEON, subtitle=""):
        super().__init__()
        self.setObjectName("Card")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 10, 14, 10)
        self._title = QLabel(title.upper())
        self._title.setObjectName("CardTitle")
        self._value = QLabel(str(value))
        self._value.setObjectName("CardValue")
        self._value.setStyleSheet(f"color: {accent};")
        self._subtitle = QLabel(subtitle)
        self._subtitle.setObjectName("Muted")
        lay.addWidget(self._title)
        lay.addWidget(self._value)
        lay.addWidget(self._subtitle)
        lay.addStretch(1)

    def set_value(self, value, subtitle=None):
        self._value.setText(str(value))
        if subtitle is not None:
            self._subtitle.setText(subtitle)


class ModulePlaceholder(QWidget):
    """Honest 'not built yet' page. Never pretends the module works."""

    def __init__(self, title, stage, plan):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(40, 40, 40, 40)
        name = QLabel(title.upper())
        name.setObjectName("SectionTitle")
        tag = QLabel(f"PLANNED FOR STAGE {stage} — NOT FUNCTIONAL YET")
        tag.setStyleSheet(f"color: {SEVERITY_COLORS['medium']}; font-weight: 700; letter-spacing: 1px;")
        body = QLabel(plan)
        body.setWordWrap(True)
        body.setStyleSheet(f"color: {MUTED}; font-size: 13px;")
        lay.addWidget(name)
        lay.addWidget(tag)
        lay.addWidget(body)
        lay.addStretch(1)


class SeverityBarChart(QWidget):
    """Minimal bar chart painted from real severity counts (no external chart lib)."""

    def __init__(self, breakdown):
        super().__init__()
        self._breakdown = breakdown or {}
        self.setMinimumHeight(140)

    def set_breakdown(self, breakdown):
        self._breakdown = breakdown or {}
        self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        p.fillRect(self.rect(), QColor(PANEL))
        order = ["critical", "high", "medium", "low", "informational"]
        max_n = max([self._breakdown.get(k, 0) for k in order] + [1])
        w = self.width() / len(order)
        chart_h = self.height() - 26
        p.setPen(QColor(TEXT))
        for i, key in enumerate(order):
            n = self._breakdown.get(key, 0)
            h = int((n / max_n) * (chart_h - 10)) if n else 0
            x = int(i * w + w * 0.22)
            bar = QPainterPath()
            bar.addRoundedRect(x, chart_h - h, int(w * 0.56), max(h, 2), 3, 3)
            p.fillPath(bar, QColor(SEVERITY_COLORS[key]))
            p.drawText(int(i * w), chart_h + 4, int(w), 20, Qt.AlignHCenter, key[:4].upper())
            if n:
                p.drawText(int(i * w), chart_h - h - 18, int(w), 16, Qt.AlignHCenter, str(n))


class StatusLed(QWidget):
    """Animated LED. It only pulses while an operation is genuinely running."""

    def __init__(self):
        super().__init__()
        self._on = False
        self._busy = False
        self._phase = 0
        self.setFixedSize(14, 14)
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(400)

    def set_busy(self, busy: bool):
        self._busy = busy
        self._on = not busy
        self.update()

    def _tick(self):
        if self._busy:
            self._phase = (self._phase + 1) % 2
            self._on = self._phase == 0
            self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        color = QColor(NEON) if self._on else QColor("#1e2a1e")
        p.setBrush(color)
        p.setPen(QColor(LINE))
        p.drawEllipse(2, 2, 10, 10)


class Console(QPlainTextEdit):
    """Scrolling terminal console. Only real application events are printed."""

    def __init__(self):
        super().__init__()
        self.setObjectName("Console")
        self.setReadOnly(True)
        self.setMaximumBlockCount(2000)

    def log(self, message, kind="info"):
        stamp = time.strftime("%H:%M:%S")
        color = {"ok": NEON, "warn": "#ffd60a", "err": "#ff2e4d"}.get(kind, TEXT)
        self.appendHtml(f'<span style="color:{MUTED}">[{stamp}]</span> '
                        f'<span style="color:{color}">{message}</span>')
