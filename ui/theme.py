"""Dark security-operations theme: black/dark-gray surfaces, neon-green accents."""

SEVERITY_COLORS = {
    "critical": "#ff2e4d",
    "high": "#ff8c1a",
    "medium": "#ffd60a",
    "low": "#35c4ff",
    "informational": "#9aa5a0",
}
NEON = "#39ff14"
BG = "#0a0f0a"
PANEL = "#111711"
PANEL_ALT = "#161f16"
TEXT = "#d8ffd0"
MUTED = "#7d8a7d"
LINE = "#223022"

STYLESHEET = f"""
QWidget {{ background: {BG}; color: {TEXT}; font-family: 'Consolas','Courier New',monospace; font-size: 13px; }}
QMainWindow {{ background: {BG}; }}

/* Sidebar */
#Sidebar {{ background: {PANEL}; border-right: 1px solid {LINE}; }}
QPushButton#NavButton {{
    text-align: left; padding: 10px 14px; border: none; border-radius: 6px;
    color: {MUTED}; background: transparent; font-weight: 600;
}}
QPushButton#NavButton:hover {{ color: {TEXT}; background: {PANEL_ALT}; }}
QPushButton#NavButton:checked {{ color: {NEON}; background: {PANEL_ALT}; border-left: 3px solid {NEON}; }}
QLabel#Brand {{
    color: {NEON}; font-size: 16px; font-weight: 800; letter-spacing: 2px; padding: 16px 14px 4px 14px;
}}
QLabel#BrandTag {{ color: {MUTED}; font-size: 10px; letter-spacing: 1px; padding: 0 14px 12px 14px; }}

/* Panels and cards */
QFrame#Card {{ background: {PANEL}; border: 1px solid {LINE}; border-radius: 8px; }}
QLabel#CardTitle {{ color: {MUTED}; font-size: 11px; letter-spacing: 1px; }}
QLabel#CardValue {{ color: {NEON}; font-size: 26px; font-weight: 800; }}
QLabel#SectionTitle {{ color: {TEXT}; font-size: 18px; font-weight: 800; letter-spacing: 1px; }}
QLabel#Muted {{ color: {MUTED}; }}

/* Tables */
QTableWidget {{
    background: {PANEL}; alternate-background-color: {PANEL_ALT};
    gridline-color: {LINE}; border: 1px solid {LINE}; border-radius: 6px;
}}
QHeaderView::section {{
    background: {PANEL_ALT}; color: {TEXT}; border: none; border-bottom: 1px solid {LINE};
    padding: 6px; font-weight: 700;
}}
QTableWidget::item {{ padding: 4px; }}

/* Terminal console */
QPlainTextEdit#Console {{
    background: #060a06; color: {NEON}; border: 1px solid {LINE};
    border-radius: 6px; font-size: 12px; padding: 6px;
}}

/* Status bar */
QStatusBar {{ background: {PANEL}; border-top: 1px solid {LINE}; color: {MUTED}; }}

/* Scrollbars */
QScrollBar:vertical {{ background: {PANEL}; width: 10px; border-radius: 5px; }}
QScrollBar::handle:vertical {{ background: {LINE}; border-radius: 5px; min-height: 24px; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
"""
