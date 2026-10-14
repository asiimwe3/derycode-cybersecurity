# DERYCODE CYBERSECURITY

*Build. Learn. Test. Defend.*

Professional Windows desktop application for Derycode Organization: authorized security testing, café network monitoring, ethical hacking training and professional reporting.

Built with Python 3, PySide6 and SQLite. Runs fully locally — no web dashboard required.

## Status — which parts work today

Stage 1 is complete and tested. Later modules are wired into navigation but clearly labelled
"NOT FUNCTIONAL YET" — no button pretends to work before its stage ships.

| Stage | Scope | Status |
|---|---|---|
| 1 | Shell, navigation, database, dashboard, console, audit | **Working** |
| 2 | Login, roles, asset authorization, audit UI | Planned |
| 3 | SecScan (website, app, API, source code) | Planned |
| 4 | Reports, dependency scanning | Planned |
| 5 | Network Guard, Windows security audit, events, inventory | Planned |
| 6 | CyberLab challenges, Academy | Planned |
| 7 | Firewall integrations, advanced monitoring | Planned |
| 8 | Packaging, docs, release | Planned |

## Install (Windows)

```
py -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

Python 3.10+ required. Data is stored in `%APPDATA%\DerycodeCybersecurity\app.db`.

## First run

Create the first administrator before using the app in a real environment:

```
python main.py --create-admin admin <strong-password>
```

Passwords are stored only as PBKDF2-HMAC-SHA256 hashes with per-user salts.

## Demonstration data (evaluation only)

```
python main.py --demo-seed
```

Seeds clearly-labelled demo records (every title carries `[DEMO]`) so the dashboard and
charts can be reviewed before real assets are registered. The dashboard shows a yellow
"DEMO DATA" badge while demo mode is on.

## Tests

```
pip install pytest
pytest tests
```

Database tests need no GUI. GUI tests run headless (`QT_QPA_PLATFORM=offscreen` is set
automatically), so they also work in CI on Linux.

## Security principles enforced by design

1. Authorized testing only — scans will require an approved asset + scope (Stage 2).
2. Potential findings are never reported as confirmed vulnerabilities.
3. Secrets are masked in reports; source code never leaves the machine without consent.
4. Parameterized SQL only; audit log records every action.
5. No credential theft, Wi-Fi cracking, stealth persistence or destructive payloads.

## Windows executable (packaged in Stage 8; command works today)

```
pip install pyinstaller
pyinstaller --noconfirm --onedir --windowed --name DerycodeCybersecurity main.py
```

The resulting `dist\DerycodeCybersecurity\` folder is the portable build; wrap it in an
installer (e.g. Inno Setup) for the installed variant. PyInstaller packaging will be
finalized and verified in Stage 8.

## Project layout

```
main.py               entry point + demo fixtures
core/                 database, audit logging
ui/                   shell, dashboard, theme, widgets
tests/                database + headless GUI tests
packaging/            build specs (added in stage 8)
```
