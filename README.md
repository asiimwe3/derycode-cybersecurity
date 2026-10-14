# DERYCODE CYBERSECURITY

*Build. Learn. Test. Defend.*

Professional Windows desktop application for Derycode Organization: authorized security testing, café network monitoring, ethical hacking training and professional reporting.

Built with Python 3, PySide6 and SQLite. Runs fully locally — no web dashboard required.

## Status — every stage delivered

| Stage | Scope | Status |
|---|---|---|
| 1 | Shell, navigation, database, dashboard, console | Working (tested) |
| 2 | Login, roles/permissions, asset authorization, audit | Working (tested) |
| 3 | SecScan: website, API, source code checks | Working (tested) |
| 4 | Reports (HTML + real PDF), dependency audit | Working (tested) |
| 5 | Network Guard, device inventory, security events | Working (tested) |
| 6 | CyberLab challenges + Academy (10 courses) | Working (tested) |
| 7 | Firewall integration (read-only + confirmed actions) | Working (tested) |
| 8 | Packaging, CI, docs | Spec + workflow included |

Windows-specific host audits (Defender status, event logs, netsh firewall) run only on
Windows; on other systems they report `requires_windows` instead of pretending.

## Install (Windows)

```
py -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

Python 3.10+ required. Data lives in `%APPDATA%\DerycodeCybersecurity\app.db`.
On first launch the app asks you to create the administrator account.

## Using each module

1. *SecScan* — register an asset, record its authorization, select modules, Start Scan.
   Findings are labelled confirmed/potential. Generate HTML or PDF reports from the view.
2. *Network Guard* — refresh devices (ARP, read-only), take traffic snapshots, run
   detection rules, review the firewall. Blocking a destination requires an admin role,
   an explicit confirmation, and elevated privileges.
3. *CyberLab* — start the local vulnerable app (127.0.0.1 only), solve the 8 challenges,
   earn points. Nothing external is ever touched.
4. *Academy* — add students/instructors, enroll in the 10 courses, take quizzes (70%
   passes), generate certificates for completed courses, export CSV records.
5. *Settings* — create users/roles, toggle online dependency lookups (OSV — package
   names only), back up the database.

## Demo data (evaluation only)

```
python main.py --demo-seed
```

Seeds clearly-labelled `[DEMO]` records so every dashboard number and report can be
reviewed before real assets are registered. A yellow "DEMO DATA" badge shows while on.

## Tests

```
pip install pytest
pytest tests
```

20 automated tests: schema, password hashing, scope authorization (unauthorized scans are
rejected), website checks against a live local mock target, source-code secret detection
with masking, offline dependency audit, HTML report content, detection rules, firewall
guard (refuses without confirmation), the SQLi lab challenge end-to-end, quiz/certificate
flow (incomplete courses never certify), and headless GUI tests.

## Safety and authorization model

1. Nothing scans without a registered asset + recorded authorization (ScopeManager).
2. Potential findings are never reported as confirmed vulnerabilities.
3. Secrets are masked in all evidence; source code never leaves the machine without
   explicit consent (Settings toggle, off by default).
4. Network monitoring is read-only by default; disruptive actions need role permission,
   a confirmation dialog and OS elevation. No customer traffic content is ever read.
5. The training lab binds to 127.0.0.1 only and never targets public systems.
6. No credential theft, Wi-Fi cracking, stealth persistence or destructive payloads.
7. Every action lands in the audit log; the database is one-click backupable.

## Windows executable and installer (Stage 8)

Portable build:
```
pip install pyinstaller
pyinstaller packaging/dcs.spec
```
Result: `dist\DerycodeCybersecurity\` (runs without installing Python).

Installer: open `packaging\installer.iss` in Inno Setup 6 and compile after the
PyInstaller build. Produces `DerycodeCybersecurity-Setup.exe`.

CI: `.github/workflows/ci.yml` runs the full test suite on every push.

## Project layout

```
main.py                 entry point, login flow, demo fixtures
core/                   database, permissions, scope manager, audit
secscan/                engine, website/api checks, source audit, dependency audit
network_guard/          discovery, traffic, detection rules, firewall integration
windows_security/       system audit, event log reader (read-only)
cyberlab/               local vulnerable lab app, challenges, scoring
academy/                courses, students, certificates
reports/                HTML + PDF generation
ui/                     shell, dashboard, module views
tests/                  20 automated tests
packaging/              PyInstaller spec + Inno Setup installer script
```

## Troubleshooting

* *PySide6 install fails on old Python* — use Python 3.10+.
* *Login says invalid* — run `python main.py --create-admin user newpassword` to reset an admin.
* *Windows audit shows "requires Windows"* — expected on non-Windows systems.
* *Database locked / corrupt* — delete `app.db` (data loss) or restore from
  `backups/` (Settings → Back up now).
