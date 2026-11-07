# X — local browser / MCP bridge

Editable source distribution, version 2.3.0, for Windows. The browser extension
connects supported AI chat pages to a local helper exposing Roblox Studio, Files
and CMD tools. Chrome Native Messaging starts the helper; authenticated
WebSocket traffic uses `127.0.0.1:17613`.

## Installation

1. Download or clone the repository, keeping its files together.
2. Double-click **Install.cmd**. Internet access is needed for dependencies.
3. Open `chrome://extensions`, enable **Developer mode**, choose **Load unpacked**
   and select `%LOCALAPPDATA%\X\x-extension`.
4. Open the extension and a supported chat page, then enable the agent.
   Native Messaging starts the helper when needed. Roblox tools also require
   Studio and its MCP plugin; Files and CMD work independently of Studio.

The installer uses 64-bit Python 3.12/3.13, or downloads Python 3.13.17 from
python.org with SHA256 and Authenticode verification. It creates an isolated
runtime in `%LOCALAPPDATA%\X\runtime`. Bootstrapped Python lives separately in
`%LOCALAPPDATA%\X-Python`. No administrator account is required.

The native host is registered for the current Windows user in Chrome's HKCU
registry key. A desktop shortcut is created. Chrome extension loading remains a
manual user action. The extension alone cannot install the native helper.
Install.cmd uses a process-only execution-policy override; system policy is not
changed. Managed computers may block scripts or unpacked extensions.

Custom install:

```powershell
.\Install.ps1 -Destination "$env:LOCALAPPDATA\X" -PythonExecutable 'C:\Python313\python.exe'
```

Existing X configuration and pairing keys are preserved. Changed application
files are backed up in `backups`; unrelated nonempty destinations are rejected.
Close X normally and reload the extension after an update. The installer does
not kill an already running older bridge.

## Data and permissions

Each computer creates its own `data/pairing-key.txt` and
`x-extension/local-connection.json`. Do not share data, logs, backups, generated
XHost.exe or local-connection.json. Share this source checkout instead.
The public manifest key keeps the extension ID stable and may be committed.

Files and CMD tools run with the Windows user's permissions. Enable the agent
only for conversations you trust. Local authentication does not make generated
commands trustworthy. No cloud credentials are included. AI provider web layout
changes can break their adapters.

## Troubleshooting

- Connection refused: complete installation, reload the extension and open the
  desktop shortcut. Inspect `logs/launcher-error.log` locally.
- Native host missing: rerun the installer under the same user who runs Chrome.
  Other browsers require separate registration.
- Port occupied: close the previous X instance normally. Unrelated processes
  are never terminated by this installer.
- Existing file: identical writes leave it unchanged; conflicting contents are
  preserved unless replacement was explicitly requested.

## Development and license

See [CONTRIBUTING.md](CONTRIBUTING.md). Python, JavaScript, HTML and CSS remain
editable. The native launcher is compiled during installation from C# embedded
in X.pyw, using the Windows .NET Framework compiler.

GPL-3.0-or-later; see [LICENSE](LICENSE) and [NOTICE.md](NOTICE.md).
Keep attribution and provide corresponding source when distributing changes.
