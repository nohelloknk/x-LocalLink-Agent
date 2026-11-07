# Developing X

Use Windows, 64-bit Python 3.12/3.13 and Node.js 22 or newer.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
node tests/check-js.cjs
```

Test installation without changing Chrome registration, creating a shortcut or
starting the bridge. Use a new destination:

```powershell
.\Install.ps1 -PythonExecutable "$PWD\.venv\Scripts\python.exe" -Destination "$env:TEMP\X-stage-test" -StageOnly
```

For full integration testing, use a separate Windows account or VM. Run the
normal installer, load the installed extension, enable the agent, create and
read back a temporary file, then test CMD and Studio separately. Restart Chrome
and verify Native Messaging startup. Stage-only deliberately skips registration.

## Source map

- X.pyw: validation, authenticated gateway, audit/replay, MCP process management,
  Studio proxy, Files, CMD, installation and embedded native launcher. Entry
  flags select the role. This single source file is directly editable.
- config.json: portable relative MCP commands; keep machine paths out of defaults.
- x-extension/background.js: native bootstrap and bridge connection.
- x-extension/content.js: provider adapters, parser and agent loop. The checked-in
  bundle is the editable source; no private build step is required.
- page-hooks.js: page-world integration.
- panel.js, HTML and CSS: popup/dashboard and presentation.
- Install.ps1: dependency/runtime setup, delegating application setup to X.pyw.

Keep stdout of MCP/native processes exclusively protocol data. Use stderr or
local logs for diagnostics. Keep the bridge bound to loopback. Test repeated
calls, file conflicts, malformed inputs and reconnects. Never silently force
overwrite after a conflict. Update runtime and manifest versions together.

Before publishing, run tests and inspect `git status --short` / `git ls-files`.
Never commit user keys, history, logs, backups or machine-specific executables.
Preserve GPL and upstream attribution. CI checks do not prove compatibility
with every changing provider website or a clean Windows machine.

## Removal

Remove the Chrome extension, close X normally, then remove the installed folder,
desktop shortcut and this current-user registration:
`HKCU\Software\Google\Chrome\NativeMessagingHosts\com.x.localbridge`.
Remove X-Python only if no other installation uses it. The installer never
automatically deletes user data.
