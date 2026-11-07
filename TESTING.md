# Distribution verification — 2026-11-08

Verified locally on Windows with Python 3.12:

- Seven automated tests passed: public package hygiene, manifest assets,
  independent pairing keys, update preservation, unrelated-file protection,
  idempotent/conflicting/concurrent writes and native launcher protocol checks.
- All four extension JavaScript files passed Node syntax checks.
- Install.ps1 passed PowerShell parsing.
- Stage-only installation created an isolated runtime and installed all pinned
  dependencies. Reinstallation passed under Windows PowerShell 5.1.
- The C# native launcher compiled and rejected a foreign origin. Unsupported
  native requests returned framed JSON without revealing the pairing token.
  Registry calls were mocked for this test.
- The Python bootstrap download matched the pinned SHA256 and had a valid
  Python Software Foundation Authenticode signature. It was not installed as
  part of this verification.

Not yet verified in a fresh VM: the no-Python bootstrap installation, actual
Chrome registration/loading on a second account and Python 3.13 execution.
CI is configured for Python 3.12 and 3.13; its remote run is pending publication.
Browser-provider behavior must also be checked against their current websites.
