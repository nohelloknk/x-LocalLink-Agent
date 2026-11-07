# SPDX-License-Identifier: GPL-3.0-or-later
[CmdletBinding()]
param(
    [string]$Destination = (Join-Path $env:LOCALAPPDATA 'X'),
    [string]$PythonExecutable,
    [switch]$StageOnly
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
function Invoke-Checked([string]$Executable, [string[]]$Arguments) {
    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Command failed ($LASTEXITCODE): $Executable" }
}
function Test-Python([string]$Executable) {
    if (-not $Executable -or -not (Test-Path -LiteralPath $Executable -PathType Leaf)) { return $false }
    if ($Executable -match 'WindowsApps') { return $false }
    try {
        & $Executable -c 'import sys,venv;sys.exit(0 if (3,12)<=sys.version_info[:2]<(3,14) and sys.maxsize>2**32 else 1)' 2>$null
        return ($LASTEXITCODE -eq 0)
    } catch { return $false }
}
try {
    $destinationPath = [IO.Path]::GetFullPath($Destination)
    if ($destinationPath -eq [IO.Path]::GetFullPath($PSScriptRoot)) { throw 'Choose an installation folder outside the source checkout.' }
    if (Test-Path -LiteralPath $destinationPath) {
        $knownInstall = Test-Path -LiteralPath (Join-Path $destinationPath 'data\installation.json')
        $unexpected = @(Get-ChildItem -LiteralPath $destinationPath -Force | Where-Object Name -ne 'runtime')
        if (-not $knownInstall -and $unexpected.Count -gt 0) { throw 'Destination contains unrelated files; nothing was changed.' }
    }
    if ($PythonExecutable) {
        if (-not (Test-Python $PythonExecutable)) { throw 'PythonExecutable must point to 64-bit Python 3.12 or 3.13.' }
    } else {
        $candidates = [Collections.Generic.List[string]]::new()
        $pythonCommand = Get-Command python.exe -ErrorAction SilentlyContinue
        if ($pythonCommand) { $candidates.Add($pythonCommand.Source) }
        $pyCommand = Get-Command py.exe -ErrorAction SilentlyContinue
        if ($pyCommand) {
            foreach ($version in @('-3.13', '-3.12')) {
                try {
                    $found = & $pyCommand.Source $version -c 'import sys;print(sys.executable)' 2>$null
                    if ($LASTEXITCODE -eq 0 -and $found) { $candidates.Add([string]$found) }
                } catch { continue }
            }
        }
        foreach ($registryRoot in @('HKCU:\Software\Python\PythonCore', 'HKLM:\Software\Python\PythonCore')) {
            if (Test-Path $registryRoot) {
                foreach ($entry in Get-ChildItem $registryRoot) {
                    $installKey = Join-Path $entry.PSPath 'InstallPath'
                    if (Test-Path $installKey) {
                        $folder = (Get-Item $installKey).GetValue('')
                        if ($folder) { $candidates.Add((Join-Path $folder 'python.exe')) }
                    }
                }
            }
        }
        $privatePython = Join-Path $env:LOCALAPPDATA 'X-Python\python.exe'
        $candidates.Add($privatePython)
        foreach ($candidate in $candidates) {
            if (Test-Python $candidate) { $PythonExecutable = $candidate; break }
        }
        if (-not $PythonExecutable) {
            Write-Host 'Downloading Python 3.13.17 from python.org (per-user installation)...'
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            $download = Join-Path ([IO.Path]::GetTempPath()) ('x-python-' + [guid]::NewGuid() + '.exe')
            try {
                Invoke-WebRequest -UseBasicParsing -Uri 'https://www.python.org/ftp/python/3.13.17/python-3.13.17-amd64.exe' -OutFile $download
                $expectedHash = '5da012101ba2e17113a9a1cd901e9ce1441086f2b7ecb5de06ec94163899a190'
                if ((Get-FileHash -LiteralPath $download -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedHash) { throw 'Python installer SHA256 mismatch.' }
                $signature = Get-AuthenticodeSignature -LiteralPath $download
                if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'Python Software Foundation') { throw 'Python installer signature is invalid.' }
                $pythonHome = Split-Path $privatePython
                $installArgs = '/quiet InstallAllUsers=0 Include_launcher=0 Include_test=0 Include_doc=0 Include_pip=1 PrependPath=0 Shortcuts=0 TargetDir="' + $pythonHome + '"'
                $process = Start-Process -FilePath $download -ArgumentList $installArgs -WindowStyle Hidden -Wait -PassThru
                if ($process.ExitCode -notin @(0,3010)) { throw "Python installation failed: $($process.ExitCode)" }
            } finally {
                if (Test-Path -LiteralPath $download) { Remove-Item -LiteralPath $download }
            }
            $PythonExecutable = $privatePython
            if (-not (Test-Python $PythonExecutable)) { throw 'Installed Python did not pass verification.' }
        }
    }
    New-Item -ItemType Directory -Path $destinationPath -Force | Out-Null
    $runtime = Join-Path $destinationPath 'runtime'
    $runtimePython = Join-Path $runtime 'Scripts\python.exe'
    if (-not (Test-Path -LiteralPath $runtimePython)) {
        Write-Host 'Creating the isolated X runtime...'
        Invoke-Checked $PythonExecutable @('-m', 'venv', $runtime)
    }
    if (-not (Test-Python $runtimePython)) { throw 'Existing X runtime is invalid. Choose a new destination or repair its Python runtime.' }
    Invoke-Checked $runtimePython @('-m', 'pip', 'install', '--disable-pip-version-check', '-r', (Join-Path $PSScriptRoot 'requirements.txt'))
    $setupArgs = @((Join-Path $PSScriptRoot 'X.pyw'), '--install', '--destination', $destinationPath, '--setup-only', '--no-open')
    if ($StageOnly) { $setupArgs += '--stage-only' }
    Invoke-Checked $runtimePython $setupArgs
    Write-Host "Installed extension folder: $(Join-Path $destinationPath 'x-extension')"
    if ($StageOnly) {
        Write-Host 'Stage-only: no registry registration, desktop shortcut or bridge startup.'
    } else {
        Write-Host 'Chrome: chrome://extensions > Developer mode > Load unpacked > select that folder.'
        Write-Host 'Keep this installed folder. Native Messaging starts the helper when needed.'
    }
} catch {
    Write-Error -Message $_.Exception.Message -ErrorAction Continue
    exit 1
}
