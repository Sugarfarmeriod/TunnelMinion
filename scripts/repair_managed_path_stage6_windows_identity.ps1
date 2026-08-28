[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this repair script from a normal, non-Administrator PowerShell window."
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$python = Join-Path $repoRoot ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw "Project virtual-environment Python was not found: $python"
}

Push-Location $repoRoot
try {
    & $python -m scripts.managed_path_stage6_identity `
        --platform windows `
        --repair-missing
    if ($LASTEXITCODE -ne 0) {
        throw "Windows Stage 6 identity repair failed (exit code $LASTEXITCODE)."
    }
    Write-Host "Windows Stage 6 identity was rebuilt in the current user's Credential Manager."
    Write-Host "Copy only the new public-identity.json to the macOS peer identity file before apply."
}
finally {
    Pop-Location
}
