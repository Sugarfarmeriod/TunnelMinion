[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("apply", "recover", "rollback", "archive")]
    [string]$Mode,

    [ValidatePattern("^[0-9a-f]{32}$")]
    [string]$BarrierId,

    [string]$IdentityPipeName
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$python = Join-Path $repoRoot ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw "Project virtual-environment Python was not found: $python"
}
if ($Mode -eq "archive") {
    if ($BarrierId -or $IdentityPipeName) {
        throw "Archive mode does not accept a barrier or identity pipe."
    }
}
elseif (-not $BarrierId) {
    throw "BarrierId is required for $Mode mode."
}

$principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    if ($Mode -eq "archive") {
        $arguments = @(
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-File", "`"$PSCommandPath`"",
            "-Mode", "archive"
        )
        $stdoutPath = [IO.Path]::GetTempFileName()
        $stderrPath = [IO.Path]::GetTempFileName()
        try {
            $process = Start-Process powershell.exe `
                -Verb RunAs `
                -ArgumentList $arguments `
                -RedirectStandardOutput $stdoutPath `
                -RedirectStandardError $stderrPath `
                -PassThru `
                -Wait
            $stdout = Get-Content -LiteralPath $stdoutPath -Raw -ErrorAction SilentlyContinue
            $stderr = Get-Content -LiteralPath $stderrPath -Raw -ErrorAction SilentlyContinue
            if ($stdout) {
                Write-Output $stdout.TrimEnd()
            }
            if ($stderr) {
                [Console]::Error.WriteLine($stderr.TrimEnd())
            }
            exit $process.ExitCode
        }
        finally {
            Remove-Item -LiteralPath $stdoutPath, $stderrPath -Force -ErrorAction SilentlyContinue
        }
    }
    & $python -m scripts.managed_path_stage6_windows_operator $Mode $BarrierId --serve
    exit $LASTEXITCODE
}

function Invoke-Stage6 {
    param([Parameter(Mandatory = $true)][string]$Action)

    & $python -m scripts.managed_path_stage6_apply `
        --platform windows `
        --barrier-id $BarrierId `
        $Action
    if ($LASTEXITCODE -ne 0) {
        throw "Stage 6 command failed: $Action (exit code $LASTEXITCODE)."
    }
}

Push-Location $repoRoot
try {
    if ($Mode -eq "archive") {
        & $python -m scripts.managed_path_stage6_apply --platform windows --archive-rolled-back
        if ($LASTEXITCODE -ne 0) {
            throw "Stage 6 rolled-back run archive failed (exit code $LASTEXITCODE)."
        }
        return
    }
    if ($Mode -eq "recover") {
        if ($IdentityPipeName) {
            & $python -m scripts.managed_path_stage6_windows_operator $Mode $BarrierId --elevated --pipe-name $IdentityPipeName
            exit $LASTEXITCODE
        }
        Invoke-Stage6 "--recover"
        return
    }
    if ($Mode -eq "rollback") {
        if ($IdentityPipeName) {
            & $python -m scripts.managed_path_stage6_windows_operator $Mode $BarrierId --elevated --pipe-name $IdentityPipeName
            exit $LASTEXITCODE
        }
        Invoke-Stage6 "--rollback-create"
        return
    }

    $readyPath = "F:\Project\codex\tunnelminion-stage6-data\windows\stage6-apply-ready.json"
    $protectedNames = @(
        "stage6-apply-evidence.json",
        "stage6-apply-ready.json",
        "stage6-apply-go.json",
        "stage6-apply-peer-ready.json",
        "stage6-apply-governance.sqlite3",
        "stage6-rollback-evidence.json"
    )
    $existing = @($protectedNames | Where-Object {
        Test-Path -LiteralPath (Join-Path (Split-Path $readyPath) $_)
    })
    if ($existing.Count -ne 0) {
        throw "Stage 6 state already exists: $($existing -join ', '). Use recover or rollback; do not apply again."
    }
    $arguments = @(
        "-m", "scripts.managed_path_stage6_apply",
        "--platform", "windows",
        "--barrier-id", $BarrierId,
        "--apply"
    )
    if ($IdentityPipeName) {
        $arguments = @(
            "-m", "scripts.managed_path_stage6_windows_operator",
            "apply", $BarrierId, "--elevated", "--pipe-name", $IdentityPipeName
        )
    }
    $applyProcess = Start-Process `
        -FilePath $python `
        -ArgumentList $arguments `
        -PassThru `
        -NoNewWindow

    $deadline = [DateTime]::UtcNow.AddSeconds(120)
    while (-not (Test-Path -LiteralPath $readyPath -PathType Leaf)) {
        $applyProcess.Refresh()
        if ($applyProcess.HasExited) {
            # Refresh() 可能先报告 HasExited，退出码此时尚未可读；等待进程
            # 完成后再读取，确保操作者看到真实状态。
            $applyProcess.WaitForExit()
            throw "Windows apply exited before writing the ready marker (exit code $($applyProcess.ExitCode))."
        }
        if ([DateTime]::UtcNow -ge $deadline) {
            throw "Timed out waiting for the Windows ready marker; apply will exit on its own timeout."
        }
        Start-Sleep -Milliseconds 250
    }

    $readyJson = (Get-Content -LiteralPath $readyPath -Raw -Encoding UTF8).Trim()
    Write-Host ""
    Write-Host "Copy this entire line into the macOS root script:"
    Write-Host $readyJson
    Write-Host ""
    $peerReady = Read-Host "Paste the complete ready JSON line from the macOS script here"
    $peerReady | & $python -m scripts.managed_path_stage6_apply `
        --platform windows `
        --barrier-id $BarrierId `
        --import-peer-ready
    if ($LASTEXITCODE -ne 0) {
        throw "macOS ready-marker import failed. Do not apply again; retry import and release before authorization expires."
    }

    Invoke-Stage6 "--release-barrier"
    $applyProcess.WaitForExit()
    if ($applyProcess.ExitCode -ne 0) {
        throw "Windows apply did not pass (exit code $($applyProcess.ExitCode))."
    }
    Write-Host "Windows Stage 6.3 apply, Provider verify, path verify, and acknowledgement completed."
}
finally {
    Pop-Location
}
