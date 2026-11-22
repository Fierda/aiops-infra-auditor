<#
.SYNOPSIS
    Run AIOps Infra Auditor on Windows against any local project directory.
.EXAMPLE
    .\scripts\run-audit.ps1 -Target . -Profile local-dev
    .\scripts\run-audit.ps1 -Target "D:\Code\my-php-or-node-project" -Profile prod-16gb-coder
#>
param(
    [string]$Target = ".",
    [ValidateSet("offline-heuristic", "local-tiny", "local-dev", "local-8gb", "prod-16gb-coder", "prod-16gb-reasoning", "prod-16gb-vllm")]
    [string]$Profile = "local-dev",
    [string]$OutDir = "reports",
    [switch]$EnableOsv,
    [switch]$AutoSyncCve,
    [switch]$NoFail
)

$ErrorActionPreference = "Stop"
$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$env:PYTHONPATH = Join-Path $RepoRoot "auditor\src"

$ArgsList = @(
    "-m", "aiops_auditor", "scan",
    "--target", $Target,
    "--profile", $Profile,
    "--out-dir", $OutDir
)

if ($EnableOsv) { $ArgsList += "--enable-osv" }
if ($AutoSyncCve) { $ArgsList += "--auto-sync-cve" }
if ($NoFail) { $ArgsList += "--no-fail" }

python @ArgsList
exit $LASTEXITCODE

