<#
.SYNOPSIS
    E2E Pre-Deploy & Config-Change Gatekeeper for IaC, Ansible, and App/Native C-C++-ASM changes.
    Blocks deployment/configuration commands automatically if AIOps Auditor detects >= HIGH findings.
.EXAMPLE
    .\scripts\deploy-gate.ps1 -Stage iac -Profile local-dev
    .\scripts\deploy-gate.ps1 -Stage ansible -Profile prod-16gb-coder -ChangedOnly
    .\scripts\deploy-gate.ps1 -Stage app -Profile prod-16gb-coder -DeployCommand "kubectl apply -k k8s/overlays/cloud-k8s-nvidia"
#>
param(
    [ValidateSet("iac", "ansible", "app", "all")]
    [string]$Stage = "all",
    [ValidateSet("offline-heuristic", "local-tiny", "local-dev", "local-8gb", "prod-16gb-coder", "prod-16gb-reasoning", "prod-16gb-vllm")]
    [string]$Profile = "local-dev",
    [switch]$ChangedOnly,
    [switch]$EnableOsv,
    [switch]$AutoSyncCve,
    [string]$DeployCommand = ""
)

$ErrorActionPreference = "Stop"
$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$env:PYTHONPATH = Join-Path $RepoRoot "auditor\src"

$GateArgs = @(
    "-m", "aiops_auditor", "gate",
    "--stage", $Stage,
    "--repo", $RepoRoot,
    "--profile", $Profile,
    "--out-dir", (Join-Path $RepoRoot "reports")
)
if ($ChangedOnly) { $GateArgs += "--changed-only" }
if ($EnableOsv) { $GateArgs += "--enable-osv" }
if ($AutoSyncCve) { $GateArgs += "--auto-sync-cve" }

Write-Host "[AIOPS-GATE] Auditing stage '$Stage' before deploy/config change..." -ForegroundColor Cyan
python @GateArgs
if ($LASTEXITCODE -ne 0) {
    Write-Host "[AIOPS-GATE] BLOCKED! Fix CRITICAL/HIGH security findings before deploying." -ForegroundColor Red
    exit $LASTEXITCODE
}

Write-Host "[AIOPS-GATE] PASSED! Deploy / config change is approved." -ForegroundColor Green
if ($DeployCommand -ne "") {
    Write-Host "[AIOPS-GATE] Running: $DeployCommand" -ForegroundColor Yellow
    Invoke-Expression $DeployCommand
    exit $LASTEXITCODE
}

