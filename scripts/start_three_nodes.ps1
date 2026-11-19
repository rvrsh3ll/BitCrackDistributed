param(
	[string]$ExePath
)

$base = Join-Path (Get-Location) 'dist/windows/gui'

# Prefer the packaged GUI exe in dist/windows/gui unless the caller passed an explicit ExePath
if (-not $ExePath) {
	$candidate = Join-Path $base 'bitcrack-distributed-gui.exe'
	if (Test-Path $candidate) { $ExePath = $candidate; Write-Host "Using GUI exe: $ExePath" } else { $ExePath = Join-Path $base 'bitcrack-distributed-gui.exe' }
} else { Write-Host "Using provided ExePath: $ExePath" }
$exe = $ExePath
$node1cfg = Join-Path $base 'node1_config.json'
$node2cfg = Join-Path $base 'node2_config.json'
$node3cfg = Join-Path $base 'node3_config.json'

# Stop existing
Get-Process -Name bitcrack* -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

$p1 = Start-Process -FilePath $exe -ArgumentList '--cpu','--autostart','--config',$node1cfg -RedirectStandardOutput (Join-Path $base 'node1_run.log') -RedirectStandardError (Join-Path $base 'node1_err.log') -NoNewWindow -PassThru
Start-Sleep -Milliseconds 500
$p2 = Start-Process -FilePath $exe -ArgumentList '--cpu','--autostart','--config',$node2cfg -RedirectStandardOutput (Join-Path $base 'node2_run.log') -RedirectStandardError (Join-Path $base 'node2_err.log') -NoNewWindow -PassThru
Start-Sleep -Milliseconds 500
$p3 = Start-Process -FilePath $exe -ArgumentList '--cpu','--autostart','--config',$node3cfg -RedirectStandardOutput (Join-Path $base 'node3_run.log') -RedirectStandardError (Join-Path $base 'node3_err.log') -NoNewWindow -PassThru

Write-Host "Started PIDs: $($p1.Id), $($p2.Id), $($p3.Id)"
Write-Host "Logs: $base\node1_run.log, $base\node2_run.log, $base\node3_run.log"
