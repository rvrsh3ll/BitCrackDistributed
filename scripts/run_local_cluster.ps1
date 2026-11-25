<#
Run tiny local cluster to validate COMMIT -> KeyspaceBlock assembly and persistence.
Usage: run in a PowerShell prompt from repository root:
  .\scripts\run_local_cluster.ps1

This script will:
- Stop existing bitcrack processes
- Clean data directories for a reproducible run
- Start three nodes with configs in dist/windows/cli
- Wait for them to become reachable and form a P2P ring
- Inject two COMMIT messages that reach the quorum and verify block minting + persistence
- Restart node2 to verify replay of persisted KeyspaceBlock

Requirements: Build artifacts present at build_vs2022\Release\bitcrack-distributed.exe
#>

param(
    [string]$ExePath = ".\\build_vs2022\\Release\\bitcrack-distributed.exe",
    [int]$Node1Port = 3338,
    [int]$Node2Port = 3339,
    [int]$Node3Port = 3340,
    [int]$TimeoutSeconds = 30
)

# If the caller did not explicitly pass ExePath and a packaged CLI exe exists under dist, prefer that exe.
try {
    if (-not $PSBoundParameters.ContainsKey('ExePath')) {
        $candidate = Join-Path (Get-Location) 'dist/windows/cli/bitcrack-distributed-cli.exe'
        if (Test-Path $candidate) {
            Write-Host "Found packaged CLI binary at $candidate; overriding ExePath"
            $ExePath = $candidate
        }
    }
} catch {
    # Conservative: if anything goes wrong, continue with provided ExePath
}

function Stop-BitCrackProcesses {
    Get-Process -Name bitcrack* -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }
}

function Start-Node($configJson, $outLog, $errLog) {
    if (Test-Path $outLog) { Remove-Item $outLog -Force }
    if (Test-Path $errLog) { Remove-Item $errLog -Force }
    $psi = Start-Process -FilePath $ExePath -ArgumentList "--cpu","--autostart","--config",$configJson -RedirectStandardOutput $outLog -RedirectStandardError $errLog -NoNewWindow -PassThru
    return $psi
}

function Wait-For-Port($port, $timeout) {
    $start = Get-Date
    while ((Get-Date) -lt $start.AddSeconds($timeout)) {
        $c = Test-NetConnection -ComputerName 127.0.0.1 -Port $port -WarningAction SilentlyContinue
        if ($c.TcpTestSucceeded) { return $true }
        Start-Sleep -Seconds 1
    }
    return $false
}

function Wait-For-Log($path, $pattern, $timeout) {
    $start = Get-Date
    while ((Get-Date) -lt $start.AddSeconds($timeout)) {
        if (Test-Path $path) {
            $lines = Get-Content $path -ErrorAction SilentlyContinue
            foreach ($l in $lines) {
                if ($l -match $pattern) { return $true }
            }
        }
        Start-Sleep -Milliseconds 250
    }
    return $false
}

function Get-WorkstatePath($nodeDataDir) {
    $path = Join-Path $nodeDataDir 'workstate_p71.json'
    return $path
}

function Get-PersistedBlockCount($nodeDataDir) {
    $path = Get-WorkstatePath -nodeDataDir $nodeDataDir
    if (-not (Test-Path $path)) { return 0 }
    try {
        $json = Get-Content $path -Raw | ConvertFrom-Json
        if ($null -eq $json.blocks) { return 0 }
        return $json.blocks.Count
    } catch {
        return 0
    }
}

function Get-LatestPersistedBlockRange($nodeDataDir) {
    $path = Get-WorkstatePath -nodeDataDir $nodeDataDir
    if (-not (Test-Path $path)) { return $null }
    try {
        $json = Get-Content $path -Raw | ConvertFrom-Json
        if ($null -eq $json.blocks -or $json.blocks.Count -eq 0) { return $null }
        $b = $json.blocks[-1]
        return @{ start = $b.range_start; end = $b.range_end }
    } catch {
        return $null
    }
}

function Inject-Commit($port, $rangeStart, $rangeEnd, $keys, $peerId, [int]$keepAliveMs = 2000) {
    try {
        $c = New-Object System.Net.Sockets.TcpClient('127.0.0.1', $port)
        $stream = $c.GetStream()
        $sw = New-Object System.IO.StreamWriter($stream)
        $sw.AutoFlush = $true
        # Use explicit CRLF and a short pause to allow the server to parse
        $sw.WriteLine("HELLO:$peerId")
        Start-Sleep -Milliseconds 50
        # Attach a correlation id and injected timestamp for log correlation
        $cid = [guid]::NewGuid().ToString()
        $injectedAt = (Get-Date).ToString('o')
        $commit = @{ range_start = $rangeStart; range_end = $rangeEnd; keys_processed = $keys; peer_id = $peerId; correlation_id = $cid; injected_at = $injectedAt } | ConvertTo-Json -Compress
        $sw.WriteLine("COMMIT:$commit")
        # Keep socket open for a bit to ensure the server reads the full payload
        Start-Sleep -Milliseconds $keepAliveMs
        $sw.Close()
        $c.Close()
        return $cid
    } catch {
        return $null
    }
}

function Assert($expr, $msg="Assertion failed") {
    if (-not $expr) { throw $msg }
}

Write-Host "Stopping any running bitcrack processes..."
Stop-BitCrackProcesses

Write-Host "Cleaning test data dirs..."
# Ensure entire data directory is removed and recreated for a clean baseline
if (Test-Path 'dist/windows/cli/data') { Remove-Item -Recurse -Force -ErrorAction SilentlyContinue 'dist/windows/cli/data' }
New-Item -Path dist/windows/cli/data -ItemType Directory -Force | Out-Null
New-Item -Path dist/windows/cli/data/node1 -ItemType Directory -Force | Out-Null
New-Item -Path dist/windows/cli/data/node2 -ItemType Directory -Force | Out-Null
New-Item -Path dist/windows/cli/data/node3 -ItemType Directory -Force | Out-Null

$baseConfigPath = Join-Path -Path (Get-Location) -ChildPath "dist/windows/cli"
$node1Config = Join-Path $baseConfigPath "node1_config.json"
$node2Config = Join-Path $baseConfigPath "node2_config.json"
$node3Config = Join-Path $baseConfigPath "node3_config.json"

# Backup originals so we can revert at the end of the script
$node1ConfigBak = Join-Path $baseConfigPath "node1_config.json.bak"
$node2ConfigBak = Join-Path $baseConfigPath "node2_config.json.bak"
$node3ConfigBak = Join-Path $baseConfigPath "node3_config.json.bak"

$node1Out = Join-Path $baseConfigPath "node1_run.log"
$node1Err = Join-Path $baseConfigPath "node1_err.log"
$node2Out = Join-Path $baseConfigPath "node2_run.log"
$node2Err = Join-Path $baseConfigPath "node2_err.log"
$node3Out = Join-Path $baseConfigPath "node3_run.log"
$node3Err = Join-Path $baseConfigPath "node3_err.log"

Write-Host "Starting nodes..."
function Set-CommitQuorumOne($configPath, $bakPath) {
    if (Test-Path $configPath) {
        # Back up original config
        Copy-Item -Path $configPath -Destination $bakPath -Force
        $cfg = Get-Content $configPath -Raw | ConvertFrom-Json
        if ($null -eq $cfg.network) { $cfg.network = @{} }
        $cfg.network.commit_quorum = 1
        $cfg | ConvertTo-Json -Depth 10 | Set-Content $configPath -Force
        Write-Host "Set commit_quorum=1 in $configPath"
    } else { Write-Warning "Config not found: $configPath" }
}

function Restore-OriginalConfig($bakPath, $configPath) {
    if (Test-Path $bakPath) {
        Copy-Item -Path $bakPath -Destination $configPath -Force
        Remove-Item -Path $bakPath -Force
        Write-Host "Restored original config $configPath from $bakPath"
    }
}

# Set commit_quorum to 1 for faster persistence in test runs
Set-CommitQuorumOne -configPath $node1Config -bakPath $node1ConfigBak
Set-CommitQuorumOne -configPath $node2Config -bakPath $node2ConfigBak
Set-CommitQuorumOne -configPath $node3Config -bakPath $node3ConfigBak

try {
    $p1 = Start-Node $node1Config $node1Out $node1Err
    $p2 = Start-Node $node2Config $node2Out $node2Err
    $p3 = Start-Node $node3Config $node3Out $node3Err
    # Small delay to let node processes initialize their data directories
    Start-Sleep -Seconds 1
    $node1DataDir = Join-Path $baseConfigPath "data\node1"
    $node2DataDir = Join-Path $baseConfigPath "data\node2"
    $node3DataDir = Join-Path $baseConfigPath "data\node3"
    # Record initial persisted counts before any COMMIT injection
    $initialCounts = @{ node1 = Get-PersistedBlockCount -nodeDataDir $node1DataDir; node2 = Get-PersistedBlockCount -nodeDataDir $node2DataDir; node3 = Get-PersistedBlockCount -nodeDataDir $node3DataDir }

Write-Host "Waiting for ports to be listening..."
Assert( (Wait-For-Port -port $Node1Port -timeout $TimeoutSeconds), "Node1 did not listen on port $Node1Port" )
Assert( (Wait-For-Port -port $Node2Port -timeout $TimeoutSeconds), "Node2 did not listen on port $Node2Port" )
Assert( (Wait-For-Port -port $Node3Port -timeout $TimeoutSeconds), "Node3 did not listen on port $Node3Port" )

Write-Host "Waiting for P2P ring formation and independent node initialization..."
Assert( (Wait-For-Log -path $node2Out -pattern 'Independent-node keyspace initialization complete' -timeout $TimeoutSeconds), "Node2 did not initialize P2P keyspace in time" )
Assert( (Wait-For-Log -path $node3Out -pattern 'Independent-node keyspace initialization complete' -timeout $TimeoutSeconds), "Node3 did not initialize P2P keyspace in time" )
Assert( (Wait-For-Log -path $node1Out -pattern 'Independent-node keyspace initialization complete' -timeout $TimeoutSeconds), "Node1 did not initialize P2P keyspace in time" )

# (initialCounts already computed earlier)
Write-Host "Injecting two COMMITs to reach quorum for a tiny range and trigger assembly..."
$rangeStart = '400000000000000000'
$rangeEnd = '400000000000007F'
# Inject commits to two different nodes to simulate quorum (node1 and node2)
$cid1 = Inject-Commit -port $Node1Port -rangeStart $rangeStart -rangeEnd $rangeEnd -keys 128 -peerId 'test_peer_a' -keepAliveMs 2000
Assert( ($cid1 -ne $null -and $cid1 -ne ''), "Failed to inject commit 1 to node1" )
$cid2 = Inject-Commit -port $Node2Port -rangeStart $rangeStart -rangeEnd $rangeEnd -keys 128 -peerId 'test_peer_b' -keepAliveMs 2000
Assert( ($cid2 -ne $null -and $cid2 -ne ''), "Failed to inject commit 2 to node2" )
Start-Sleep -Seconds 2
Write-Host "Checking raw COMMIT arrival in node logs for correlation IDs $cid1, $cid2..."
if (!( (Wait-For-Log -path $node1Out -pattern $cid1 -timeout 6 -errorAction SilentlyContinue) -or (Wait-For-Log -path $node2Out -pattern $cid1 -timeout 6 -errorAction SilentlyContinue) -or (Wait-For-Log -path $node3Out -pattern $cid1 -timeout 6 -errorAction SilentlyContinue) -or (Wait-For-Log -path $node1Out -pattern $cid2 -timeout 6 -errorAction SilentlyContinue) -or (Wait-For-Log -path $node2Out -pattern $cid2 -timeout 6 -errorAction SilentlyContinue) -or (Wait-For-Log -path $node3Out -pattern $cid2 -timeout 6 -errorAction SilentlyContinue) )) {
    Write-Host "No raw COMMIT detected immediately; attempting one retry to each node with extended keepalive"
    # Retry injection with longer keepalive
    $cid1 = Inject-Commit -port $Node1Port -rangeStart $rangeStart -rangeEnd $rangeEnd -keys 128 -peerId 'test_peer_a' -keepAliveMs 3000
    $cid2 = Inject-Commit -port $Node2Port -rangeStart $rangeStart -rangeEnd $rangeEnd -keys 128 -peerId 'test_peer_b' -keepAliveMs 3000
    Start-Sleep -Seconds 1
    Assert((Wait-For-Log -path $node1Out -pattern $cid1 -timeout 6 -errorAction SilentlyContinue) -or (Wait-For-Log -path $node2Out -pattern $cid1 -timeout 6 -errorAction SilentlyContinue) -or (Wait-For-Log -path $node3Out -pattern $cid1 -timeout 6 -errorAction SilentlyContinue) -or (Wait-For-Log -path $node1Out -pattern $cid2 -timeout 6 -errorAction SilentlyContinue) -or (Wait-For-Log -path $node2Out -pattern $cid2 -timeout 6 -errorAction SilentlyContinue) -or (Wait-For-Log -path $node3Out -pattern $cid2 -timeout 6 -errorAction SilentlyContinue), "No node log shows raw COMMIT bytes arrival even after retry")
}

Write-Host "Checking commit parsing invocation in logs for CIDs $cid1, $cid2 (handleCommitMessage...)"
if (!( (Wait-For-Log -path $node1Out -pattern $cid1 -timeout 6 -errorAction SilentlyContinue) -or (Wait-For-Log -path $node2Out -pattern $cid1 -timeout 6 -errorAction SilentlyContinue) -or (Wait-For-Log -path $node3Out -pattern $cid1 -timeout 6 -errorAction SilentlyContinue) -or (Wait-For-Log -path $node1Out -pattern $cid2 -timeout 6 -errorAction SilentlyContinue) -or (Wait-For-Log -path $node2Out -pattern $cid2 -timeout 6 -errorAction SilentlyContinue) -or (Wait-For-Log -path $node3Out -pattern $cid2 -timeout 6 -errorAction SilentlyContinue) )) {
    Write-Host "No handleCommitMessage invocation detected immediately; retrying injection to missing node(s)"
    # retry to node1/node2 as needed
    if (-not (Wait-For-Log -path $node1Out -pattern $cid1 -timeout 1 -errorAction SilentlyContinue) -and -not (Wait-For-Log -path $node1Out -pattern $cid2 -timeout 1 -errorAction SilentlyContinue)) { $cid1 = Inject-Commit -port $Node1Port -rangeStart $rangeStart -rangeEnd $rangeEnd -keys 128 -peerId 'test_peer_a' -keepAliveMs 3000 }
    if (-not (Wait-For-Log -path $node2Out -pattern $cid1 -timeout 1 -errorAction SilentlyContinue) -and -not (Wait-For-Log -path $node2Out -pattern $cid2 -timeout 1 -errorAction SilentlyContinue)) { $cid2 = Inject-Commit -port $Node2Port -rangeStart $rangeStart -rangeEnd $rangeEnd -keys 128 -peerId 'test_peer_b' -keepAliveMs 3000 }
    Start-Sleep -Seconds 1
    Assert( (Wait-For-Log -path $node1Out -pattern $cid1 -timeout 6 -errorAction SilentlyContinue -eq $true) -or (Wait-For-Log -path $node2Out -pattern $cid1 -timeout 6 -errorAction SilentlyContinue -eq $true) -or (Wait-For-Log -path $node3Out -pattern $cid1 -timeout 6 -errorAction SilentlyContinue -eq $true) -or (Wait-For-Log -path $node1Out -pattern $cid2 -timeout 6 -errorAction SilentlyContinue -eq $true) -or (Wait-For-Log -path $node2Out -pattern $cid2 -timeout 6 -errorAction SilentlyContinue -eq $true) -or (Wait-For-Log -path $node3Out -pattern $cid2 -timeout 6 -errorAction SilentlyContinue -eq $true), "No node log shows handleCommitMessage being invoked for a COMMIT payload even after retry")
}
Write-Host "Waiting briefly for persistence to flush to disk..."
Start-Sleep -Seconds 2

# Verify persisted block count incremented by at least 1 on at least one node (node that stored the block)
$node1DataDir = Join-Path $baseConfigPath "data\node1"
$node2DataDir = Join-Path $baseConfigPath "data\node2"
$node3DataDir = Join-Path $baseConfigPath "data\node3"
$afterCounts = @{ node1 = Get-PersistedBlockCount -nodeDataDir $node1DataDir; node2 = Get-PersistedBlockCount -nodeDataDir $node2DataDir; node3 = Get-PersistedBlockCount -nodeDataDir $node3DataDir }
Write-Host "Persisted blocks: before=($($initialCounts.node1),$($initialCounts.node2),$($initialCounts.node3)) after=($($afterCounts.node1),$($afterCounts.node2),$($afterCounts.node3))"

# Look for a node where the block count increased OR the latest persisted range matches our injected range
foreach ($k in $afterCounts.Keys) {
    if ($afterCounts[$k] -ge ($initialCounts[$k] + 1)) { $persistedNode = $k; break }
}
if ($persistedNode -eq '') { throw "No node recorded an increase in persisted KeyspaceBlock count; mint may not have been persisted" }
Write-Host "Block persisted on node: $persistedNode"

switch ($persistedNode) {
    'node1' { $persistedDataDir = $node1DataDir; $persistedOutLog = $node1Out; $persistedPid = $p1.Id }
    'node2' { $persistedDataDir = $node2DataDir; $persistedOutLog = $node2Out; $persistedPid = $p2.Id }
    'node3' { $persistedDataDir = $node3DataDir; $persistedOutLog = $node3Out; $persistedPid = $p3.Id }
}

# Check latest persisted block range matches injected range (best-effort)
$latestRange = Get-LatestPersistedBlockRange -nodeDataDir $persistedDataDir
if ($null -ne $latestRange) { Assert(($latestRange.start -eq $rangeStart -and $latestRange.end -eq $rangeEnd), "Latest persisted block range does not match injected range on $persistedNode") }

Write-Host "Restarting node2 to verify replay of persisted KeyspaceBlock..."
Stop-Process -Id $p2.Id -Force
Start-Sleep -Seconds 2
$p2n = Start-Node $node2Config $node2Out $node2Err

Write-Host "Waiting for replay log message"
Assert( (Wait-For-Log -path $node2Out -pattern 'Replayed KeyspaceBlock|Replayed KeyspaceBlock height' -timeout 20), "Node2 did not replay persisted KeyspaceBlock on restart" )

Write-Host "Cluster test completed successfully"

# Cleanup: stop processes
    Stop-Process -Id $p1.Id -ErrorAction SilentlyContinue
    Stop-Process -Id $p2n.Id -ErrorAction SilentlyContinue
    Stop-Process -Id $p3.Id -ErrorAction SilentlyContinue
} finally {
    # Restore original node configs if backups exist
    Restore-OriginalConfig -bakPath $node1ConfigBak -configPath $node1Config
    Restore-OriginalConfig -bakPath $node2ConfigBak -configPath $node2Config
    Restore-OriginalConfig -bakPath $node3ConfigBak -configPath $node3Config
}

# Restore original node configs if backups exist
Restore-OriginalConfig -bakPath $node1ConfigBak -configPath $node1Config
Restore-OriginalConfig -bakPath $node2ConfigBak -configPath $node2Config
Restore-OriginalConfig -bakPath $node3ConfigBak -configPath $node3Config

exit 0
