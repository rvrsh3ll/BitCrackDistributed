param($port,$peer_alias)

$client = New-Object System.Net.Sockets.TcpClient('127.0.0.1',$port)
$stream = $client.GetStream()
$writer = New-Object System.IO.StreamWriter($stream)
$writer.AutoFlush = $true
$writer.WriteLine("HELLO:$peer_alias")
Start-Sleep -Milliseconds 50
$cid = [guid]::NewGuid().ToString()
$injectedAt = (Get-Date).ToString('o')
$payload = @{range_start='400000000000000000'; range_end='400000000000007F'; keys_processed=128; peer_id=$peer_alias; correlation_id=$cid; injected_at=$injectedAt } | ConvertTo-Json -Compress
$writer.WriteLine("COMMIT:$payload")
$writer.Close()
$client.Close()
Write-Host "Injected to $port as $peer_alias"
