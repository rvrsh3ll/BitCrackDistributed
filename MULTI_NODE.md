# Running Two Nodes

## Node 1 (Coordinator)
```powershell
cd build_vs2022
Copy-Item ..\config.json config.json -Force
.\bitcrack-distributed.exe --console
```

Then in Node 1 console:
```
setreward 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
start
```

## Node 2 (Worker)
Open a second terminal:
```powershell
cd build_vs2022
mkdir node2 -ErrorAction SilentlyContinue
cd node2
Copy-Item ..\bitcrack-distributed.exe .
Copy-Item ..\config.json config.json
.\bitcrack-distributed.exe --console
```

Then in Node 2 console:
```
setreward 1YourBitcoinAddressHere
start
```

Node 2 will:
 - Connect to Node 1 at 127.0.0.1:3338
- Request work automatically
- Receive 256-bit work chunks
- Report completion and request more

## Verify Connection
In either console, type:
```
peers
```

You should see the other node listed.

## Key Differences
- **Node 1**: Port 3338, no bootstrap (coordinator)
- **Node 2**: Port 8335, bootstraps to 127.0.0.1:3338 (worker)
