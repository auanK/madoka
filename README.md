# Madoka

> **Status:** Under active development.

Zero-configuration encrypted peer-to-peer mesh network with cryptographic identity and virtual IPv6 addressing.

## Build

```bash
cmake -B build
cmake --build build
```

## Automated Tests

```bash
ctest --test-dir build --output-on-failure
```

## Manual Testing (2 Local Nodes)

### Terminal 1 — Start Node 1
```powershell
$env:MADOKA_STATE_DIR = "$env:TEMP\node1"; $env:MADOKA_MOCK_TUN = "1"
.\build\madoka.exe --listen 127.0.0.1:9001
```

### Terminal 2 — Generate Invite and Join Node 2
```powershell
# Generate invite on Node 1
$env:MADOKA_STATE_DIR = "$env:TEMP\node1"
$token = (.\build\madoka.exe invite)

# Join Node 2 using the invitation token
$env:MADOKA_STATE_DIR = "$env:TEMP\node2"; $env:MADOKA_MOCK_TUN = "1"
.\build\madoka.exe join $token --listen 127.0.0.1:9002
```

### Terminal 3 — Check Status
```powershell
$env:MADOKA_STATE_DIR = "$env:TEMP\node1"
.\build\madoka.exe status
```
