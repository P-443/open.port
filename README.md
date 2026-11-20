# SSH over 443 on Windows — Pure Windows & .NET (No Docker / No External Tools)

Complete native Windows implementation of the original Linux `Run.sh` tunneling script. Everything is powered solely by native Windows components: **Built-in Windows OpenSSH Server + C# .NET runtime**.

---

## 1. Quick Install (One-Line Command)

Open **PowerShell as Administrator** and paste the following line (pulls directly from the `neteg` branch):

```powershell
[Net.ServicePointManager]::SecurityProtocol='Tls12'; $b='https://raw.githubusercontent.com/P-443/open.port/neteg'; $d=Join-Path $env:ProgramData 'open.port'; New-Item $d -ItemType Directory -Force | Out-Null; 'Run.ps1','Tunnel443.ps1','Stop-Tunnel.ps1' | %{ iwr "$b/$_" -OutFile (Join-Path $d $_) -UseBasicParsing }; & (Join-Path $d 'Run.ps1')
```

### What this one-liner does:
1. Downloads the 3 required scripts (`Run.ps1`, `Tunnel443.ps1`, `Stop-Tunnel.ps1`) into `C:\ProgramData\open.port`.
2. Automatically installs and enables the built-in Windows OpenSSH Server feature.
3. Automatically repairs servicing services (Windows Update / TrustedInstaller) if disabled on stripped/custom Windows builds.
4. Generates standard 2048-bit RSA / ECDSA / ED25519 host keys and self-signed TLS certificates.
5. Configures TCP forwarding, UDP gateway (`udpgw`), firewall rules, and creates a background startup Scheduled Task (`SSH443-Tunnel`).
6. Prompts you interactively for username, password, and port (defaults: `telegram` / `@d_s_d_c1` / `443`).

---

## 2. Manual Installation & Arguments

If you have already cloned or downloaded the files locally:

```powershell
cd C:\ProgramData\open.port
powershell -ExecutionPolicy Bypass -File .\Run.ps1
```

### Non-Interactive One-Liner with Custom Parameters:

```powershell
powershell -ExecutionPolicy Bypass -File .\Run.ps1 -User myuser -Pass 'MySecurePass123' -Port 443
```

### Available Parameters:
| Parameter | Default | Description |
|---|---|---|
| `-User` | `telegram` | Local SSH username created by the script |
| `-Pass` | `@d_s_d_c1` | Password for the SSH user |
| `-Port` | `443` | Public TLS/SSH tunnel port |
| `-SshPort` | `22` | Internal OpenSSH Server port |
| `-UdpGwPort` | `7300` | Port for the badvpn-compatible UDP gateway (`0` to disable) |
| `-SniHost` | `$User` | Domain name to include in the self-signed TLS certificate |
| `-BindIp` | auto | Physical NIC IP to bind sshd + the 443 listener + UDP sockets to (auto-detected if omitted) |
| `-NoUdpgw` | `False` | Switch to disable the UDP gateway completely |

---

## 3. Client Configuration (NetMod / HTTP Custom / HTTP Injector / v2rayN)

| Setting | Value |
|---|---|
| **Host / IP** | Server IP address. On the **same PC** use the `Local NIC IP` printed by `Run.ps1` (e.g. `192.168.1.25`), **not** `127.0.0.1` and **not** the VPN/TUN address |
| **Port** | `443` (or the port specified in `-Port`) |
| **Protocol** | SSH |
| **TLS / SSL** | **ON** (SNI: any domain, e.g. `telegram` or your chosen SNI) |
| **SSL Certificate** | Enable **Allow Insecure / Trust All Certificates** (Self-Signed) |
| **Username / Password** | Your configured SSH credentials |
| **UDPGW / UDP Port** | `7300` (for games, VoIP, and DNS over UDP) |

> **Note:** The tunnel listener automatically auto-detects incoming packets: if the first byte is `0x16` it initiates a TLS handshake; otherwise, it passes plain SSH traffic transparently.

---

## 4. Connecting from the Same PC (NetMod Localhost Setup & "No Internet" Fix)

If you are running this server on your Windows PC and connecting to it using **NetMod PC** on the **same machine** (`127.0.0.1` / `localhost`), you might encounter a situation where **NetMod says "Connected", but websites do not load ("No Internet")**.

### Why does this happen? (The TUN Routing Loop)
When you enable **TUN Mode** in NetMod:
1. NetMod creates a virtual network adapter (Wintun) and rewrites the Windows default route (`0.0.0.0/0`) so that all system internet traffic is forced into the TUN adapter.
2. NetMod routes your application traffic through the local SSH tunnel to `sshd.exe`.
3. `sshd.exe` tries to open an outbound TCP connection to the destination website on the internet (e.g. `google.com`).
4. **Because the default route was changed to the TUN adapter, Windows routes `sshd.exe`'s outbound packets right back into the TUN adapter!**
5. This creates an **infinite recursive loop**: packets never reach your real router or network card.

### How to Fix It:

#### Option 0 (v1.5+): The script pins the SSH service to the physical NIC - automatic
`Run.ps1` now detects the real Wi-Fi/Ethernet card (it skips TAP/Wintun/NetMod/VPN/Hyper-V/WSL adapters) and:
- writes `ListenAddress 127.0.0.1` + `ListenAddress <physical-IP>` into `sshd_config` (sshd never listens on the TUN adapter),
- binds the TLS listener on port 443 to that same IP instead of `0.0.0.0`,
- binds the outbound UDP-gateway sockets to that IP as well,
- adds a persistent `/32` route so traffic to your own NIC IP always stays on the physical card,
- prints the IP at the end. **Use that printed `Local NIC IP` as the Host in NetMod** (not `127.0.0.1`, not the TUN address).

You can force a specific card with `-BindIp 192.168.1.25`. The value is stored in
`C:\ProgramData\ssh443\primary-ip.txt` so the SYSTEM scheduled task uses it at boot.

> Note: Windows still chooses the route for *outbound connections opened by `sshd.exe`*
> by destination, not by process. The listener/bind fix above removes the listener-side
> loop; if your VPN client still captures `sshd.exe`'s own upstream sockets, add the
> process bypass below (Option 2) or use System Proxy (Option 1).

#### Option 1: Use "System Proxy" Mode in NetMod (Instant)
- Inside NetMod PC, switch the connection mode from **TUN Mode** to **System Proxy Mode**.
- In System Proxy mode, NetMod exposes a local SOCKS5/HTTP proxy (usually `127.0.0.1:1080`) and sets Windows proxy settings without hijacking the network adapter default route.
- `sshd.exe` connects out to the real internet directly through your physical Wi-Fi/Ethernet adapter without looping. Everything will load immediately.

#### Option 2: Use TUN Mode with Process-Level Bypass
- If you require TUN Mode (e.g., for applications or games that do not support SOCKS proxies):
- Go to **NetMod Settings -> Routing / Rules**.
- Add a **Direct (Bypass)** rule for `sshd.exe` and `powershell.exe`.
- This tells NetMod's routing engine: *"Do not capture traffic from `sshd.exe`; send it directly through the physical network gateway."*

#### Option 3: Local Network Requirements
- An SSH tunnel forwards through the host machine's active network connection. If you are looking for free internet / SNI bug bypassing without an active internet quota, the SSH server must run on an **external VPS** that has full internet connectivity. A local server on `127.0.0.1` shares the local machine's existing connection.

---

## 5. UDP Gateway (`badvpn-udpgw` Protocol)

- **Protocol**: Exact implementation of `badvpn udpgw` packet protocol (2-byte little-endian length prefix).
- **Default bind**: `127.0.0.1:7300` (accessible safely through the SSH tunnel).
- **DNS Handling**: Resolves DNS via Windows client DNS (falls back to `1.1.1.1`).
- **Winsock Stability Fix**: Automatically handles Windows `SIO_UDP_CONNRESET` and suppresses error `10054` so ICMP Port Unreachable packets never terminate the UDP receive loop.

---

## 6. Service Management & Troubleshooting

### Check Service Status:
```powershell
# Check scheduled background task
Get-ScheduledTask SSH443-Tunnel | Select-Object TaskName, State

# Check active listeners
Get-NetTCPConnection -LocalPort 443, 7300, 22 -State Listen

# Live tail tunnel logs
Get-Content C:\ProgramData\ssh443\tunnel.log -Tail 30 -Wait
```

### Stop / Restart Tunnel:
```powershell
# Stop tunnel service
powershell -File .\Stop-Tunnel.ps1

# Start tunnel service
Start-ScheduledTask SSH443-Tunnel
```

### Complete Uninstallation:
```powershell
# Removes scheduled task, firewall rules, TLS certificate, and banner
powershell -File .\Stop-Tunnel.ps1 -Uninstall

# Removes everything AND deletes the created SSH user
powershell -File .\Stop-Tunnel.ps1 -Uninstall -RemoveUser -User telegram
```

### Log File Locations:
- `C:\ProgramData\ssh443\tunnel.log` — Tunnel activity (connections, TLS handshakes, errors).
- `C:\ProgramData\ssh\logs\sshd.log` — OpenSSH server debug log (`SyslogFacility LOCAL0`).
- `C:\ProgramData\ssh443\setup-*.log` — Detailed installation log.

---

## 7. Linux `Run.sh` vs. Windows Native Architecture

| Linux Component (`Run.sh`) | Role | Windows Equivalent |
|---|---|---|
| `apt` / `dnf` / `pacman` | Package management | Windows Capabilities / Win32-OpenSSH fallback |
| `python3` + `udocker` | Run container unprivileged | ❌ Not needed |
| `dweomer/stunnel` | Port 443 TLS -> Port 22 SSH | ✅ `Tunnel443.ps1` (.NET TLS / TCP listener) |
| `openssh-server` + `systemd` | SSH Server & background daemon | ✅ Built-in `OpenSSH.Server` + Windows `sshd` service |
| `adduser` + `chpasswd` | SSH user credentials | ✅ `New-LocalUser` / `Set-LocalUser` |
| `/etc/ssh/sshd_config` + banner | SSH banner and configuration | ✅ `C:\ProgramData\ssh\sshd_config` + `banner.txt` |
| `badvpn udpgw` (Go build) | UDP gateway on port 7300 | ✅ Built-in C# `UdpGw` class with little-endian framing |
| `sysctl net.core.*` | Network performance tuning | ✅ `netsh int tcp set global ...` |

---

## 8. License & Credits

- Original Linux Script: `telegram: @d_s_d_c1` / `l_s_I_I.t.me`
- Windows Pure .NET Port & Enhancements: Branch `neteg`
