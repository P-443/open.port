#requires -Version 5.1
<#
    Run.ps1  -  Windows port of "Run.sh"  (SSH over port 443, no Docker, no extra programs)
    ==============================================================================
    Linux original used:  apt + python3-venv + udocker + stunnel image + Go(udpgw)
    Windows version uses: Windows OpenSSH Server (built-in) + .NET TLS listener
    ==============================================================================
    What it does:
      1. enables and starts the built-in OpenSSH Server
      2. creates the SSH user / password
      3. adds an SSH banner
      4. creates a self-signed certificate
      5. detects the physical (primary) NIC and binds sshd + the TLS listener to it
      6. starts a TLS listener on <Port> that forwards to 127.0.0.1:<SshPort>
      7. starts a badvpn-compatible UDP gateway on 127.0.0.1:<UdpGwPort> (UDP over the tunnel)
      8. adds firewall rules, registers a start-up scheduled task, tunes TCP
    Must be run as Administrator.

    Why the primary NIC binding matters (NetMod / any TUN-mode VPN on the same PC):
    a TUN adapter rewrites 0.0.0.0/0. If sshd and the TLS listener sit on 0.0.0.0,
    the VPN captures their packets and feeds them straight back into the tunnel ->
    infinite loop and "connected but no internet". By listening only on the real
    card (plus 127.0.0.1 for the local TLS -> SSH hop), the TUN adapter is never a
    listener and the client always reaches the server through the physical card.
#>

[CmdletBinding()]
param(
    [string] $User         = '',
    [string] $Pass         = '',
    [int]    $Port         = 0,
    [int]    $SshPort      = 22,
    [int]    $UdpGwPort    = 7300,
    [switch] $NoUdpgw,
    [string] $SniHost      = '',
    [string] $CertSubject  = 'CN=ssh443-tunnel',
    [string] $BindIp       = ''
)

$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }
# outbound HTTPS (ipinfo / github) needs TLS 1.2 on older images, and the
# progress bar makes Invoke-WebRequest crawl
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }
$ProgressPreference = 'SilentlyContinue'
$TaskName   = 'SSH443-Tunnel'
$RootDir    = Split-Path -Parent $MyInvocation.MyCommand.Path
$WorkDir    = Join-Path $env:ProgramData 'ssh443'
$LogFile    = Join-Path $WorkDir 'tunnel.log'
$SetupLog   = Join-Path $WorkDir 'setup.log'
# Windows build version - its own counter, bumped on every change (1.0 -> 1.1 -> ...)
$WinVer     = '1.9'

function Write-Step   ($m) { Write-Host "  [*] $m" -ForegroundColor Cyan }
function Write-Ok     ($m) { Write-Host "  [v] $m" -ForegroundColor Green }
function Write-Warn2  ($m) { Write-Host "  [!] $m" -ForegroundColor Yellow }
function Write-Err2   ($m) { Write-Host "  [x] $m" -ForegroundColor Red }

# ------------------------------------------------------------------ header
$line = '#' * 74
Write-Host ""
Write-Host $line -ForegroundColor Green
Write-Host "#        SSH over port 443 on Windows  ( no docker / no extra tools )       #" -ForegroundColor Red
$hdrText = 'Windows port of Run.sh  v' + $WinVer
$hdrLp   = [math]::Floor((74 - $hdrText.Length) / 2)
Write-Host ('#' + (' ' * $hdrLp) + $hdrText + (' ' * (74 - $hdrText.Length - $hdrLp)) + '#') -ForegroundColor Green
Write-Host $line -ForegroundColor Green
Write-Host ""

# ------------------------------------------------------------------ admin check
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Err2 'This script must be run as Administrator.'; exit 1 }

if (-not (Test-Path $WorkDir)) { New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null }
Start-Transcript -Path (Join-Path $WorkDir ("setup-" + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.log')) -Force | Out-Null

# ------------------------------------------------------------------ inputs
if (-not $User) { $i = Read-Host '  Enter User (default: telegram)'; $User = if ([string]::IsNullOrWhiteSpace($i)) { 'telegram' } else { $i.Trim() } }
if (-not $Pass) { $i = Read-Host '  Enter Pass (default: @d_s_d_c1)'; $Pass = if ([string]::IsNullOrWhiteSpace($i)) { '@d_s_d_c1' } else { $i } }
if ($Port -le 0) {
    $i = Read-Host '  Enter Port (default: 443)'
    $Port = if ([string]::IsNullOrWhiteSpace($i)) { 443 } else { [int]$i.Trim() }
}
if (-not $SniHost) { $SniHost = $User }
if ($NoUdpgw) { $UdpGwPort = 0 }

# ------------------------------------------------------------------ primary NIC
# The SSH service must live on the real internet card, never on a VPN/TUN adapter.
function Get-PrimaryNic {
    $virtualPattern = '(?i)(TAP|Wintun|NetMod|VPN|Tunnel|Virtual|Hyper-V|vEthernet|VMware|VirtualBox|WSL|WireGuard|OpenVPN|Loopback|WAN Miniport)'
    $cands = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {
        $_.IPAddress -notlike '127.*' -and
        $_.IPAddress -notlike '169.254.*' -and
        $_.PrefixLength -gt 0 -and
        $_.InterfaceAlias -notmatch $virtualPattern
    })
    if ($cands.Count -eq 0) { return $null }
    $routes = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
                Where-Object { $_.NextHop -and $_.NextHop -ne '0.0.0.0' -and $_.InterfaceIndex -gt 0 })
    $best = $null; $bestScore = [int]::MaxValue
    foreach ($c in $cands) {
        $r = $routes | Where-Object { $_.InterfaceIndex -eq $c.InterfaceIndex } | Sort-Object RouteMetric | Select-Object -First 1
        $score = if ($r) { [int]$r.RouteMetric } else { 1000 }
        $adapter = Get-NetAdapter -InterfaceIndex $c.InterfaceIndex -ErrorAction SilentlyContinue
        if ($adapter -and $adapter.Status -ne 'Up') { $score += 5000 }
        if ($score -lt $bestScore) {
            $bestScore = $score
            $best = [pscustomobject]@{
                IP    = $c.IPAddress
                Index = $c.InterfaceIndex
                Alias = $c.InterfaceAlias
                GW    = $(if ($r) { $r.NextHop } else { '' })
            }
        }
    }
    return $best
}

# Persist the resolver/gateway from the SAME physical NIC. Reading DNS after the
# TUN client is connected returns the VPN adapter (10.4.2.2) and sends UDP/DNS
# straight back into the tunnel - the "server doesn't support UDP" failure.
function Get-PhysicalDns {
    param([int]$InterfaceIndex)
    try {
        $d = Get-DnsClientServerAddress -InterfaceIndex $InterfaceIndex -AddressFamily IPv4 `
                 -ErrorAction SilentlyContinue |
             Where-Object { $_.ServerAddresses -and $_.ServerAddresses.Count -gt 0 } |
             Select-Object -First 1
        if ($d) {
            @($d.ServerAddresses | Where-Object { $_ -and $_ -notlike '127.*' })
        }
    } catch { }
    return @()
}

function Add-SameHostRoute {
    param([string]$Prefix, [int]$IfIndex, [string]$NextHop, [string]$StateFile)
    $wantHop = if ($NextHop) { $NextHop } else { '0.0.0.0' }
    $existing = @(Get-NetRoute -DestinationPrefix $Prefix -InterfaceIndex $IfIndex -ErrorAction SilentlyContinue)
    $ok = @($existing | Where-Object { $_.NextHop -eq $wantHop -and [int]$_.RouteMetric -le 1 })
    if ($ok.Count -gt 0) { return $false }
    try {
        if ($NextHop) {
            New-NetRoute -DestinationPrefix $Prefix -InterfaceIndex $IfIndex `
                -NextHop $NextHop -RouteMetric 1 -ErrorAction Stop | Out-Null
        } else {
            New-NetRoute -DestinationPrefix $Prefix -InterfaceIndex $IfIndex `
                -RouteMetric 1 -ErrorAction Stop | Out-Null
        }
        $line = "$Prefix|$IfIndex|$wantHop"
        $have = @()
        if (Test-Path $StateFile) { $have = @(Get-Content -LiteralPath $StateFile -ErrorAction SilentlyContinue) }
        if ($have -notcontains $line) { Add-Content -LiteralPath $StateFile -Value $line -Encoding ASCII }
        return $true
    } catch {
        Write-Warn2 "could not pin route $Prefix -> ifIndex $IfIndex : $($_.Exception.Message)"
        return $false
    }
}

if ($BindIp) {
    $a = Get-NetIPAddress -AddressFamily IPv4 -IPAddress $BindIp -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($a) {
        $primaryNic = [pscustomobject]@{ IP = $BindIp; Index = $a.InterfaceIndex; Alias = $a.InterfaceAlias; GW = '' }
    } else {
        Write-Warn2 "BindIp $BindIp was not found on a local adapter - binding anyway"
        $primaryNic = [pscustomobject]@{ IP = $BindIp; Index = 0; Alias = ''; GW = '' }
    }
} else {
    $primaryNic = Get-PrimaryNic
}
if (-not $primaryNic) {
    Write-Warn2 'No physical NIC detected - falling back to 0.0.0.0 (TUN loop protection disabled)'
    $primaryNic = [pscustomobject]@{ IP = '0.0.0.0'; Index = 0; Alias = ''; GW = '' }
}
$BindIp = $primaryNic.IP
Write-Ok "Primary NIC : $($primaryNic.Alias)  $BindIp  (ifIndex $($primaryNic.Index), gw $($primaryNic.GW))"

# Tunnel443.ps1 runs as SYSTEM at boot, so persist the whole NIC choice next to
# its log. Line 1 stays the IP for backwards compatibility with older scripts.
$nicFile     = Join-Path $WorkDir 'primary-ip.txt'
$RouteState  = Join-Path $WorkDir 'samehost-routes.txt'
$Gateway     = if ($primaryNic.GW) { [string]$primaryNic.GW } else { '' }
$DnsServers  = @(Get-PhysicalDns $primaryNic.Index)
if ($DnsServers.Count -eq 0) { $DnsServers = @('1.1.1.1') }
$DnsCsv      = $DnsServers -join ','
@($BindIp, "$($primaryNic.Index)", $Gateway, $DnsCsv) | Set-Content -LiteralPath $nicFile -Encoding ASCII
if (-not (Test-Path $RouteState)) { New-Item -ItemType File -Force -Path $RouteState | Out-Null }
Write-Ok "Physical DNS  : $DnsCsv  (persisted - not re-read from the TUN adapter)"

if ($primaryNic.Index -gt 0 -and $BindIp -ne '0.0.0.0') {
    # /32 exceptions beat NetMod's 0.0.0.0/1 and 128.0.0.0/1 routes. They are
    # re-asserted by Tunnel443.ps1's route guard while the TUN client is up.
    $changed = 0
    if (Add-SameHostRoute "$BindIp/32" $primaryNic.Index '' $RouteState) { $changed++ }
    if ($Gateway -and (Add-SameHostRoute "$Gateway/32" $primaryNic.Index '' $RouteState)) { $changed++ }
    foreach ($dns in $DnsServers) {
        if ($dns -eq $BindIp -or $dns -eq $Gateway) { continue }
        if (Add-SameHostRoute "$dns/32" $primaryNic.Index $Gateway $RouteState) { $changed++ }
    }
    Write-Ok "Route pins    : $changed added/changed (state: $RouteState)"
}

# ------------------------------------------------------------------ sshd NIC shim (v1.9)
# OpenSSH forks a NEW sshd.exe for every connection.  Those children open the
# outbound sockets used by SOCKS / direct-tcpip and would follow the client's
# TUN default route straight back into this tunnel (recursive loop -> no net).
# bindnic.dll v3 suspends each child, injects before its first socket, then
# resumes it; no first-packet race remains.
# Downloaded from neteg here so the ORIGINAL one-line installer (which only
# fetches the three .ps1 files) continues to work unchanged.
$NativeDir  = Join-Path $RootDir 'native'
if (-not (Test-Path $NativeDir)) { New-Item -ItemType Directory -Force -Path $NativeDir | Out-Null }
# The injected DLL also runs as the unprivileged SSH user. Grant Users write on
# this folder so bindnic.log is always written next to the DLL (no silent loss).
try { & icacls.exe $NativeDir /grant '*S-1-5-32-545:(OI)(CI)M' /T 2>&1 | Out-Null } catch { }
$BindNicDll = Join-Path $NativeDir 'bindnic.dll'
$InjectExe  = Join-Path $NativeDir 'inject.exe'
$BindNicLog = Join-Path $NativeDir 'bindnic.log'
# Use the refs/heads path: the short branch URL is served by a CDN that can keep
# returning an older native binary for a while after a push.
$RawBase    = 'https://raw.githubusercontent.com/P-443/open.port/refs/heads/neteg/native'
foreach ($n in 'bindnic.dll','inject.exe') {
    $dst = Join-Path $NativeDir $n
    try {
        Invoke-WebRequest -Uri "$RawBase/$n" -OutFile $dst -UseBasicParsing -TimeoutSec 60
        Write-Ok "Downloaded native/$n"
    } catch {
        if (Test-Path $dst) { Write-Warn2 "Could not refresh $n - using cached copy" }
        else { Write-Warn2 "Could not download $n : $($_.Exception.Message)" }
    }
}
if (Test-Path $BindNicDll) {
    $cfg = Join-Path $NativeDir 'bindnic.cfg'
    @($BindIp, "$($primaryNic.Index)", $BindNicLog) | Set-Content -LiteralPath $cfg -Encoding ASCII
    Write-Ok "sshd binder config : bind=$BindIp if=$($primaryNic.Index) log=$BindNicLog"
    # Immediate injection into the already running sshd service.  The SYSTEM
    # tunnel keeper takes care of the per-connection children from then on.
    if (Test-Path $InjectExe) {
        Get-Process sshd -ErrorAction SilentlyContinue | ForEach-Object {
            & $InjectExe $_.Id $BindNicDll 2>&1 | Out-Null
        }
    }
} else {
    Write-Warn2 'sshd NIC shim unavailable - TUN loop protection OFF'
}

Write-Host ""
Write-Host "  ------------------------------------------------------------------"
Write-Ok "Input accepted : User=$User  Pass=$Pass  Port=$Port  (pass length: $($Pass.Length))"
Write-Host "  ------------------------------------------------------------------"
Write-Host ""

# ------------------------------------------------------------------ 1. OpenSSH server
Write-Step 'OpenSSH Server : checking'

# --- helpers -------------------------------------------------------------
# A fresh or "tweaked" Windows VPS often has the Windows Update / Windows
# Modules Installer service set to Disabled.  Get-WindowsCapability then fails
# with 0x80070422 ("The service cannot be started ... it is disabled") even
# though it is only a *query*.  Because $ErrorActionPreference is 'Stop' that
# used to kill the whole script on the very first step.  So everything below:
#   * short-circuits when OpenSSH is already on disk,
#   * wraps every DISM call in try/catch so it can never abort the script,
#   * repairs the servicing services and retries once,
#   * and, as a last resort, installs the official Win32-OpenSSH package
#     (that path does not use DISM / Windows Update at all).
function Test-SshdPresent {
    (Test-Path (Join-Path $env:WINDIR 'System32\OpenSSH\sshd.exe')) -or
    (Test-Path (Join-Path $env:ProgramFiles 'OpenSSH\sshd.exe'))
}
function Get-SshdDir {
    if (Test-Path (Join-Path $env:WINDIR 'System32\OpenSSH\sshd.exe')) { return (Join-Path $env:WINDIR 'System32\OpenSSH') }
    if (Test-Path (Join-Path $env:ProgramFiles 'OpenSSH\sshd.exe'))     { return (Join-Path $env:ProgramFiles 'OpenSSH') }
    return (Join-Path $env:WINDIR 'System32\OpenSSH')
}
function Repair-ServicingServices {
    foreach ($n in 'wuauserv', 'TrustedInstaller', 'msiserver', 'UsoSvc', 'BITS') {
        try {
            $svc = Get-Service -Name $n -ErrorAction Stop
            if ($svc.StartType -eq 'Disabled') {
                Write-Warn2 "servicing service '$n' is Disabled -> switching it to Manual"
                Set-Service -Name $n -StartupType Manual -ErrorAction Stop
            }
        } catch { }
    }
}
function Add-OpenSshCapability {
    try {
        $cap = Get-WindowsCapability -Online -Name 'OpenSSH.Server*' -ErrorAction Stop | Select-Object -First 1
        if ($cap -and $cap.State -eq 'Installed') { return $true }
        Write-Step 'OpenSSH Server : installing (Windows capability)'
        Add-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0' -ErrorAction Stop | Out-Null
        return (Test-SshdPresent)
    } catch {
        Write-Warn2 "OpenSSH Server : capability path failed - $($_.Exception.Message)"
        return $false
    }
}
function Install-OpenSshFromGitHub {
    try {
        Write-Step 'OpenSSH Server : downloading the official Win32-OpenSSH package'
        $rel   = Invoke-RestMethod -Uri 'https://api.github.com/repos/PowerShell/Win32-OpenSSH/releases/latest' -TimeoutSec 30 -UseBasicParsing
        $asset = $rel.assets | Where-Object { $_.name -eq 'OpenSSH-Win64.zip' } | Select-Object -First 1
        if (-not $asset) { Write-Warn2 'OpenSSH Server : release asset not found'; return $false }
        $zip = Join-Path $env:TEMP 'OpenSSH-Win64.zip'
        Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $zip -UseBasicParsing -TimeoutSec 180
        Expand-Archive -Path $zip -DestinationPath $env:TEMP -Force
        $dst = Join-Path $env:ProgramFiles 'OpenSSH'
        Remove-Item $dst -Recurse -Force -ErrorAction SilentlyContinue
        Move-Item (Join-Path $env:TEMP 'OpenSSH-Win64') $dst -Force
        $install = Join-Path $dst 'install-sshd.ps1'
        if (Test-Path $install) { & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $install | Out-Null }
        $keygen = Join-Path $dst 'ssh-keygen.exe'
        if (Test-Path $keygen) { & $keygen -A | Out-Null }
        if (-not (Get-Service sshd -ErrorAction SilentlyContinue)) {
            New-Service -Name sshd -BinaryPathName "`"$dst\sshd.exe`"" -DisplayName 'OpenSSH SSH Server' -StartupType Automatic | Out-Null
        }
        Set-Service -Name sshd -StartupType Automatic -ErrorAction SilentlyContinue
        return (Test-SshdPresent)
    } catch {
        Write-Warn2 "OpenSSH Server : Win32-OpenSSH fallback failed - $($_.Exception.Message)"
        return $false
    }
}

if (-not (Test-SshdPresent)) {
    [void](Add-OpenSshCapability)
    if (-not (Test-SshdPresent)) {
        Write-Warn2 'OpenSSH Server : repairing the servicing services then retrying'
        Repair-ServicingServices
        Start-Service wuauserv -ErrorAction SilentlyContinue
        [void](Add-OpenSshCapability)
    }
    if (-not (Test-SshdPresent)) { [void](Install-OpenSshFromGitHub) }
}

if (-not (Test-SshdPresent)) {
    Write-Err2 'OpenSSH Server could not be installed automatically.'
    Write-Err2 'Enable it manually (Settings > Optional Features > OpenSSH Server), then re-run this script.'
    exit 1
}
$OpenSshDir = Get-SshdDir
$sshdExe    = Join-Path $OpenSshDir 'sshd.exe'
$keygenExe  = Join-Path $OpenSshDir 'ssh-keygen.exe'
Write-Ok "OpenSSH Server : binaries -> $OpenSshDir"

# make sure the sshd service exists AND points at the binary we just installed.
# A leftover service from an older/partial install can point at a path that no
# longer exists -> "Failed to start service 'OpenSSH SSH Server (sshd)'".
try {
    $svc = Get-CimInstance Win32_Service -Filter "Name='sshd'" -ErrorAction SilentlyContinue
    if (-not $svc) {
        New-Service -Name sshd -BinaryPathName "`"$sshdExe`"" -DisplayName 'OpenSSH SSH Server' -StartupType Automatic | Out-Null
        Write-Step 'OpenSSH Server : created the sshd service'
    } elseif ($svc.PathName -and ($svc.PathName -notlike "*$OpenSshDir*")) {
        Write-Warn2 "sshd service pointed at '$($svc.PathName)' - repointing it to $sshdExe"
        & sc.exe config sshd binPath= "`"$sshdExe`"" | Out-Null
    }
} catch { Write-Warn2 "could not verify the sshd service : $($_.Exception.Message)" }
try { Set-Service -Name sshd -StartupType Automatic -ErrorAction Stop } catch { }

$sshDir  = Join-Path $env:ProgramData 'ssh'
if (-not (Test-Path $sshDir)) { New-Item -ItemType Directory -Force -Path $sshDir | Out-Null }
$sshLogs = Join-Path $sshDir 'logs'
if (-not (Test-Path $sshLogs)) { New-Item -ItemType Directory -Force -Path $sshLogs | Out-Null }

# the shipped sshd_config contains:  AllowGroups administrators "openssh users"
# The "OpenSSH Users" group (S-1-5-32-585) ships with the OpenSSH *capability*,
# but the Win32-OpenSSH zip does not create it - and sshd refuses to start when
# an AllowGroups entry cannot be resolved.  Create it *before* sshd starts.
if (-not (Get-LocalGroup -Name 'openssh users' -ErrorAction SilentlyContinue)) {
    try { New-LocalGroup -Name 'openssh users' -Description 'OpenSSH login users' | Out-Null; Write-Step "OpenSSH Server : created local group 'openssh users'" } catch { }
}

# --- pick a free internal SSH port ---------------------------------------
# A fresh cloud image can already have something bound to port 22 (provider
# agent, a second sshd, ...).  sshd would then fail to start and the 443 tunnel
# would forward to the wrong service.  Detect that and move to a free port.
function Get-PortOwner([int]$p) {
    $c = Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $c) { return $null }
    return (Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue)
}
$owner = Get-PortOwner $SshPort
if ($owner -and $owner.ProcessName -ne 'sshd') {
    Write-Warn2 "internal port $SshPort is used by '$($owner.ProcessName)' (pid $($owner.Id)) - moving sshd to a free port"
    foreach ($cand in 2222, 22222, 2200, 2022, 8022, 22022, 4422, 22223) {
        if (-not (Get-PortOwner $cand)) { $SshPort = $cand; break }
    }
    Write-Ok "OpenSSH Server : sshd will listen on internal port $SshPort"
}

# --- host keys -----------------------------------------------------------
# Generated explicitly (one per type) instead of relying on "ssh-keygen -A":
# that is deterministic, verifiable, and any missing/empty key is repaired.
Write-Step 'OpenSSH Server : generating host keys'
$hostKeyDefs = @(
    @{ t = 'rsa';     f = 'ssh_host_rsa_key';     extra = @('-b', '3072') },
    @{ t = 'ecdsa';   f = 'ssh_host_ecdsa_key';   extra = @() },
    @{ t = 'ed25519'; f = 'ssh_host_ed25519_key'; extra = @() }
)
$hostKeyPaths = @()
foreach ($hk in $hostKeyDefs) {
    $kp = Join-Path $sshDir $hk.f
    $need = $true
    if (Test-Path $kp) { try { if ((Get-Item $kp).Length -gt 0) { $need = $false } } catch { } }
    if ($need) {
        Remove-Item $kp -Force -ErrorAction SilentlyContinue
        $kgArgs = @('-t', $hk.t) + $hk.extra + @('-f', $kp, '-N', '""', '-q')
        try { & $keygenExe @kgArgs 2>&1 | Out-Null } catch { }
        if ((-not (Test-Path $kp)) -or ((Get-Item $kp).Length -eq 0)) {
            # retry verbosely so the real error is visible instead of hidden
            $kgArgs = @('-t', $hk.t) + $hk.extra + @('-f', $kp, '-N', '""')
            try { & $keygenExe @kgArgs 2>&1 | ForEach-Object { Write-Host "      $_" -ForegroundColor DarkGray } } catch { }
        }
    }
    if (Test-Path $kp) { $hostKeyPaths += $kp }
}
if ($hostKeyPaths.Count -eq 0) { Write-Err2 'OpenSSH Server : no host keys could be created - sshd cannot start' }

# Windows sshd refuses to use host keys that any principal other than
# SYSTEM/Administrators can touch ("UNPROTECTED PRIVATE KEY FILE" / "no hostkeys
# available -- exiting").  ssh-keygen run from an admin console leaves an extra
# ACE for the calling user behind, so the ACL is rewritten explicitly.
function Repair-HostKeyAcl {
    param([string]$Path)
    try {
        $admins = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
        $system = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
        $acl = New-Object System.Security.AccessControl.FileSecurity
        $acl.SetOwner($admins)
        $acl.SetGroup($admins)
        $acl.SetAccessRuleProtection($true, $false)
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($system, 'FullControl', 'Allow')))
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($admins, 'FullControl', 'Allow')))
        Set-Acl -Path $Path -AclObject $acl
    } catch { Write-Warn2 "host key ACL not fixed for $Path : $($_.Exception.Message)" }
}
Get-ChildItem (Join-Path $sshDir 'ssh_host_*_key') -ErrorAction SilentlyContinue |
    ForEach-Object { Repair-HostKeyAcl $_.FullName }
Write-Ok 'OpenSSH Server : host key permissions secured'

$sshdConfig = Join-Path $sshDir 'sshd_config'
if (-not (Test-Path $sshdConfig)) {
    $def = Join-Path $OpenSshDir 'sshd_config_default'
    if (Test-Path $def) {
        Copy-Item $def $sshdConfig -Force
    } else {
        # minimal template; Set-SshdOption fills in everything else below
        Set-Content -LiteralPath $sshdConfig -Encoding ASCII -Value @(
            '# generated by Run.ps1',
            'Subsystem sftp sftp-server.exe'
        )
    }
    Write-Step "OpenSSH Server : created $sshdConfig"
}

function Set-SshdOption {
    # sshd_config on Windows ends with a "Match Group administrators" block.
    # Any directive placed after it would land inside the Match block, so the
    # value is inserted in the top level scope, just before the first Match.
    param([string]$Config, [string]$Name, [string]$Value)
    $esc = [regex]::Escape($Name)
    $out = New-Object System.Collections.Generic.List[string]
    $inserted = $false
    $inMatch  = $false
    foreach ($l in (Get-Content -LiteralPath $Config)) {
        if ($l -match '^\s*Match\s') {
            if (-not $inserted) { $out.Add("$Name $Value"); $inserted = $true }
            $inMatch = $true
        }
        if (-not $inMatch -and $l -match ("^\s*#?\s*" + $esc + "(\s|$)")) { continue }
        $out.Add($l)
    }
    if (-not $inserted) { $out.Add("$Name $Value") }
    Set-Content -LiteralPath $Config -Value $out -Encoding ASCII
}

function Set-SshdMultiOption {
    # like Set-SshdOption but the directive is written several times (HostKey)
    param([string]$Config, [string]$Name, [string[]]$Values)
    if (-not $Values -or $Values.Count -eq 0) { return }
    $esc = [regex]::Escape($Name)
    $out = New-Object System.Collections.Generic.List[string]
    $inserted = $false
    $inMatch  = $false
    foreach ($l in (Get-Content -LiteralPath $Config)) {
        if ($l -match '^\s*Match\s') {
            if (-not $inserted) { foreach ($v in $Values) { $out.Add("$Name $v") }; $inserted = $true }
            $inMatch = $true
        }
        if (-not $inMatch -and $l -match ("^\s*#?\s*" + $esc + "(\s|$)")) { continue }
        $out.Add($l)
    }
    if (-not $inserted) { foreach ($v in $Values) { $out.Add("$Name $v") } }
    Set-Content -LiteralPath $Config -Value $out -Encoding ASCII
}

function Remove-SshdOption {
    # drop a directive (and its commented form) from sshd_config.
    # NB: read into a variable first - piping Get-Content straight into
    # Set-Content on the SAME file fails with "being used by another process".
    param([string]$Config, [string]$Name)
    $esc  = [regex]::Escape($Name)
    $kept = @(Get-Content -LiteralPath $Config | Where-Object { $_ -notmatch ("^\s*#?\s*" + $esc + "(\s|$)") })
    Set-Content -LiteralPath $Config -Value $kept -Encoding ASCII
}

Set-SshdOption -Config $sshdConfig -Name 'Port'                       -Value $SshPort
Set-SshdOption -Config $sshdConfig -Name 'PasswordAuthentication'     -Value 'yes'
Set-SshdOption -Config $sshdConfig -Name 'PubkeyAuthentication'       -Value 'yes'
Set-SshdOption -Config $sshdConfig -Name 'PermitEmptyPasswords'       -Value 'no'
Set-SshdOption -Config $sshdConfig -Name 'AllowTcpForwarding'         -Value 'yes'
Set-SshdOption -Config $sshdConfig -Name 'GatewayPorts'               -Value 'yes'
Set-SshdOption -Config $sshdConfig -Name 'PermitTunnel'               -Value 'yes'
Set-SshdOption -Config $sshdConfig -Name 'AllowStreamLocalForwarding' -Value 'yes'
Set-SshdOption -Config $sshdConfig -Name 'DisableForwarding'          -Value 'no'
Set-SshdOption -Config $sshdConfig -Name 'TCPKeepAlive'               -Value 'yes'
# Listen ONLY on loopback (the local TLS -> SSH hop) and the physical NIC.
# A listener on the VPN/TUN adapter is what creates the recursive routing loop.
if ($BindIp -and $BindIp -ne '0.0.0.0') {
    Set-SshdMultiOption -Config $sshdConfig -Name 'ListenAddress' -Values @('127.0.0.1', $BindIp)
} else {
    Remove-SshdOption -Config $sshdConfig -Name 'ListenAddress'
}
Set-SshdOption -Config $sshdConfig -Name 'ClientAliveInterval'        -Value '30'
Set-SshdOption -Config $sshdConfig -Name 'ClientAliveCountMax'        -Value '6'
# readable sshd log next to the tunnel log (default would go to the event log only)
Set-SshdOption -Config $sshdConfig -Name 'SyslogFacility'         -Value 'LOCAL0'
# channel level logging: shows which host/port every client forward asked for
Set-SshdOption -Config $sshdConfig -Name 'LogLevel'               -Value 'DEBUG2'
Set-SshdOption -Config $sshdConfig -Name 'MaxStartups'            -Value '100:30:200'
Set-SshdOption -Config $sshdConfig -Name 'MaxSessions'            -Value '100'
# explicit host keys (absolute paths) so sshd never has to guess where they are
Set-SshdMultiOption -Config $sshdConfig -Name 'HostKey' -Values $hostKeyPaths
# Some Windows images ship a default config containing:
#     AllowGroups administrators "openssh users"
# sshd then denies EVERY local user that is not in one of those groups, and the
# client only sees "Password authentication failed" even when the password is
# correct.  The Linux original has no such restriction (the script creates a
# single dedicated user), so the gate is removed to guarantee login.
Remove-SshdOption -Config $sshdConfig -Name 'AllowGroups'

# Keep authorised keys in a fixed, per-user location under ProgramData instead of
# the user profile ("%USERPROFILE%\.ssh") - the profile of a fresh local account
# only exists after its first logon and Windows otherwise falls back to
# C:\Windows\.ssh.  Same pattern Microsoft uses for administrators_authorized_keys.
$akDir = Join-Path $sshDir 'authorized_keys'
if (-not (Test-Path $akDir)) { New-Item -ItemType Directory -Force -Path $akDir | Out-Null }
try {
    $adminsSid = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
    $systemSid = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
    $acl = New-Object System.Security.AccessControl.FileSecurity
    $acl.SetOwner($adminsSid); $acl.SetGroup($adminsSid)
    $acl.SetAccessRuleProtection($true, $false)
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($systemSid, 'FullControl', 'Allow')))
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($adminsSid, 'FullControl', 'Allow')))
    Set-Acl -Path $akDir -AclObject $acl
} catch { Write-Warn2 "authorized_keys folder ACL not set : $($_.Exception.Message)" }
Set-SshdOption -Config $sshdConfig -Name 'AuthorizedKeysFile' -Value '__PROGRAMDATA__/ssh/authorized_keys/%u'
Write-Ok "OpenSSH Server : per-user keys -> $akDir\%u"
Write-Ok "OpenSSH Server : sshd_config configured (port $SshPort, password auth on)"

try { $cfgTest = & $sshdExe -t -f $sshdConfig 2>&1 } catch { $cfgTest = $_.Exception.Message }
if ($cfgTest) { Write-Warn2 "sshd -t : $cfgTest" } else { Write-Ok 'sshd -t : config OK' }

function Start-SshdService {
    # (re)start the service and wait until it actually reaches "Running"
    try { Restart-Service sshd -Force -ErrorAction Stop } catch { }
    for ($i = 0; $i -lt 12; $i++) {
        $s = Get-Service sshd -ErrorAction SilentlyContinue
        if ($s -and $s.Status -eq 'Running') { return $true }
        Start-Sleep -Milliseconds 500
    }
    try { Start-Service sshd -ErrorAction Stop } catch { }
    Start-Sleep -Milliseconds 800
    return ((Get-Service sshd -ErrorAction SilentlyContinue).Status -eq 'Running')
}
function Show-SshdDiagnostics {
    Write-Warn2 'OpenSSH Server : sshd failed to start - collecting the real reason'
    try { & sc.exe qc sshd 2>&1 | ForEach-Object { Write-Host "      $_" -ForegroundColor DarkGray } } catch { }
    # run sshd in debug mode in the foreground to capture the exact error
    # (bind failure, unreadable host key, bad config, ...) then kill it
    $out = Join-Path $env:TEMP 'ssh443-sshd-out.txt'
    $err = Join-Path $env:TEMP 'ssh443-sshd-err.txt'
    Remove-Item $out, $err -Force -ErrorAction SilentlyContinue
    try {
        $proc = Start-Process -FilePath $sshdExe -ArgumentList @('-d', '-f', "`"$sshdConfig`"") -RedirectStandardOutput $out -RedirectStandardError $err -NoNewWindow -PassThru
        Start-Sleep -Seconds 3
        if ($proc -and -not $proc.HasExited) { try { $proc.Kill() } catch { }; Write-Ok 'sshd runs fine in debug mode (config and host keys are OK)' }
        else { Write-Warn2 "sshd debug mode exited with code $($proc.ExitCode)" }
    } catch { Write-Host "      diag: $($_.Exception.Message)" -ForegroundColor DarkGray }
    foreach ($f in @($err, $out)) {
        if (Test-Path $f) { Get-Content $f -ErrorAction SilentlyContinue | Select-Object -Last 20 | ForEach-Object { Write-Host "      $_" -ForegroundColor DarkGray } }
    }
    $slog = Join-Path $sshDir 'logs\sshd.log'
    if (Test-Path $slog) { Get-Content $slog -Tail 15 -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "      $_" -ForegroundColor DarkGray } }
    try {
        Get-WinEvent -LogName System -MaxEvents 60 -ErrorAction Stop |
            Where-Object { $_.ProviderName -match 'Service Control Manager' -and $_.Message -match 'sshd|OpenSSH' } |
            Select-Object -First 3 | ForEach-Object { Write-Host ('      ' + ($_.Message -replace '\s+', ' ')) -ForegroundColor DarkGray }
    } catch { }
}

if (Start-SshdService) {
    Write-Ok "OpenSSH Server : running on port $SshPort"
} else {
    Show-SshdDiagnostics
    Start-Sleep -Seconds 1
    if (Start-SshdService) { Write-Ok "OpenSSH Server : running on port $SshPort (after the diagnostic run)" }
    else { Write-Warn2 'OpenSSH Server : sshd is still not running - SSH logins will fail until it starts' }
}

# ------------------------------------------------------------------ 2. ssh banner
Write-Step 'SSH banner : writing'
$Server_Message = '<div><span style="color: #ff0000">[C1]</span><span style="color: #ff0600">[C1]</span><span style="color: #ff0b00">[C1]</span><span style="color: #ff1100">[C1]</span><span style="color: #ff1600">[C1]</span><span style="color: #ff1c00">[C1]</span><span style="color: #ff2100">[C1]</span><span style="color: #ff2700">[C1]</span><span style="color: #ff2c00">[C1]</span><span style="color: #ff3200">[C1]</span><span style="color: #ff3700">[C1]</span><span style="color: #ff3d00">[C1]</span><span style="color: #ff4200">[C2]</span><span style="color: #ff4800">[C3]</span><span style="color: #ff4d00">[C4]</span><span style="color: #ff5300">[C5]</span><span style="color: #ff5800">[C6]</span><span style="color: #ff5e00">[C7]</span><span style="color: #ff6300">[C8]</span><span style="color: #ff6900">[C2]</span></div><div></div><div><span style="color: #ff6e00">D</span><span style="color: #ff7400">e</span><span style="color: #ff7900">v</span><span style="color: #ff7f00">e</span><span style="color: #ff8500">l</span><span style="color: #ff8a00">o</span><span style="color: #ff9000">p</span><span style="color: #ff9500">e</span><span style="color: #ff9b00">r</span><span style="color: #ffa000"> </span><span style="color: #ffa600">:</span><span style="color: #ffac00"> </span><span style="color: #ffb100"> </span><span style="color: #ffb700">l</span><span style="color: #ffbc00">_</span><span style="color: #ffc200">s</span><span style="color: #ffc700">_</span><span style="color: #ffcd00">I</span><span style="color: #ffd200">_</span><span style="color: #ffd800">I</span><span style="color: #ffde00">.</span><span style="color: #ffe300">t</span><span style="color: #ffe900">.</span><span style="color: #ffee00">m</span><span style="color: #fff400">e</span></div><div></div><div><span style="color: #fff900">C</span><span style="color: #ffff00">H</span><span style="color: #f4ff00">A</span><span style="color: #eaff00">N</span><span style="color: #dfff00">N</span><span style="color: #d5ff00">E</span><span style="color: #caff00">L</span><span style="color: #bfff00"> </span><span style="color: #b5ff00">:</span><span style="color: #aaff00"> </span><span style="color: #9fff00">D</span><span style="color: #95ff00">_</span><span style="color: #8aff00">S</span><span style="color: #80ff00">_</span><span style="color: #75ff00">D</span><span style="color: #6aff00">_</span><span style="color: #60ff00">C</span><span style="color: #55ff00">.</span><span style="color: #4aff00">t</span><span style="color: #40ff00">.</span><span style="color: #35ff00">m</span><span style="color: #2bff00">e</span></div><div></div><div><span style="color: #20ff00">S</span><span style="color: #15ff00">t</span><span style="color: #0bff00">a</span><span style="color: #00ff00">t</span><span style="color: #00ff0b">u</span><span style="color: #00ff16">s</span><span style="color: #00ff21">:</span><span style="color: #00ff2c"> </span><span style="color: #00ff37">s</span><span style="color: #00ff43">u</span><span style="color: #00ff4e">c</span><span style="color: #00ff59">c</span><span style="color: #00ff64">e</span><span style="color: #00ff6f">s</span><span style="color: #00ff7a">s</span></div><div></div><div><span style="color: #00ff85">S</span><span style="color: #00ff90">u</span><span style="color: #00ff9b">p</span><span style="color: #00ffa6">p</span><span style="color: #00ffb1">o</span><span style="color: #00ffbc">r</span><span style="color: #00ffc8">t</span><span style="color: #00ffd3"> </span><span style="color: #00ffde">:</span><span style="color: #00ffe9"> </span><span style="color: #00fff4">U</span><span style="color: #00ffff">D</span><span style="color: #00f4ff">P</span><span style="color: #00e9ff">G</span><span style="color: #00deff">W</span><span style="color: #00d3ff"> </span><span style="color: #00c8ff">/</span><span style="color: #00bcff"> </span><span style="color: #00b1ff">G</span><span style="color: #00a6ff">a</span><span style="color: #009bff">m</span><span style="color: #0090ff">e</span><span style="color: #0085ff"> </span><span style="color: #007aff">&</span><span style="color: #006fff"> </span><span style="color: #0064ff">V</span><span style="color: #0059ff">i</span><span style="color: #004eff">d</span><span style="color: #0043ff">e</span><span style="color: #0037ff">o</span><span style="color: #002cff"> </span><span style="color: #0021ff">c</span><span style="color: #0016ff">a</span><span style="color: #000bff">l</span><span style="color: #0000ff">l</span></div>'
$Server_Message = $Server_Message.Replace('[C1]',[string][char]0x3164).Replace('[C2]',[string][char]0x02D7).Replace('[C3]',[string][char]0x02CF).Replace('[C4]',[string][char]0x02CB).Replace('[C5]',[string][char]0x26A1).Replace('[C6]',[string][char]0xFE0E).Replace('[C7]',[string][char]0x02CE).Replace('[C8]',[string][char]0x02CA)

$bannerFile = Join-Path $sshDir 'banner.txt'
[System.IO.File]::WriteAllText($bannerFile, $Server_Message, (New-Object System.Text.UTF8Encoding($false)))
Set-SshdOption -Config $sshdConfig -Name 'Banner' -Value $bannerFile
if (-not (Start-SshdService)) { Write-Warn2 'OpenSSH Server : sshd did not reload the banner (sshd not running)' }
Write-Ok "SSH banner : $bannerFile"

# ------------------------------------------------------------------ 3. user
Write-Step "User account : $User"
$sec  = ConvertTo-SecureString $Pass -AsPlainText -Force
$userName = if ($User -match '\\') { $User.Split('\')[-1] } else { $User }
$existing = Get-LocalUser -Name $userName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Warn2 'User already existed - resetting the password'
} else {
    New-LocalUser -Name $userName -Password $sec -PasswordNeverExpires -AccountNeverExpires -Description 'SSH tunnel account' | Out-Null
    Write-Ok 'User created'
}
# always re-assert everything password authentication depends on - this is
# idempotent and repairs an account an earlier install/(un)install left half set up
try { Enable-LocalUser -Name $userName -ErrorAction Stop } catch { }
try { Set-LocalUser -Name $userName -Password $sec -PasswordNeverExpires $true -ErrorAction Stop }
catch { Write-Warn2 "could not set the password : $($_.Exception.Message)" }
if ($userName -ne 'Administrator') {
    # some Windows images ship sshd_config with:  AllowGroups administrators "openssh users"
    # every SSH login must then be a member of one of those groups or sshd answers
    # "Password authentication failed" although the password is correct
    try { Add-LocalGroupMember -Group 'openssh users' -Member $userName -ErrorAction Stop } catch { }
    try { Add-LocalGroupMember -Group 'Users'         -Member $userName -ErrorAction SilentlyContinue } catch { }
}
# make sure the account is NOT an administrator (mirrors the linux non-root user)
try {
    $admins = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue | ForEach-Object { ($_.Name -split '\\')[-1] })
    if ($admins -contains $userName) { Remove-LocalGroupMember -Group 'Administrators' -Member $userName -ErrorAction SilentlyContinue }
} catch { }
$inSshGroup = $false
try { $inSshGroup = [bool](@(Get-LocalGroupMember -Group 'openssh users' -ErrorAction Stop | ForEach-Object { ($_.Name -split '\\')[-1] }) -contains $userName) } catch { }
Write-Ok ("User {0} ready (password auth)  |  in 'openssh users': {1}" -f $userName, $inSshGroup)

# --- verify the password the SAME way sshd does -------------------------------
# sshd authenticates with LogonUser(..., LOGON32_LOGON_NETWORK).  We run exactly
# that check here, so a password that did not get stored correctly is caught now
# instead of later showing up as "Password authentication failed" on the client.
if (-not ('Ssh443LogonCheck' -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class Ssh443LogonCheck {
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool LogonUser(string u, string d, string p, int type, int provider, out IntPtr token);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr h);
    public static int Check(string u, string p) {
        IntPtr t;
        if (LogonUser(u, ".", p, 3, 0, out t)) { CloseHandle(t); return 0; }
        return Marshal.GetLastWin32Error();
    }
}
"@
}
$pwCheck = -1
try { $pwCheck = [Ssh443LogonCheck]::Check($userName, $Pass) } catch { }
if ($pwCheck -ne 0) {
    Write-Warn2 "password check failed (win32 error $pwCheck) - re-applying it with 'net user'"
    try { Set-LocalUser -Name $userName -Password $sec -ErrorAction SilentlyContinue } catch { }
    try { & net.exe user $userName $Pass 2>&1 | Out-Null } catch { }
    $pwCheck = -1; try { $pwCheck = [Ssh443LogonCheck]::Check($userName, $Pass) } catch { }
}
if ($pwCheck -eq 0) { Write-Ok "Password verified for $userName (Windows logon test passed)" }
else { Write-Warn2 "Password could NOT be verified (win32 error $pwCheck) - SSH password login will fail" }

# ------------------------------------------------------------------ 4. firewall
Write-Step 'Firewall : opening ports'
try {
    foreach ($p in @($Port)) {
        if (-not (Get-NetFirewallRule -DisplayName "SSH443-Tunnel-$p" -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -DisplayName "SSH443-Tunnel-$p" -Direction Inbound -Action Allow `
                -Protocol TCP -LocalPort $p -Profile Any -ErrorAction Stop | Out-Null
        }
    }
    if (-not (Get-NetFirewallRule -DisplayName 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName 'OpenSSH-Server-In-TCP' -Direction Inbound -Action Allow `
            -Protocol TCP -LocalPort $SshPort -Profile Any -ErrorAction Stop | Out-Null
    } else {
        Set-NetFirewallRule -DisplayName 'OpenSSH-Server-In-TCP' -Enabled True -Profile Any -ErrorAction Stop | Out-Null
    }
    if (-not (Get-NetFirewallRule -DisplayName 'OpenSSH-Server-Out' -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName 'OpenSSH-Server-Out' -Direction Outbound -Action Allow `
            -Program "$sshdExe" -Profile Any -ErrorAction SilentlyContinue | Out-Null
    }
    Write-Ok "Firewall : TCP $Port open  (+ SSH $SshPort in/out)"
} catch { Write-Warn2 "Firewall rule not created - $($_.Exception.Message)" }

# ------------------------------------------------------------------ 5. certificate
Write-Step 'Certificate : self-signed TLS'
$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -eq $CertSubject } |
        Sort-Object NotAfter -Descending | Select-Object -First 1
if (-not $cert -or $cert.NotAfter -lt (Get-Date).AddDays(30)) {
    try {
        $cert = New-SelfSignedCertificate -DnsName $SniHost, 'localhost', 'www.microsoft.com' `
            -Subject $CertSubject -CertStoreLocation Cert:\LocalMachine\My `
            -NotAfter (Get-Date).AddYears(10) -KeyAlgorithm RSA -KeyLength 2048 `
            -HashAlgorithm SHA256 -KeyExportPolicy Exportable -Type SSLServerAuthentication -ErrorAction Stop
        Write-Ok "Certificate created : $($cert.Thumbprint)"
    } catch {
        Write-Err2 "Certificate creation failed : $($_.Exception.Message)"
        exit 1
    }
} else {
    Write-Ok "Certificate reused  : $($cert.Thumbprint)"
}

# ------------------------------------------------------------------ 6. TCP tuning
Write-Step 'TCP tuning : applying (net.core.* equivalent)'
$tunings = @(
    'int tcp set global autotuninglevel=normal',
    'int tcp set global rss=enabled',
    'int tcp set global timestamps=enabled',
    'int tcp set heuristics disabled',
    'int tcp set global ecncapability=disabled'
)
foreach ($t in $tunings) { try { Invoke-Expression "netsh $t" | Out-Null } catch { } }
try { Set-NetTCPSetting -SettingName InternetCustom -AutoTuningLevelLocal Normal -ErrorAction SilentlyContinue } catch { }
Write-Ok 'TCP tuning applied'

# ------------------------------------------------------------------ 7. scheduled task (auto start at boot)
Write-Step "Service host : scheduled task '$TaskName'"

# A previous install leaves its tunnel process running and holding <Port>.  The
# task uses MultipleInstances=IgnoreNew, so Task Scheduler would REFUSE to start
# the new instance and 443 would keep being served by the OLD process (with the
# OLD target port) - the new settings would simply never take effect.  So stop
# the task and kill whatever still holds the tunnel port before (re)registering.
try { Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue } catch { }
for ($i = 0; $i -lt 20; $i++) {
    $l = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $l) { break }
    $proc = Get-Process -Id $l.OwningProcess -ErrorAction SilentlyContinue
    if ($proc -and $proc.ProcessName -match 'powershell|pwsh') {
        Write-Warn2 "stopping the previous tunnel process $($proc.ProcessName) (pid $($proc.Id)) on port $Port"
        try { Stop-Process -Id $proc.Id -Force -ErrorAction Stop } catch { }
        Start-Sleep -Milliseconds 500
    } else {
        Write-Warn2 "port $Port is held by '$($proc.ProcessName)' (pid $($proc.Id)) - it will have to be stopped manually"
        break
    }
}
# start from a clean log so the verification step below reflects THIS run only
if (Test-Path $LogFile) { Remove-Item $LogFile -Force -ErrorAction SilentlyContinue }

$tunnelPs = Join-Path $RootDir 'Tunnel443.ps1'
$argList = @(
    '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Hidden',
    '-File', "`"$tunnelPs`"",
    '-Port', $Port, '-TargetPort', $SshPort, '-CertSubject', "`"$CertSubject`"",
    '-UdpGwPort', $UdpGwPort, '-UdpGwDns', "`"$($DnsServers[0])`"",
    '-LogFile', "`"$LogFile`"", '-SniHost', "`"$SniHost`"",
    '-BindIp', "`"$BindIp`"", '-BindIfIndex', $primaryNic.Index,
    '-BindGateway', "`"$Gateway`"", '-DnsServers', "`"$DnsCsv`"",
    '-RouteStateFile', "`"$RouteState`"", '-BindNicDll', "`"$BindNicDll`""
) -join ' '

$action    = New-ScheduledTaskAction -Execute (Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe') -Argument $argList
$trigger   = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
                -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew

try {
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
        -Principal $principal -Settings $settings -Force -ErrorAction Stop | Out-Null
    Start-ScheduledTask -TaskName $TaskName -ErrorAction Stop
    Write-Ok "Task registered and started (auto-start at boot, run as SYSTEM)"
} catch {
    Write-Err2 "Could not register the scheduled task : $($_.Exception.Message)"
    exit 1
}

# ------------------------------------------------------------------ 8. verify
Write-Step 'Verifying listener ...'
$ok = $false
for ($i = 0; $i -lt 20; $i++) {
    Start-Sleep -Seconds 1
    $l = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($l) { $ok = $true; break }
}
# the tunnel logs "tcp listen" only once it really bound the port, so a leftover
# process sitting on the port can no longer make this step look successful
$bindOk = $false
if (Test-Path $LogFile) {
    $bindOk = [bool](Get-Content $LogFile -ErrorAction SilentlyContinue | Where-Object { $_ -match 'tcp listen' })
}
if ($ok -and $bindOk) {
    $owner = (Get-Process -Id $l.OwningProcess -ErrorAction SilentlyContinue).ProcessName
    Write-Ok "Listening on $BindIp`:$Port (process: $owner)  ->  127.0.0.1:$SshPort"
} else {
    Write-Err2 "tunnel did not come up on port $Port - check $LogFile"
    if (Test-Path $LogFile) { Get-Content $LogFile -Tail 20 | ForEach-Object { Write-Host "      $_" -ForegroundColor DarkGray } }
}

# ------------------------------------------------------------------ 9. public info
$ip = ''; $cc = ''
try {
    $info = Invoke-RestMethod -Uri 'https://ipinfo.io/json' -TimeoutSec 10
    $ip = $info.ip; $cc = $info.country
} catch { }
if (-not $ip) { $ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } | Select-Object -First 1).IPAddress }

function Get-Flag([string]$c) {
    if ($c.Length -ne 2) { return '' }
    $c = $c.ToUpper()
    return [char]::ConvertFromUtf32(0x1F1E6 + ([int][char]$c[0] - 65)) + [char]::ConvertFromUtf32(0x1F1E6 + ([int][char]$c[1] - 65))
}
$flag = Get-Flag $cc
$countryLabel = (($cc, $flag) | Where-Object { $_ }) -join ' '

# Kept ASCII-only on purpose: Windows PowerShell 5.1 reads a BOM-less .ps1 using
# the system ANSI codepage, which turns every non-ASCII literal into "?" garbage.
# So the few pretty symbols are built from their code points at runtime.
$chBullet = [string][char]0x2022                 # bullet
$chArrow  = [string][char]0x2014 + [char]0x00BB  # long dash + right guillemet
$chCheck  = [string][char]0x221A                 # check mark

Write-Host ''
Write-Host '  ------------------------------------------------------------------'
Write-Host '  ========== SSH Account ==========' -ForegroundColor Green
Write-Host ("  {0} CHANNEL URL:- D_S_D_C1.T.ME" -f $chBullet) -ForegroundColor Yellow
Write-Host ("  {0} VPS Country:- {1}" -f $chBullet, $countryLabel) -ForegroundColor Yellow
Write-Host ("  {0} IP Address:- {1}" -f $chBullet, $ip) -ForegroundColor Yellow
Write-Host ("  {0} Local NIC IP:- {1}  (use this in NetMod on the same PC)" -f $chBullet, $BindIp) -ForegroundColor Yellow
Write-Host ("  {0} Physical DNS:- {1}  (pinned; TUN DNS is ignored)" -f $chBullet, $DnsCsv) -ForegroundColor Yellow
Write-Host ("  {0} port:- {1}" -f $chBullet, $Port) -ForegroundColor Yellow
Write-Host ("  {0} User:- {1}" -f $chBullet, $userName) -ForegroundColor Yellow
Write-Host ("  {0} Pass:- {1}" -f $chBullet, $Pass) -ForegroundColor Yellow
if ($UdpGwPort -gt 0) { Write-Host ("  {0} UDPGW Port:- {1}" -f $chBullet, $UdpGwPort) -ForegroundColor Yellow }
Write-Host '  ========== Http Custom ==========' -ForegroundColor Green
Write-Host ("  {0}:{1}@{2}:{3} {4} {5}" -f $ip, $Port, $userName, $Pass, $chArrow, $flag) -ForegroundColor Yellow
Write-Host '  ------------------------------------------------------------------'
Write-Host '  # DEV:- l_s_I_I.T.ME' -ForegroundColor DarkGray
Write-Host ("  # Script V ==> {0} {1}" -f $WinVer, $chCheck) -ForegroundColor Green
Write-Host '  ------------------------------------------------------------------'
Write-Host '  Client settings:  SSH + TLS / SNI  (self-signed OK)'
Write-Host ("  NetMod Host/IP : {0}  (physical NIC - NOT 127.0.0.1, NOT the TUN address)" -f $BindIp) -ForegroundColor Cyan
Write-Host '  NetMod mode    : TUN/VPN fine - sshd children, UDP and DNS are pinned + route guard active' -ForegroundColor Cyan
Write-Host '  Files          :  ' -NoNewline; Write-Host $RootDir
Write-Host '  Log            :  ' -NoNewline; Write-Host $LogFile
Write-Host '  Stop           :  ' -NoNewline; Write-Host ("powershell -File `"{0}`"" -f (Join-Path $RootDir 'Stop-Tunnel.ps1'))
Write-Host '  ------------------------------------------------------------------'
Write-Host ''

try { Stop-Transcript | Out-Null } catch { }
