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
    [string] $BindIp       = '',
    [switch] $Diagnose,
    [switch] $SameHost,
    [switch] $ListenLocalOnly,
    [switch] $UseInject,
    [switch] $SelfTest
)

# ------------------------------------------------------------------ diagnose (read-only)
# -Diagnose must never start a transcript, create a directory, prompt, or change
# any route/service/process. It exits before all of that.
if ($Diagnose) {
    function D-Say ($m, $c = 'Gray') { Write-Host $m -ForegroundColor $c }
    D-Say '=== Run.ps1 -Diagnose (read-only, no changes) ===' 'Cyan'

    $tunPattern = '(?i)(TAP|Wintun|NetMod|VPN|Tunnel|Virtual|Hyper-V|vEthernet|VMware|VirtualBox|WSL|WireGuard|OpenVPN)'

    D-Say '' 
    D-Say '[1] TUN / virtual adapters' 'Green'
    $tun = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -match $tunPattern -or $_.InterfaceDescription -match $tunPattern
    })
    if ($tun.Count -eq 0) { D-Say '  none detected' 'Yellow' }
    else {
        $tun | Select-Object Name,InterfaceIndex,Status,InterfaceDescription,MacAddress |
            Format-Table -AutoSize | Out-String -Width 200 | Write-Host
    }

    D-Say '[2] /1 routes installed by the TUN client' 'Green'
    $one = @(Get-NetRoute -DestinationPrefix '0.0.0.0/1','128.0.0.0/1' -ErrorAction SilentlyContinue)
    if ($one.Count -eq 0) { D-Say '  none detected' 'Yellow' }
    else {
        $one | Select-Object DestinationPrefix,NextHop,InterfaceIndex,InterfaceAlias,RouteMetric,InterfaceMetric |
            Sort-Object DestinationPrefix,InterfaceIndex |
            Format-Table -AutoSize | Out-String -Width 200 | Write-Host
    }

    D-Say '[3] primary NIC (same selection logic as the installer)' 'Green'
    $cands = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {
        $_.IPAddress -notlike '127.*' -and
        $_.IPAddress -notlike '169.254.*' -and
        $_.PrefixLength -gt 0 -and
        $_.InterfaceAlias -notmatch $tunPattern
    })
    $rts = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
             Where-Object { $_.NextHop -and $_.NextHop -ne '0.0.0.0' -and $_.InterfaceIndex -gt 0 })
    $primary = $null; $best = [int]::MaxValue
    foreach ($c in $cands) {
        $r = $rts | Where-Object { $_.InterfaceIndex -eq $c.InterfaceIndex } | Sort-Object RouteMetric | Select-Object -First 1
        $m = if ($r) { [int]$r.RouteMetric } else { 9999 }
        if ($m -lt $best) { $best = $m; $primary = $c; $gw = if ($r) { $r.NextHop } else { '' } }
    }
    if ($primary) {
        [pscustomobject]@{ IPAddress = $primary.IPAddress; InterfaceIndex = $primary.InterfaceIndex;
                           InterfaceAlias = $primary.InterfaceAlias; Gateway = $gw; DefaultRouteMetric = $best } |
            Format-List | Out-String -Width 200 | Write-Host
    } else { D-Say '  no physical NIC detected' 'Yellow' }

    D-Say '[4] sshd processes (parent -> children)' 'Green'
    $sshd = @(Get-CimInstance Win32_Process -Filter "Name='sshd.exe'" -ErrorAction SilentlyContinue)
    if ($sshd.Count -eq 0) { D-Say '  no sshd.exe process' 'Yellow' }
    else {
        $sshd | Select-Object ProcessId,ParentProcessId,SessionId,CommandLine |
            Sort-Object ParentProcessId,ProcessId |
            Format-Table -AutoSize -Wrap | Out-String -Width 200 | Write-Host
    }

    D-Say '[5] native helper' 'Green'
    $nativeDir = Join-Path $env:ProgramData 'open.port\native'
    $dll = Join-Path $nativeDir 'bindnic.dll'
    if (Test-Path -LiteralPath $dll) {
        $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $dll).Hash
        $bytes = [IO.File]::ReadAllBytes($dll)
        $marker = ([Text.Encoding]::ASCII.GetString($bytes)).Contains('hooks installed (v3)')
        [pscustomobject]@{ Path = $dll; Length = $bytes.Length; SHA256 = $hash; V3Marker = $marker } |
            Format-List | Out-String -Width 200 | Write-Host
        if (-not $marker) { D-Say '  STALE: v3 marker absent - suspended-inject fix is NOT active' 'Red' }
    } else { D-Say "  MISSING: $dll" 'Red' }
    $cfg = Join-Path $nativeDir 'bindnic.cfg'
    if (Test-Path -LiteralPath $cfg) { D-Say "  bindnic.cfg: $((Get-Content -LiteralPath $cfg -Raw) -replace '\r?\n', ' | ')" }

    D-Say '[6] last 50 lines of logs' 'Green'
    $logs = @(
        (Join-Path $env:ProgramData 'ssh443\shim-logs\bindnic.log'),
        (Join-Path $nativeDir 'bindnic.log'),
        (Join-Path $env:WINDIR 'Temp\bindnic.log'),
        (Join-Path $env:ProgramData 'ssh443\tunnel.log')
    )
    foreach ($l in $logs) {
        D-Say "  --- $l ---"
        if (Test-Path -LiteralPath $l) { Get-Content -LiteralPath $l -Tail 50 | ForEach-Object { "  $_" } }
        else { D-Say '  (not found)' 'Yellow' }
    }
    D-Say '=== end of diagnosis ===' 'Cyan'
    exit 0
}

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
$WinVer     = '2.0'

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
    # Any /32 route on the physical NIC beats NetMod's /1 routes. Windows may
    # already have created one (on-link metric 256, or via the gateway metric
    # 0/25). Do not try to add a duplicate just because the metric differs -
    # that produced a "MSFT_NetRoute already exists" failure every 10 seconds.
    $existing = @(Get-NetRoute -DestinationPrefix $Prefix -InterfaceIndex $IfIndex -ErrorAction SilentlyContinue)
    if ($existing.Count -gt 0) { return $false }
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

# A same-host client can reach 127.0.0.1:443 directly, which removes the listener
# from the TUN path entirely. It is opt-in (-SameHost / -ListenLocalOnly); remote
# clients still need the physical NIC address.
$ListenerIp = if ($SameHost -or $ListenLocalOnly) { '127.0.0.1' } else { $BindIp }
if ($SameHost -or $ListenLocalOnly) {
    Write-Ok "Listener    : 127.0.0.1:$Port (local-only; physical NIC $BindIp still used for UDP and routes)"
} else {
    Write-Ok "Listener    : $BindIp`:$Port (remote clients allowed)"
}

function Test-SameHostTun {
    $virtualPattern = '(?i)(TAP|Wintun|NetMod|VPN|Tunnel|Virtual|Hyper-V|vEthernet|VMware|VirtualBox|WSL|WireGuard|OpenVPN)'
    $adapters = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -match $virtualPattern -or $_.InterfaceDescription -match $virtualPattern
    })
    if ($adapters.Count -gt 0) { return $true }
    $tunRoutes = @(Get-NetRoute -DestinationPrefix '0.0.0.0/1','128.0.0.0/1' -ErrorAction SilentlyContinue)
    return ($tunRoutes.Count -gt 0)
}
if (Test-SameHostTun) {
    if ($UseInject) {
        Write-Ok 'TUN/VPN detected on this host - sshd injection enabled (-UseInject)'
    } else {
        Write-Warn2 'TUN/VPN detected here and -UseInject was NOT passed: sshd children can route outbound TCP back into the tunnel (no internet). Re-run with -UseInject, or use a non-TUN client.'
    }
}

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

# ------------------------------------------------------------------ self test
# End-to-end proof, not an assumption: TCP + DNS are exercised from the physical
# NIC and again through the tunnel (local 443 -> sshd -> SOCKS -> outbound).
# Every network operation has a 5 second deadline. A temporary ssh key is added
# to authorized_keys only for the duration of the test and always removed.
if ($SelfTest) {
    function ST-Say { param($m,$c='Gray') Write-Host $m -ForegroundColor $c }
    function ST-Fail { param($m) Write-Host "  [x] SELFTEST FAIL: $m" -ForegroundColor Red; exit 1 }
    function ST-Bail { param($m) $script:stErr = $m; throw 'SELFTEST_FAILED' }
    function ST-ReadExactly {
        param($Stream,[int]$Count)
        $buf = New-Object byte[] $Count
        $off = 0
        while ($off -lt $Count) {
            $n = $Stream.Read($buf,$off,$Count-$off)
            if ($n -le 0) { throw 'stream closed' }
            $off += $n
        }
        return ,$buf
    }
    function ST-Tcp {
        param([string]$Ip,[int]$Port,[string]$LocalIp,[int]$Ms=5000)
        $c = $null
        try {
            # .NET Framework TcpClient has no Bind(); the local endpoint must be
            # supplied to the constructor instead.
            if ($LocalIp) {
                $localEp = New-Object Net.IPEndPoint ([Net.IPAddress]::Parse($LocalIp)), 0
                $c = New-Object Net.Sockets.TcpClient -ArgumentList $localEp
            } else {
                $c = New-Object Net.Sockets.TcpClient
            }
            $t = $c.ConnectAsync($Ip,$Port)
            if (-not $t.Wait($Ms)) { return $false }
            return $c.Connected
        } catch { return $false } finally { if ($c) { $c.Close() } }
    }
    function ST-DnsQueryBytes {
        param([string]$Name)
        $q = New-Object 'System.Collections.Generic.List[byte]'
        $q.Add([byte]0x12); $q.Add([byte]0x34)   # id
        $q.Add([byte]0x01); $q.Add([byte]0x00)   # recursion desired
        $q.Add([byte]0x00); $q.Add([byte]0x01)   # QDCOUNT = 1
        $q.Add([byte]0); $q.Add([byte]0); $q.Add([byte]0)
        $q.Add([byte]0); $q.Add([byte]0); $q.Add([byte]0)   # AN/NS/AR = 0
        foreach ($label in ($Name.Split('.'))) {
            $b = [Text.Encoding]::ASCII.GetBytes($label)
            $q.Add([byte]$b.Length)
            foreach ($x in $b) { $q.Add([byte]$x) }
        }
        $q.Add([byte]0)                          # root label
        $q.Add([byte]0); $q.Add([byte]1)         # QTYPE A
        $q.Add([byte]0); $q.Add([byte]1)         # QCLASS IN
        return $q.ToArray()
    }
    function ST-DnsOk {
        param([byte[]]$Response)
        if ($Response.Length -lt 12) { return $false }
        $ancount = ($Response[6] -shl 8) -bor $Response[7]
        $rcode   = $Response[3] -band 0x0F
        return (($rcode -eq 0) -and ($ancount -gt 0))
    }
    function ST-DnsUdp {
        param([string]$Server,[string]$Name,[string]$LocalIp,[int]$Ms=5000)
        $u = $null
        try {
            $q = ST-DnsQueryBytes $Name
            $u = New-Object Net.Sockets.UdpClient
            if ($LocalIp) { $u.Client.Bind((New-Object Net.IPEndPoint([Net.IPAddress]::Parse($LocalIp),0))) }
            $u.Client.ReceiveTimeout = $Ms
            [void]$u.Send($q,$q.Length,$Server,53)
            $ep = New-Object Net.IPEndPoint([Net.IPAddress]::Any,0)
            $r = $u.Receive([ref]$ep)
            return (ST-DnsOk $r)
        } catch { return $false } finally { if ($u) { $u.Close() } }
    }
    function ST-DnsTcp {
        param($Stream,[string]$Name)
        $q = ST-DnsQueryBytes $Name
        $len = New-Object byte[] 2
        $len[0] = [byte](($q.Length -shr 8) -band 0xFF)
        $len[1] = [byte]($q.Length -band 0xFF)
        $Stream.Write($len,0,2)
        $Stream.Write($q,0,$q.Length)
        $h = ST-ReadExactly $Stream 2
        $n = ($h[0] -shl 8) -bor $h[1]
        if ($n -lt 12 -or $n -gt 4096) { return $false }
        $r = ST-ReadExactly $Stream $n
        return (ST-DnsOk $r)
    }
    function ST-SocksConnect {
        param([string]$ProxyIp,[int]$ProxyPort,[string]$Target,[int]$TargetPort,[int]$Ms=5000)
        $c = $null
        try {
            $c = New-Object Net.Sockets.TcpClient
            $t = $c.ConnectAsync($ProxyIp,$ProxyPort)
            if (-not $t.Wait($Ms)) { return $null }
            $s = $c.GetStream(); $s.ReadTimeout=$Ms; $s.WriteTimeout=$Ms
            $s.Write([byte[]]@(5,1,0),0,3)
            $g = ST-ReadExactly $s 2
            if ($g[0] -ne 5 -or $g[1] -ne 0) { return $null }
            $tb = [Text.Encoding]::ASCII.GetBytes($Target)
            $req = New-Object byte[] (5 + $tb.Length + 2)
            $req[0]=[byte]5; $req[1]=[byte]1; $req[2]=[byte]0; $req[3]=[byte]3
            $req[4]=[byte]$tb.Length
            [Array]::Copy($tb,0,$req,5,$tb.Length)
            $req[5+$tb.Length]=[byte](($TargetPort -shr 8) -band 0xFF)
            $req[6+$tb.Length]=[byte]($TargetPort -band 0xFF)
            $s.Write($req,0,$req.Length)
            $rep = ST-ReadExactly $s 4
            if ($rep[1] -ne 0) { return $null }
            if ($rep[3] -eq 1) { [void](ST-ReadExactly $s 4) }
            elseif ($rep[3] -eq 4) { [void](ST-ReadExactly $s 16) }
            elseif ($rep[3] -eq 3) { $lb=ST-ReadExactly $s 1; [void](ST-ReadExactly $s $lb[0]) }
            [void](ST-ReadExactly $s 2)   # BND.PORT - otherwise it is read as the DNS length
            return $s
        } catch { if ($c) { $c.Close() }; return $null }
    }

    ST-Say '=== Run.ps1 -SelfTest (5s deadline per check) ===' 'Cyan'
    $stErr = $null

    # 1. The native helper must be the pinned, verified v3 build.
    $dllPath = Join-Path $env:ProgramData 'open.port\native\bindnic.dll'
    if (-not (Test-Path -LiteralPath $dllPath)) {
        ST-Fail "bindnic.dll is MISSING ($dllPath). Re-run Run.ps1 -UseInject with internet access."
    }
    $dllHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $dllPath).Hash.ToLower()
    $wantDll = '482a067b0d1e1fa499abf52bfad19fafeb36bf52f890689779dd747f3ccb2593'
    if ($dllHash -ne $wantDll) {
        ST-Fail "bindnic.dll is STALE: SHA256 $dllHash, expected $wantDll - loop protection is NOT active"
    }
    if (-not ([Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($dllPath))).Contains('hooks installed (v3)')) {
        ST-Fail 'bindnic.dll has no v3 marker - the suspended-inject fix is NOT active'
    }
    ST-Say "  [v] native helper verified  $dllHash" 'Green'
    if (-not $UseInject) {
        ST-Fail 'bindnic.dll is verified but -UseInject was not passed, so sshd injection is disabled and outbound TCP can loop'
    }
    ST-Say '  [v] -UseInject present' 'Green'

    # 2. With TUN up, the /32 pins must exist on the physical interface.
    $tunRoutes = @(Get-NetRoute -DestinationPrefix '0.0.0.0/1','128.0.0.0/1' -ErrorAction SilentlyContinue)
    ST-Say ("  TUN /1 routes         : {0}" -f $(if ($tunRoutes.Count) { 'present' } else { 'not present' }))
    if ($tunRoutes.Count -gt 0) {
        $pins = @("$BindIp/32", "$Gateway/32") + @($DnsServers | ForEach-Object { "$_/32" })
        foreach ($p in ($pins | Where-Object { $_ -notmatch '^/$|^\s*/32$' } | Select-Object -Unique)) {
            $hit = @(Get-NetRoute -DestinationPrefix $p -ErrorAction SilentlyContinue |
                     Where-Object { $_.InterfaceIndex -eq $primaryNic.Index })
            if ($hit.Count -eq 0) {
                ST-Fail "route pin $p is missing on physical interface $($primaryNic.Index). Loop hint: TUN default routes can capture sshd's outbound sockets."
            }
        }
        ST-Say '  [v] route pins present on the physical NIC' 'Green'
    }

    # 3. Direct path: TCP and DNS from the physical NIC.
    $dnsIp = $DnsServers[0]
    if (-not (ST-Tcp '1.1.1.1' 443 $BindIp)) {
        ST-Fail 'physical-NIC TCP to 1.1.1.1:443 did not complete within 5s'
    }
    ST-Say ("  [v] physical TCP       : {0} -> 1.1.1.1:443" -f $BindIp) 'Green'
    if (-not (ST-DnsUdp $dnsIp 'example.com' $BindIp)) {
        ST-Fail "DNS via physical NIC $dnsIp did not answer within 5s"
    }
    ST-Say ("  [v] physical DNS       : example.com via {0}" -f $dnsIp) 'Green'

    # 4. Tunnel path: temporary key, ssh -D, then TCP and DNS through SOCKS5.
    $openssh   = Join-Path $env:WINDIR 'System32\OpenSSH'
    $sshExe    = Join-Path $openssh 'ssh.exe'
    $keygenExe = Join-Path $openssh 'ssh-keygen.exe'
    if (-not (Test-Path $sshExe) -or -not (Test-Path $keygenExe)) {
        ST-Fail 'OpenSSH client (ssh.exe / ssh-keygen.exe) was not found'
    }
    $stUser    = if ($User -match '\\') { $User.Split('\')[-1] } else { $User }
    $akFile    = Join-Path $env:ProgramData ("ssh\authorized_keys\" + $stUser)
    $akDirPath = Split-Path -Parent $akFile
    $tmpDir    = Join-Path $env:TEMP ('ssh443-selftest-' + [guid]::NewGuid().ToString('N'))
    $akExisted = Test-Path -LiteralPath $akFile
    $savedAk   = $null
    $sshProc   = $null
    try {
        New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null
        $keyPath = Join-Path $tmpDir 'id'
        # PowerShell drops an empty native argument; '""' is required so
        # ssh-keygen really receives an empty passphrase.
        & $keygenExe -q -t ed25519 -N '""' -f $keyPath 2>&1 | Out-Null
        if (-not (Test-Path "$keyPath.pub")) { ST-Bail 'ssh-keygen could not create a temporary test key' }
        if (-not (Test-Path $akDirPath)) { New-Item -ItemType Directory -Force -Path $akDirPath | Out-Null }
        if ($akExisted) { $savedAk = Get-Content -LiteralPath $akFile -Raw }
        $pub = (Get-Content -LiteralPath "$keyPath.pub" -Raw).Trim()
        Add-Content -LiteralPath $akFile -Value $pub -Encoding ASCII

        $socksPort = 45000 + (Get-Random -Maximum 5000)
        $errFile   = Join-Path $tmpDir 'ssh.err'
        $sshArgs = @(
            '-i', "`"$keyPath`"", '-o','BatchMode=yes', '-o','StrictHostKeyChecking=no',
            '-o','UserKnownHostsFile=NUL', '-o','ExitOnForwardFailure=yes', '-o','ConnectTimeout=5',
            '-D', "127.0.0.1:$socksPort", '-N', '-p', "$Port", "`"$User@$ListenerIp`""
        )
        $sshProc = Start-Process -FilePath $sshExe -ArgumentList $sshArgs -PassThru `
                       -WindowStyle Hidden -RedirectStandardError $errFile
        $up = $false
        for ($i = 0; $i -lt 10; $i++) {
            Start-Sleep -Milliseconds 500
            if (Get-NetTCPConnection -LocalPort $socksPort -State Listen -ErrorAction SilentlyContinue) { $up = $true; break }
        }
        $loopHint = ' Loop hint: with a TUN client on this host, sshd children route outbound TCP back into the tunnel unless -UseInject is active and bindnic.dll v3 is verified.'
        if (-not $up) {
            $detail = if (Test-Path $errFile) { ((Get-Content $errFile -Raw) -replace '\s+',' ').Trim() } else { 'no ssh diagnostic output' }
            ST-Bail "SOCKS session through the tunnel did not open within 5s ($detail).$loopHint"
        }
        $s1 = ST-SocksConnect '127.0.0.1' $socksPort '1.1.1.1' 443
        if (-not $s1) { ST-Bail "outbound TCP via the tunnel to 1.1.1.1:443 did not complete within 5s.$loopHint" }
        ST-Say '  [v] tunnel TCP         : 1.1.1.1:443 via SOCKS' 'Green'

        $s2 = ST-SocksConnect '127.0.0.1' $socksPort $dnsIp 53
        if (-not $s2) {
            ST-Bail "SOCKS CONNECT to $dnsIp`:53 through the tunnel failed within 5s.$loopHint"
        }
        $dnsOk = $false
        $dnsWhy = ''
        try { $dnsOk = ST-DnsTcp $s2 'example.com' } catch { $dnsWhy = $_.Exception.Message }
        if (-not $dnsOk) {
            ST-Bail "DNS answer via the tunnel ($dnsIp`:53) was missing or invalid within 5s ($dnsWhy).$loopHint"
        }
        ST-Say ("  [v] tunnel DNS         : example.com via {0}" -f $dnsIp) 'Green'
    } catch {
        if (-not $stErr) { $stErr = $_.Exception.Message }
    } finally {
        if ($sshProc -and -not $sshProc.HasExited) { Stop-Process -Id $sshProc.Id -Force -ErrorAction SilentlyContinue }
        if ($akExisted) {
            Set-Content -LiteralPath $akFile -Value $savedAk -Encoding ASCII -NoNewline
        } else {
            Remove-Item -LiteralPath $akFile -Force -ErrorAction SilentlyContinue
        }
        Remove-Item -LiteralPath $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    if ($stErr) { ST-Fail $stErr }
    ST-Say '=== SELFTEST PASS ===' 'Green'
    exit 0
}

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
# native\ holds executable code. Only SYSTEM and Administrators may write here.
# Users:Modify on this folder would let any local account replace bindnic.dll.
try {
    & icacls.exe $NativeDir /inheritance:r /remove:g '*S-1-5-32-545' /T 2>&1 | Out-Null
    & icacls.exe $NativeDir /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /T 2>&1 | Out-Null
} catch { }
$BindNicDll = Join-Path $NativeDir 'bindnic.dll'
$InjectExe  = Join-Path $NativeDir 'inject.exe'

# The shim writes its log from inside sshd children (unprivileged SSH user) and
# from the SYSTEM-owned sshd service. Give it a DATA-ONLY directory outside the
# code path: no DLL/EXE/PS1 is ever loaded from here. bindnic.cfg line 3 is the
# path the native DLL itself opens.
$ShimLogDir = Join-Path $WorkDir 'shim-logs'
if (-not (Test-Path $ShimLogDir)) { New-Item -ItemType Directory -Force -Path $ShimLogDir | Out-Null }
try {
    & icacls.exe $ShimLogDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)M' /T 2>&1 | Out-Null
} catch { }
$BindNicLog = Join-Path $ShimLogDir 'bindnic.log'
# Pinned native helper. The expected hashes are literals in THIS file - they
# are not fetched from the same host as the binaries. URLs address an immutable
# commit, so a branch/CDN cache can never serve a different build.
$PinnedCommit = 'e5f5925c3cdca208c2201e4dc400c0b726c9cf4d'
$PinnedSha = @{
    'bindnic.dll' = '482a067b0d1e1fa499abf52bfad19fafeb36bf52f890689779dd747f3ccb2593'
    'inject.exe'  = '41aefe9cdad60289813a2dc7a72846cf7e106f4da39a7a5cb23d0ae7d8fe8757'
}
$PinnedB64Sha = 'b7145d564042e88ab0e1a49dd5b43357885323681060a806af1e107a3cf35add'
$NativeBase   = "https://raw.githubusercontent.com/P-443/open.port/$PinnedCommit/native"
$V3Marker     = 'hooks installed (v3)'
function Get-Sha256 { param([string]$Path) (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLower() }
function Test-V3Marker {
    param([string]$Path)
    try { return ([Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($Path))).Contains($V3Marker) } catch { return $false }
}

$NativeHelperOk = $true
foreach ($n in @('bindnic.dll','inject.exe')) {
    $dst = Join-Path $NativeDir $n
    $expect = $PinnedSha[$n]
    $failures = New-Object System.Collections.Generic.List[string]
    $got = $false
    for ($attempt = 1; $attempt -le 3 -and -not $got; $attempt++) {
        $tmp = Join-Path $env:TEMP ("ssh443-$n-$attempt")
        try {
            Invoke-WebRequest -Uri "$NativeBase/$n" -OutFile $tmp -UseBasicParsing -TimeoutSec 60 -ErrorAction Stop
            $actual = Get-Sha256 $tmp
            if ($actual -ne $expect) {
                $failures.Add("attempt $attempt : SHA256 mismatch from $NativeBase/$n - expected $expect, got $actual")
            } elseif ($n -eq 'bindnic.dll' -and -not (Test-V3Marker $tmp)) {
                $failures.Add("attempt $attempt : hash matched but v3 marker '$V3Marker' is absent")
            } else {
                Copy-Item $tmp $dst -Force
                $got = $true
            }
        } catch {
            $failures.Add("attempt $attempt : download from $NativeBase/$n failed - $($_.Exception.Message)")
        } finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
        if (-not $got) { Start-Sleep -Milliseconds 750 }
    }

    # Text fallback for the DLL: downloaded and decoded locally, then held to
    # the SAME pinned SHA256. A mismatch is refused, never silently accepted.
    if ($n -eq 'bindnic.dll' -and -not $got) {
        try {
            $c = (Invoke-WebRequest -Uri "$NativeBase/bindnic.b64" -UseBasicParsing -TimeoutSec 90 -ErrorAction Stop).Content
            if ($c -is [byte[]]) { $c = [Text.Encoding]::ASCII.GetString($c) }
            $b64Hash = ([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes(($c -replace '\s',''))))
            $b64Hex  = [BitConverter]::ToString($b64Hash).Replace('-','').ToLower()
            if ($b64Hex -ne $PinnedB64Sha) {
                $failures.Add("base64 fallback : SHA256 mismatch - expected $PinnedB64Sha, got $b64Hex")
            } else {
                $bytes = [Convert]::FromBase64String(($c -replace '\s',''))
                $tmpDll = Join-Path $env:TEMP 'ssh443-bindnic-decoded.dll'
                [IO.File]::WriteAllBytes($tmpDll, $bytes)
                $actual = Get-Sha256 $tmpDll
                if ($actual -ne $expect) {
                    $failures.Add("base64 fallback : decoded SHA256 mismatch - expected $expect, got $actual")
                } elseif (-not (Test-V3Marker $tmpDll)) {
                    $failures.Add("base64 fallback : decoded DLL has no v3 marker")
                } else {
                    Copy-Item $tmpDll $dst -Force
                    $got = $true
                }
                Remove-Item $tmpDll -Force -ErrorAction SilentlyContinue
            }
        } catch { $failures.Add("base64 fallback : $($_.Exception.Message)") }
    }

    if ($got) { Write-Ok "Downloaded native/$n (SHA256=$expect)" }
    elseif (Test-Path $dst) {
        $cached = Get-Sha256 $dst
        if ($cached -eq $expect) { Write-Ok "Cached native/$n verified (SHA256=$cached)" }
        else {
            $NativeHelperOk = $false
            Write-Err2 "REFUSED: $dst has SHA256 $cached, expected $expect - it will NOT be used"
        }
    } else {
        $NativeHelperOk = $false
        Write-Err2 "REFUSED: $n is missing and no verified copy could be downloaded"
    }
    foreach ($f in $failures) { Write-Warn2 "  reason: $f" }
}

# Report (do not remediate) antivirus quarantine. No exclusions are added.
try {
    $threats = @(Get-MpThreatDetection -ErrorAction Stop | Where-Object {
        $r = ($_.Resources -join ' ')
        $r -match 'bindnic|inject\.exe|open\.port'
    })
    if ($threats.Count -gt 0) {
        Write-Err2 "Defender quarantine detected for our native helper ($($threats.Count) detection(s))."
        Write-Warn2 'Add an exclusion manually if you trust this repository; this script never adds exclusions.'
        $threats | Select-Object -First 5 InitialDetectionTime,ThreatID,Resources | Format-List | Out-String -Width 160 | Write-Host
    }
} catch {
    Write-Warn2 "Defender threat detection unavailable: $($_.Exception.Message)"
}

if (-not $UseInject) {
    Write-Ok 'sshd injection disabled (default) - pass -UseInject only for a TUN client on this host'
} elseif (-not ($NativeHelperOk -and (Test-Path $BindNicDll))) {
    Write-Err2 '-UseInject requested but bindnic.dll is missing or failed hash verification; loop protection is NOT active'
} else {
    $cfg = Join-Path $NativeDir 'bindnic.cfg'
    @($BindIp, "$($primaryNic.Index)", $BindNicLog) | Set-Content -LiteralPath $cfg -Encoding ASCII
    Write-Ok "sshd binder config : bind=$BindIp if=$($primaryNic.Index) log=$BindNicLog"
    if (Test-Path $InjectExe) {
        Get-Process sshd -ErrorAction SilentlyContinue | ForEach-Object {
            & $InjectExe $_.Id $BindNicDll 2>&1 | Out-Null
        }
        Write-Ok 'sshd binder : existing sshd processes injected; keeper enabled in Tunnel443.ps1'
    } else {
        Write-Warn2 'inject.exe unavailable - only the Tunnel443 keeper will inject new sshd children'
    }
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
$createdFiles = @()   # exact files WE generated, for a precise uninstall
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
    if (Test-Path $kp) { $hostKeyPaths += $kp; if ($need) { $createdFiles += $kp } }
}
# Record only files this installer actually created so uninstall never deletes
# a pre-existing host key belonging to another setup.
Set-Content -LiteralPath (Join-Path $WorkDir 'installed-files.txt') -Value $createdFiles -Encoding ASCII
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
Write-Step 'SSH banner : removing branding'
Remove-SshdOption -Config $sshdConfig -Name 'Banner'
Remove-Item (Join-Path $sshDir 'banner.txt') -Force -ErrorAction SilentlyContinue
Write-Ok 'SSH banner : removed (no channel/branding banners)'

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
$argParts = @(
    '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Hidden',
    '-File', "`"$tunnelPs`"",
    '-Port', $Port, '-TargetPort', $SshPort, '-CertSubject', "`"$CertSubject`"",
    '-UdpGwPort', $UdpGwPort, '-UdpGwDns', "`"$($DnsServers[0])`"",
    '-LogFile', "`"$LogFile`"", '-SniHost', "`"$SniHost`"",
    '-BindIp', "`"$BindIp`"", '-BindIfIndex', $primaryNic.Index,
    '-BindGateway', "`"$Gateway`"", '-DnsServers', "`"$DnsCsv`"",
    '-ListenerIp', "`"$ListenerIp`"",
    '-RouteStateFile', "`"$RouteState`"", '-BindNicDll', "`"$BindNicDll`""
)
if ($UseInject) { $argParts += '-UseInject' }
$argList = $argParts -join ' '

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
    Write-Ok "Listening on $ListenerIp`:$Port (process: $owner)  ->  127.0.0.1:$SshPort"
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
Write-Host ("  {0} VPS Country:- {1}" -f $chBullet, $countryLabel) -ForegroundColor Yellow
Write-Host ("  {0} IP Address:- {1}" -f $chBullet, $ip) -ForegroundColor Yellow
Write-Host ("  {0} Local NIC IP:- {1}  (physical NIC; UDP and routes are pinned here)" -f $chBullet, $BindIp) -ForegroundColor Yellow
Write-Host ("  {0} Physical DNS:- {1}  (pinned; TUN DNS is ignored)" -f $chBullet, $DnsCsv) -ForegroundColor Yellow
Write-Host ("  {0} port:- {1}" -f $chBullet, $Port) -ForegroundColor Yellow
Write-Host ("  {0} User:- {1}" -f $chBullet, $userName) -ForegroundColor Yellow
Write-Host ("  {0} Pass:- {1}" -f $chBullet, $Pass) -ForegroundColor Yellow
if ($UdpGwPort -gt 0) { Write-Host ("  {0} UDPGW Port:- {1}" -f $chBullet, $UdpGwPort) -ForegroundColor Yellow }
Write-Host '  ========== Http Custom ==========' -ForegroundColor Green
Write-Host ("  {0}:{1}@{2}:{3} {4} {5}" -f $ip, $Port, $userName, $Pass, $chArrow, $flag) -ForegroundColor Yellow
Write-Host '  ------------------------------------------------------------------'
Write-Host ("  # Script V ==> {0} {1}" -f $WinVer, $chCheck) -ForegroundColor Green
Write-Host '  ------------------------------------------------------------------'
Write-Host '  Client settings:  SSH + TLS / SNI  (self-signed OK)'
Write-Host ("  NetMod Host/IP : {0}  {1}" -f $ListenerIp, $(if ($ListenerIp -eq '127.0.0.1') { '(local-only - same PC)' } else { '(physical NIC - NOT the TUN address)' })) -ForegroundColor Cyan
Write-Host ("  NetMod mode    : {0}" -f $(if ($UseInject) { 'TUN/VPN: sshd injection ON, UDP/DNS pinned, route guard active' } else { 'non-TUN recommended: sshd injection OFF; TUN on this host can loop TCP' })) -ForegroundColor Cyan
Write-Host '  Files          :  ' -NoNewline; Write-Host $RootDir
Write-Host '  Log            :  ' -NoNewline; Write-Host $LogFile
Write-Host '  Stop           :  ' -NoNewline; Write-Host ("powershell -File `"{0}`"" -f (Join-Path $RootDir 'Stop-Tunnel.ps1'))
Write-Host '  ------------------------------------------------------------------'
Write-Host ''

try { Stop-Transcript | Out-Null } catch { }
