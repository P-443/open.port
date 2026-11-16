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
      5. starts a TLS listener on <Port> that forwards to 127.0.0.1:<SshPort>
      6. starts a badvpn-compatible UDP gateway on 127.0.0.1:<UdpGwPort> (UDP over the tunnel)
      7. adds firewall rules, registers a start-up scheduled task, tunes TCP
    Must be run as Administrator.
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
    [string] $CertSubject  = 'CN=ssh443-tunnel'
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

function Write-Step   ($m) { Write-Host "  [*] $m" -ForegroundColor Cyan }
function Write-Ok     ($m) { Write-Host "  [v] $m" -ForegroundColor Green }
function Write-Warn2  ($m) { Write-Host "  [!] $m" -ForegroundColor Yellow }
function Write-Err2   ($m) { Write-Host "  [x] $m" -ForegroundColor Red }

# ------------------------------------------------------------------ header
$line = '#' * 74
Write-Host ""
Write-Host $line -ForegroundColor Green
Write-Host "#        SSH over port 443 on Windows  ( no docker / no extra tools )       #" -ForegroundColor Red
Write-Host "#                      Windows port of Run.sh  v1.5                        #" -ForegroundColor Green
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

Write-Host ""
Write-Host "  ------------------------------------------------------------------"
Write-Ok "Input accepted : User=$User  Pass=$Pass  Port=$Port"
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
try { Set-Service -Name sshd -StartupType Automatic -ErrorAction Stop } catch { }
Write-Ok "OpenSSH Server : binaries -> $OpenSshDir"
$sshDir = Join-Path $env:ProgramData 'ssh'
if (-not (Test-Path $sshDir)) { New-Item -ItemType Directory -Force -Path $sshDir | Out-Null }

# host keys
if (-not (Test-Path (Join-Path $sshDir 'ssh_host_rsa_key'))) {
    Write-Step 'OpenSSH Server : generating host keys'
    & (Join-Path $OpenSshDir 'ssh-keygen.exe') -A | Out-Null
}

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

Set-SshdOption -Config $sshdConfig -Name 'Port'                  -Value $SshPort
Set-SshdOption -Config $sshdConfig -Name 'PasswordAuthentication' -Value 'yes'
Set-SshdOption -Config $sshdConfig -Name 'PubkeyAuthentication'   -Value 'yes'
Set-SshdOption -Config $sshdConfig -Name 'PermitEmptyPasswords'   -Value 'no'
Set-SshdOption -Config $sshdConfig -Name 'AllowTcpForwarding'     -Value 'yes'
Set-SshdOption -Config $sshdConfig -Name 'GatewayPorts'           -Value 'yes'
Set-SshdOption -Config $sshdConfig -Name 'ClientAliveInterval'    -Value '30'
Set-SshdOption -Config $sshdConfig -Name 'ClientAliveCountMax'    -Value '6'
# readable sshd log next to the tunnel log (default would go to the event log only)
Set-SshdOption -Config $sshdConfig -Name 'SyslogFacility'         -Value 'LOCAL0'
# channel level logging: shows which host/port every client forward asked for
Set-SshdOption -Config $sshdConfig -Name 'LogLevel'               -Value 'DEBUG2'
Set-SshdOption -Config $sshdConfig -Name 'MaxStartups'            -Value '100:30:200'
Set-SshdOption -Config $sshdConfig -Name 'MaxSessions'            -Value '100'

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

try { $cfgTest = & (Join-Path $OpenSshDir 'sshd.exe') -t -f $sshdConfig 2>&1 } catch { $cfgTest = $_.Exception.Message }
if ($cfgTest) { Write-Warn2 "sshd -t : $cfgTest" } else { Write-Ok 'sshd -t : config OK' }

try {
    Restart-Service sshd -Force -ErrorAction Stop
    if ((Get-Service sshd).Status -ne 'Running') { Start-Service sshd }
    Write-Ok "OpenSSH Server : running on port $SshPort"
} catch { Write-Warn2 "OpenSSH Server : sshd did not start - $($_.Exception.Message)" }

# ------------------------------------------------------------------ 2. ssh banner
Write-Step 'SSH banner : writing'
$Server_Message = '<div><span style="color: #ff0000">[C1]</span><span style="color: #ff0600">[C1]</span><span style="color: #ff0b00">[C1]</span><span style="color: #ff1100">[C1]</span><span style="color: #ff1600">[C1]</span><span style="color: #ff1c00">[C1]</span><span style="color: #ff2100">[C1]</span><span style="color: #ff2700">[C1]</span><span style="color: #ff2c00">[C1]</span><span style="color: #ff3200">[C1]</span><span style="color: #ff3700">[C1]</span><span style="color: #ff3d00">[C1]</span><span style="color: #ff4200">[C2]</span><span style="color: #ff4800">[C3]</span><span style="color: #ff4d00">[C4]</span><span style="color: #ff5300">[C5]</span><span style="color: #ff5800">[C6]</span><span style="color: #ff5e00">[C7]</span><span style="color: #ff6300">[C8]</span><span style="color: #ff6900">[C2]</span></div><div></div><div><span style="color: #ff6e00">D</span><span style="color: #ff7400">e</span><span style="color: #ff7900">v</span><span style="color: #ff7f00">e</span><span style="color: #ff8500">l</span><span style="color: #ff8a00">o</span><span style="color: #ff9000">p</span><span style="color: #ff9500">e</span><span style="color: #ff9b00">r</span><span style="color: #ffa000"> </span><span style="color: #ffa600">:</span><span style="color: #ffac00"> </span><span style="color: #ffb100"> </span><span style="color: #ffb700">l</span><span style="color: #ffbc00">_</span><span style="color: #ffc200">s</span><span style="color: #ffc700">_</span><span style="color: #ffcd00">I</span><span style="color: #ffd200">_</span><span style="color: #ffd800">I</span><span style="color: #ffde00">.</span><span style="color: #ffe300">t</span><span style="color: #ffe900">.</span><span style="color: #ffee00">m</span><span style="color: #fff400">e</span></div><div></div><div><span style="color: #fff900">C</span><span style="color: #ffff00">H</span><span style="color: #f4ff00">A</span><span style="color: #eaff00">N</span><span style="color: #dfff00">N</span><span style="color: #d5ff00">E</span><span style="color: #caff00">L</span><span style="color: #bfff00"> </span><span style="color: #b5ff00">:</span><span style="color: #aaff00"> </span><span style="color: #9fff00">D</span><span style="color: #95ff00">_</span><span style="color: #8aff00">S</span><span style="color: #80ff00">_</span><span style="color: #75ff00">D</span><span style="color: #6aff00">_</span><span style="color: #60ff00">C</span><span style="color: #55ff00">.</span><span style="color: #4aff00">t</span><span style="color: #40ff00">.</span><span style="color: #35ff00">m</span><span style="color: #2bff00">e</span></div><div></div><div><span style="color: #20ff00">S</span><span style="color: #15ff00">t</span><span style="color: #0bff00">a</span><span style="color: #00ff00">t</span><span style="color: #00ff0b">u</span><span style="color: #00ff16">s</span><span style="color: #00ff21">:</span><span style="color: #00ff2c"> </span><span style="color: #00ff37">s</span><span style="color: #00ff43">u</span><span style="color: #00ff4e">c</span><span style="color: #00ff59">c</span><span style="color: #00ff64">e</span><span style="color: #00ff6f">s</span><span style="color: #00ff7a">s</span></div><div></div><div><span style="color: #00ff85">S</span><span style="color: #00ff90">u</span><span style="color: #00ff9b">p</span><span style="color: #00ffa6">p</span><span style="color: #00ffb1">o</span><span style="color: #00ffbc">r</span><span style="color: #00ffc8">t</span><span style="color: #00ffd3"> </span><span style="color: #00ffde">:</span><span style="color: #00ffe9"> </span><span style="color: #00fff4">U</span><span style="color: #00ffff">D</span><span style="color: #00f4ff">P</span><span style="color: #00e9ff">G</span><span style="color: #00deff">W</span><span style="color: #00d3ff"> </span><span style="color: #00c8ff">/</span><span style="color: #00bcff"> </span><span style="color: #00b1ff">G</span><span style="color: #00a6ff">a</span><span style="color: #009bff">m</span><span style="color: #0090ff">e</span><span style="color: #0085ff"> </span><span style="color: #007aff">&</span><span style="color: #006fff"> </span><span style="color: #0064ff">V</span><span style="color: #0059ff">i</span><span style="color: #004eff">d</span><span style="color: #0043ff">e</span><span style="color: #0037ff">o</span><span style="color: #002cff"> </span><span style="color: #0021ff">c</span><span style="color: #0016ff">a</span><span style="color: #000bff">l</span><span style="color: #0000ff">l</span></div>'
$Server_Message = $Server_Message.Replace('[C1]',[string][char]0x3164).Replace('[C2]',[string][char]0x02D7).Replace('[C3]',[string][char]0x02CF).Replace('[C4]',[string][char]0x02CB).Replace('[C5]',[string][char]0x26A1).Replace('[C6]',[string][char]0xFE0E).Replace('[C7]',[string][char]0x02CE).Replace('[C8]',[string][char]0x02CA)

$bannerFile = Join-Path $sshDir 'banner.txt'
[System.IO.File]::WriteAllText($bannerFile, $Server_Message, (New-Object System.Text.UTF8Encoding($false)))
Set-SshdOption -Config $sshdConfig -Name 'Banner' -Value $bannerFile
Restart-Service sshd -Force -ErrorAction SilentlyContinue
Write-Ok "SSH banner : $bannerFile"

# ------------------------------------------------------------------ 3. user
Write-Step "User account : $User"
$sec  = ConvertTo-SecureString $Pass -AsPlainText -Force
$userName = if ($User -match '\\') { $User.Split('\')[-1] } else { $User }
$existing = Get-LocalUser -Name $userName -ErrorAction SilentlyContinue
if ($existing) {
    Set-LocalUser -Name $userName -Password $sec
    if (-not $existing.Enabled) { Enable-LocalUser -Name $userName }
    Write-Warn2 "User already existed - password updated"
} else {
    New-LocalUser -Name $userName -Password $sec -PasswordNeverExpires -AccountNeverExpires -Description 'SSH tunnel account' | Out-Null
    Write-Ok 'User created'
}
if ($userName -ne 'Administrator') {
    # the shipped sshd_config has:  AllowGroups administrators "openssh users"
    # so every SSH login must be a member of that group (or of administrators)
    if (-not (Get-LocalGroup -Name 'openssh users' -ErrorAction SilentlyContinue)) {
        New-LocalGroup -Name 'openssh users' -Description 'OpenSSH login users' | Out-Null
        Write-Step "Created local group 'openssh users'"
    }
    Add-LocalGroupMember -Group 'openssh users' -Member $userName -ErrorAction SilentlyContinue
    try { Add-LocalGroupMember -Group 'Users' -Member $userName -ErrorAction SilentlyContinue } catch { }
}
# make sure the account is NOT an administrator (mirrors the linux non-root user)
try {
    $admins = Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue
    if ($admins -and ($admins.Name -split '\\')[-1] -contains $userName) {
        Remove-LocalGroupMember -Group 'Administrators' -Member $userName -ErrorAction SilentlyContinue
    }
} catch { }
Write-Ok "User $userName ready (password auth)"

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
    Write-Ok "Firewall : TCP $Port open  (+ SSH $SshPort)"
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
$tunnelPs = Join-Path $RootDir 'Tunnel443.ps1'
$argList = @(
    '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Hidden',
    '-File', "`"$tunnelPs`"",
    '-Port', $Port, '-TargetPort', $SshPort, '-CertSubject', "`"$CertSubject`"",
    '-UdpGwPort', $UdpGwPort, '-LogFile', "`"$LogFile`"", '-SniHost', "`"$SniHost`""
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
for ($i = 0; $i -lt 15; $i++) {
    Start-Sleep -Seconds 1
    $l = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
    if ($l) { $ok = $true; break }
}
if ($ok) {
    $owner = (Get-Process -Id $l[0].OwningProcess -ErrorAction SilentlyContinue).ProcessName
    Write-Ok "Listening on port $Port (process: $owner)"
} else {
    Write-Err2 "Nothing is listening on port $Port - check $LogFile"
    if (Test-Path $LogFile) { Get-Content $LogFile -Tail 15 | ForEach-Object { Write-Host "      $_" -ForegroundColor DarkGray } }
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
Write-Host ("  {0} port:- {1}" -f $chBullet, $Port) -ForegroundColor Yellow
Write-Host ("  {0} User:- {1}" -f $chBullet, $userName) -ForegroundColor Yellow
Write-Host ("  {0} Pass:- {1}" -f $chBullet, $Pass) -ForegroundColor Yellow
if ($UdpGwPort -gt 0) { Write-Host ("  {0} UDPGW Port:- {1}" -f $chBullet, $UdpGwPort) -ForegroundColor Yellow }
Write-Host '  ========== Http Custom ==========' -ForegroundColor Green
Write-Host ("  {0}:{1}@{2}:{3} {4} {5}" -f $ip, $Port, $userName, $Pass, $chArrow, $flag) -ForegroundColor Yellow
Write-Host '  ------------------------------------------------------------------'
Write-Host '  # DEV:- l_s_I_I.T.ME' -ForegroundColor DarkGray
Write-Host ("  # Script V ==> 1.5 {0}" -f $chCheck) -ForegroundColor Green
Write-Host '  ------------------------------------------------------------------'
Write-Host '  Client settings:  SSH + TLS / SNI  (self-signed OK)'
Write-Host '  Files          :  ' -NoNewline; Write-Host $RootDir
Write-Host '  Log            :  ' -NoNewline; Write-Host $LogFile
Write-Host '  Stop           :  ' -NoNewline; Write-Host ("powershell -File `"{0}`"" -f (Join-Path $RootDir 'Stop-Tunnel.ps1'))
Write-Host '  ------------------------------------------------------------------'
Write-Host ''

try { Stop-Transcript | Out-Null } catch { }
