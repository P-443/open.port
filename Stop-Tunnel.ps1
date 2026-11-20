#requires -Version 5.1
<#
    Stop-Tunnel.ps1  -  stop / remove the SSH-over-443 tunnel
    Switches:
      -Uninstall   also remove firewall rules, scheduled task, certificate,
                   the ssh banner line and (optionally) the SSH user
      -RemoveUser  with -Uninstall, also delete the local user
      -User <name> user to delete with -RemoveUser (default: telegram)
#>
[CmdletBinding()]
param(
    [int]    $Port = 443,
    [switch] $Uninstall,
    [switch] $RemoveUser,
    [string] $User = 'telegram',
    [string] $CertSubject = 'CN=ssh443-tunnel',
    [int]    $UdpGwPort = 7300
)

$ErrorActionPreference = 'Continue'
$TaskName = 'SSH443-Tunnel'
$WorkDir  = Join-Path $env:ProgramData 'ssh443'

function Say  ($m, $c = 'Cyan') { Write-Host "  [*] $m" -ForegroundColor $c }

Say 'Stopping scheduled task ...'
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Say 'task stopped' 'Green'
} else { Say 'task not found' 'Yellow' }

# kill whatever still holds the tunnel port / udpgw port
foreach ($p in @($Port, $UdpGwPort)) {
    if ($p -le 0) { continue }
    $conns = Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue
    foreach ($c in $conns) {
        $proc = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
        if ($proc -and $proc.ProcessName -match 'powershell|pwsh') {
            Say "stopping $($proc.ProcessName) ($($proc.Id)) holding port $p"
            Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        }
    }
}

if (-not $Uninstall) { Say 'Done (tunnel stopped).' 'Green'; exit 0 }

Say 'Removing scheduled task ...'
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

# remove the pinned primary-NIC route and the saved IP used by Tunnel443.ps1
$nicFile = Join-Path $WorkDir 'primary-ip.txt'
if (Test-Path $nicFile) {
    $bindIp = (Get-Content -LiteralPath $nicFile -TotalCount 1).Trim()
    if ($bindIp -and $bindIp -ne '0.0.0.0') {
        foreach ($store in 'PersistentStore', 'ActiveStore') {
            Get-NetRoute -DestinationPrefix "$bindIp/32" -PolicyStore $store -ErrorAction SilentlyContinue |
                Remove-NetRoute -PolicyStore $store -Confirm:$false -ErrorAction SilentlyContinue
        }
        Say "removed pinned route for $bindIp" 'Green'
    }
    Remove-Item $nicFile -Force -ErrorAction SilentlyContinue
}

# remove the native sshd NIC shim. Processes already injected keep the DLL
# mapped until they exit; the sshd restart below drops those copies.
$nativeDir = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'native'
if (Test-Path $nativeDir) {
    foreach ($f in 'bindnic.dll','inject.exe','bindnic.cfg') {
        Remove-Item (Join-Path $nativeDir $f) -Force -ErrorAction SilentlyContinue
    }
    Say 'removed sshd NIC shim files' 'Green'
}

Say 'Removing firewall rules ...'
Get-NetFirewallRule -DisplayName 'SSH443-Tunnel-*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue

Say 'Removing certificate ...'
Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -eq $CertSubject } | Remove-Item -Force -ErrorAction SilentlyContinue

Say 'Removing ssh banner ...'
$cfg = Join-Path $env:ProgramData 'ssh\sshd_config'
if (Test-Path $cfg) {
    $kept = Get-Content -LiteralPath $cfg | Where-Object { $_ -notmatch '^\s*#?\s*Banner\s+' }
    Set-Content -LiteralPath $cfg -Value $kept -Encoding ASCII
    Remove-Item (Join-Path $env:ProgramData 'ssh\banner.txt') -Force -ErrorAction SilentlyContinue
    Restart-Service sshd -Force -ErrorAction SilentlyContinue
}

if ($RemoveUser) {
    Say "Removing local user $User ..."
    Remove-LocalUser -Name $User -ErrorAction SilentlyContinue
}

if (Test-Path $WorkDir) {
    Say "Logs kept in $WorkDir (delete manually if you want)"
}

Say 'Uninstall finished.' 'Green'
