#requires -Version 5.1
<#
    Stop-Tunnel.ps1  -  stop / remove the SSH-over-443 tunnel
    Switches:
      -Uninstall   also remove firewall rules, scheduled task, certificate,
                   generated files and the local SSH user
      -KeepUser    with -Uninstall, keep the local SSH user (otherwise removed)
      -RemoveUser  legacy alias; -Uninstall already removes the user
      -User <name> user to delete (default: telegram)
#>
[CmdletBinding()]
param(
    [int]    $Port = 443,
    [switch] $Uninstall,
    [switch] $RemoveUser,
    [switch] $KeepUser,
    [string] $User = 'telegram',
    [string] $CertSubject = 'CN=ssh443-tunnel',
    [int]    $UdpGwPort = 7300
)

$ErrorActionPreference = 'Continue'
$TaskName   = 'SSH443-Tunnel'
$WorkDir    = Join-Path $env:ProgramData 'ssh443'
$nicFile    = Join-Path $WorkDir 'primary-ip.txt'
$RouteState = Join-Path $WorkDir 'samehost-routes.txt'
$CreatedList = Join-Path $WorkDir 'installed-files.txt'

function Say ($m, $c = 'Cyan') { Write-Host "  [*] $m" -ForegroundColor $c }

function Remove-OneRoute {
    param([string]$Prefix, [int]$IfIndex, [string]$Hop)
    $wantHop = if ($Hop) { $Hop } else { '0.0.0.0' }
    $removed = 0
    foreach ($store in @('ActiveStore', 'PersistentStore')) {
        try {
            $routes = @(Get-NetRoute -DestinationPrefix $Prefix -PolicyStore $store -ErrorAction SilentlyContinue)
        } catch { continue }
        foreach ($r in $routes) {
            $rHop = if ($r.NextHop) { [string]$r.NextHop } else { '0.0.0.0' }
            if ($IfIndex -gt 0 -and [int]$r.InterfaceIndex -ne $IfIndex) { continue }
            if ($rHop -ne $wantHop) { continue }
            try {
                Remove-NetRoute -InputObject $r -Confirm:$false -ErrorAction SilentlyContinue
                $removed++
            } catch { }
        }
    }
    return $removed
}

function Remove-OurRoutes {
    $specs = New-Object System.Collections.Generic.List[object]

    # v1.9 state file: one "prefix|ifIndex|nextHop" per line. Only routes that
    # THIS script added are recorded, so a pre-existing user route is untouched.
    if (Test-Path $RouteState) {
        foreach ($line in @(Get-Content -LiteralPath $RouteState -ErrorAction SilentlyContinue)) {
            if ($line -match '^\s*(\S+/32)\|(\d+)\|(\S+)\s*$') {
                $specs.Add([pscustomobject]@{ Prefix = $Matches[1]; If = [int]$Matches[2]; Hop = $Matches[3] })
            }
        }
    }

    # Backwards compatibility: older installs only wrote the IP (and later the
    # gateway/DNS) into primary-ip.txt.
    if (Test-Path $nicFile) {
        $lines = @(Get-Content -LiteralPath $nicFile -ErrorAction SilentlyContinue | ForEach-Object { $_.Trim() })
        $ifIndex = 0
        if ($lines.Count -gt 1) { $n = 0; if ([int]::TryParse($lines[1], [ref]$n)) { $ifIndex = $n } }
        if ($lines.Count -gt 0 -and $lines[0] -match '^\d+\.\d+\.\d+\.\d+$') {
            $specs.Add([pscustomobject]@{ Prefix = "$($lines[0])/32"; If = $ifIndex; Hop = '' })
        }
        $gw = if ($lines.Count -gt 2) { $lines[2] } else { '' }
        if ($gw -match '^\d+\.\d+\.\d+\.\d+$') {
            $specs.Add([pscustomobject]@{ Prefix = "$gw/32"; If = $ifIndex; Hop = '' })
            if ($lines.Count -gt 3 -and $lines[3]) {
                foreach ($d in $lines[3].Split(',')) {
                    $d = $d.Trim()
                    if ($d -match '^\d+\.\d+\.\d+\.\d+$' -and $d -ne $gw) {
                        $specs.Add([pscustomobject]@{ Prefix = "$d/32"; If = $ifIndex; Hop = $gw })
                    }
                }
            }
        }
    }

    $total = 0
    foreach ($s in $specs) { $total += (Remove-OneRoute $s.Prefix $s.If $s.Hop) }
    if ($total -gt 0) { Say "removed $total same-host /32 route(s)" 'Green' }
    else { Say 'no same-host routes to remove' 'Yellow' }
}

function Stop-PortHolders {
    foreach ($p in @($Port, $UdpGwPort)) {
        if ($p -le 0) { continue }
        $pids = New-Object System.Collections.Generic.HashSet[int]

        try {
            foreach ($c in @(Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue)) {
                [void]$pids.Add([int]$c.OwningProcess)
            }
        } catch { }
        try {
            # UDPGW is UDP - the old script only looked at TCP listeners.
            foreach ($u in @(Get-NetUDPEndpoint -LocalPort $p -ErrorAction SilentlyContinue)) {
                [void]$pids.Add([int]$u.OwningProcess)
            }
        } catch { }

        foreach ($id in $pids) {
            $proc = Get-Process -Id $id -ErrorAction SilentlyContinue
            if ($proc -and $proc.ProcessName -match 'powershell|pwsh') {
                Say "stopping $($proc.ProcessName) ($id) holding port $p"
                Stop-Process -Id $id -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

Say 'Stopping scheduled task ...'
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Say 'task stopped' 'Green'
} else { Say 'task not found' 'Yellow' }

Stop-PortHolders
Remove-OurRoutes

# Restart sshd so any already-injected sshd.exe processes unload bindnic.dll.
if (Get-Service sshd -ErrorAction SilentlyContinue) {
    Say 'Restarting sshd to unload the NIC shim ...'
    Restart-Service sshd -Force -ErrorAction SilentlyContinue
}

if (-not $Uninstall) { Say 'Done (tunnel stopped, routes and shim processes cleaned).' 'Green'; exit 0 }

Say 'Removing scheduled task ...'
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

# Only files this installer actually generated - never a pre-existing host key.
if (Test-Path $CreatedList) {
    foreach ($f in @(Get-Content -LiteralPath $CreatedList -ErrorAction SilentlyContinue)) {
        if ($f -and (Test-Path -LiteralPath $f)) {
            Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue
            Say "removed generated file $f" 'Green'
        }
    }
}

# Native helper (code) and the separate data-only shim log directory.
$nativeDir = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'native'
if (Test-Path $nativeDir) {
    Get-ChildItem -LiteralPath $nativeDir -File -ErrorAction SilentlyContinue |
        Remove-Item -Force -ErrorAction SilentlyContinue
    Say 'removed native helper files' 'Green'
}
$shimLogDir = Join-Path $WorkDir 'shim-logs'
if (Test-Path $shimLogDir) {
    Remove-Item -LiteralPath $shimLogDir -Recurse -Force -ErrorAction SilentlyContinue
    Say 'removed shim log directory' 'Green'
}
foreach ($l in @((Join-Path $env:WINDIR 'Temp\bindnic.log'),
                 (Join-Path $env:TEMP 'bindnic.log'))) {
    Remove-Item -LiteralPath $l -Force -ErrorAction SilentlyContinue
}

Say 'Removing firewall rules ...'
foreach ($name in @("SSH443-Tunnel-$Port", 'SSH443-Tunnel-22',
                    'OpenSSH-Server-In-TCP', 'OpenSSH-Server-Out')) {
    Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue |
        Remove-NetFirewallRule -ErrorAction SilentlyContinue
}
Get-NetFirewallRule -DisplayName 'SSH443-Tunnel-*' -ErrorAction SilentlyContinue |
    Remove-NetFirewallRule -ErrorAction SilentlyContinue

Say 'Removing certificate ...'
Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -eq $CertSubject } |
    Remove-Item -Force -ErrorAction SilentlyContinue

Say 'Removing ssh banner and per-user authorized_keys ...'
$cfg = Join-Path $env:ProgramData 'ssh\sshd_config'
if (Test-Path $cfg) {
    $kept = Get-Content -LiteralPath $cfg | Where-Object { $_ -notmatch '^\s*#?\s*Banner\s+' }
    Set-Content -LiteralPath $cfg -Value $kept -Encoding ASCII
}
Remove-Item (Join-Path $env:ProgramData 'ssh\banner.txt') -Force -ErrorAction SilentlyContinue
$akFile = Join-Path $env:ProgramData ("ssh\authorized_keys\" + $User)
Remove-Item -LiteralPath $akFile -Force -ErrorAction SilentlyContinue
$akDir = Join-Path $env:ProgramData 'ssh\authorized_keys'
if ((Test-Path $akDir) -and -not (Get-ChildItem -LiteralPath $akDir -Force -ErrorAction SilentlyContinue)) {
    Remove-Item -LiteralPath $akDir -Force -ErrorAction SilentlyContinue
}

if (-not $KeepUser) {
    Say "Removing local user $User ..."
    Remove-LocalUser -Name $User -ErrorAction SilentlyContinue
}

# State files last: route removal above still needs them.
Remove-Item $nicFile -Force -ErrorAction SilentlyContinue
Remove-Item $RouteState -Force -ErrorAction SilentlyContinue
Remove-Item $CreatedList -Force -ErrorAction SilentlyContinue

# Installer scripts, then this script itself as the very last action.
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
foreach ($f in @('Run.ps1','Tunnel443.ps1','README.md')) {
    Remove-Item -LiteralPath (Join-Path $root $f) -Force -ErrorAction SilentlyContinue
}
if (Test-Path $WorkDir) {
    Remove-Item -LiteralPath $WorkDir -Recurse -Force -ErrorAction SilentlyContinue
    Say 'removed installer work directory' 'Green'
}
Say 'Uninstall finished.' 'Green'
Remove-Item -LiteralPath $MyInvocation.MyCommand.Path -Force -ErrorAction SilentlyContinue
