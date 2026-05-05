<#
.SYNOPSIS
Generates a synthetic Windows Firewall log file for VulcansTrace benchmarking.

.DESCRIPTION
Creates a realistic-volume pfirewall.log file with embedded attack patterns
(port scan, beaconing, lateral movement, flood, policy violation, and novelty)
mixed with normal background traffic. All data is synthetic -- no real IPs or
networks are represented.

.PARAMETER OutputPath
Path to write the generated log file. Defaults to .\benchmark-pfirewall.log

.PARAMETER TotalLines
Approximate number of log lines to generate. Defaults to 50000.

.EXAMPLE
.\Generate-SyntheticFirewallLog.ps1 -TotalLines 50000
Generates ~50,000 line synthetic firewall log at .\benchmark-pfirewall.log
#>
param(
    [string]$OutputPath = ".\benchmark-pfirewall.log",
    [int]$TotalLines = 50000
)

$ErrorActionPreference = "Stop"

# Internal network IPs (10.x.x.x)
$internalServers = @("10.0.0.1","10.0.0.2","10.0.0.10","10.0.0.20","10.0.0.50","10.0.0.100")
$internalWorkstations = @("10.0.1.100","10.0.1.101","10.0.1.102","10.0.1.110","10.0.1.150")
$allInternal = $internalServers + $internalWorkstations

# External IPs used for attack patterns (should not appear in background noise)
$externalIPs = @(
    "203.0.113.10","203.0.113.50","203.0.113.100",
    "198.51.100.20","198.51.100.80",
    "192.0.2.15","192.0.2.45","192.0.2.200",
    "185.220.101.33","45.33.32.156","91.218.114.11"
)

# External IPs used for background noise only (exclude attack-pattern IPs to prevent false positives)
$backgroundExternalIPs = @(
    "203.0.113.10","203.0.113.50","203.0.113.100",
    "198.51.100.20","198.51.100.80",
    "192.0.2.15","192.0.2.45","192.0.2.200"
)

# Common service ports for normal traffic
$commonPorts = @(80, 443, 53, 25, 587, 993, 8080, 8443)

# Admin ports for lateral movement
$adminPorts = @(22, 445, 3389)

# Disallowed outbound ports for policy violations
$disallowedPorts = @(21, 23)

# C2 beaconing destination (dedicated external IP + port)
$c2IP = "185.220.101.33"
$c2Port = 8443

# Scanner IP (external)
$scannerIP = "45.33.32.156"

Write-Host "Generating $TotalLines lines of synthetic firewall log data..."

$sw = [System.Diagnostics.Stopwatch]::StartNew()

$baseTime = [DateTime]::Parse("2025-06-15 08:00:00")
$lines = [System.Collections.Generic.List[string]]::new($TotalLines + 100)

# Header
$lines.Add("#Version: 1.5")
$lines.Add("#Software: Microsoft Windows Firewall")
$lines.Add("#TimeFormat: Local")
$lines.Add("#Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path")

# --- Port Scan: scanner hitting many ports on internal server in a 5-min window ---
$scanTime = $baseTime.AddMinutes(5)
for ($i = 0; $i -lt 150; $i++) {
    $port = 1 + $i
    $ts = $scanTime.AddSeconds($i * 2)
    $lines.Add("$($ts.ToString('yyyy-MM-dd HH:mm:ss')) DROP TCP $scannerIP 10.0.0.1 $($port + 1000) $port 40 S 2461835779 2461835779 65535 - - - SEND")
}

# --- Beaconing: internal workstation calling C2 every 300s for 2 hours ---
$beaconStart = $baseTime.AddMinutes(30)
for ($i = 0; $i -lt 24; $i++) {
    $ts = $beaconStart.AddSeconds($i * 300)
    $lines.Add("$($ts.ToString('yyyy-MM-dd HH:mm:ss')) ALLOW TCP 10.0.1.100 $c2IP $(50000 + $i) $c2Port 256 A 3847561238 3847561238 65535 - - - SEND")
}

# --- Lateral Movement: compromised workstation scanning internal admin ports ---
$lateralStart = $baseTime.AddMinutes(70)
for ($i = 0; $i -lt 10; $i++) {
    $ts = $lateralStart.AddSeconds($i * 15)
    $target = $internalServers[$i % $internalServers.Count]
    $port = $adminPorts[$i % $adminPorts.Count]
    $lines.Add("$($ts.ToString('yyyy-MM-dd HH:mm:ss')) ALLOW TCP 10.0.1.100 $target $(49000 + $i) $port 128 S 2847561238 2847561238 65535 - - - SEND")
}

# --- Flood: high-volume burst from external IP ---
$floodStart = $baseTime.AddMinutes(90)
for ($i = 0; $i -lt 500; $i++) {
    $ts = $floodStart.AddMilliseconds($i * 10)
    $lines.Add("$($ts.ToString('yyyy-MM-dd HH:mm:ss')) DROP TCP 91.218.114.11 10.0.0.10 $(30000 + ($i % 1000)) 443 64 S $(100000000 + $i) $(100000000 + $i) 8192 - - - SEND")
}

# --- Policy Violations: outbound connections on disallowed ports ---
for ($i = 0; $i -lt 8; $i++) {
    $ts = $baseTime.AddMinutes(20 + $i * 45)
    $port = $disallowedPorts[$i % $disallowedPorts.Count]
    $lines.Add("$($ts.ToString('yyyy-MM-dd HH:mm:ss')) ALLOW TCP 10.0.1.102 198.51.100.20 $(52000 + $i) $port 128 A 3947561238 3947561238 65535 - - - SEND")
}

# --- Novelty: one-time connections to unique external IPs ---
$noveltyIPs = @("198.51.100.200","198.51.100.201","198.51.100.202","198.51.100.203","198.51.100.204")
for ($i = 0; $i -lt $noveltyIPs.Count; $i++) {
    $ts = $baseTime.AddMinutes(40 + $i * 30)
    $lines.Add("$($ts.ToString('yyyy-MM-dd HH:mm:ss')) ALLOW TCP 10.0.1.150 $($noveltyIPs[$i]) $(54000 + $i) $(9000 + $i) 64 A 4147561238 4147561238 65535 - - - SEND")
}

# --- Background noise: normal traffic to fill remaining lines ---
$attackLineCount = $lines.Count - 4  # subtract header lines
$remainingLines = $TotalLines - $attackLineCount
if ($remainingLines -lt 0) { $remainingLines = 0 }

$rng = [System.Random]::new(42)  # deterministic seed

# Pre-assign each internal host a small set of preferred external destinations
# to prevent false-positive port scan detection from overly random traffic.
$hostPreferences = @{}
foreach ($hostIp in $allInternal) {
    $prefs = @()
    for ($j = 0; $j -lt 3; $j++) {
        $prefs += @{
            DstIp = $backgroundExternalIPs[$rng.Next($backgroundExternalIPs.Count)]
            Port = $commonPorts[$rng.Next($commonPorts.Count)]
        }
    }
    $hostPreferences[$hostIp] = $prefs
}

for ($i = 0; $i -lt $remainingLines; $i++) {
    $ts = $baseTime.AddSeconds($i * 7)
    
    # 70% outbound, 30% inbound
    if ($rng.Next(100) -lt 70) {
        # Outbound: internal -> external
        $src = $allInternal[$rng.Next($allInternal.Count)]
        $action = if ($rng.Next(100) -lt 90) { "ALLOW" } else { "DROP" }
        
        # 95% of the time use a preferred destination for this host
        if ($rng.Next(100) -lt 95) {
            $pref = $hostPreferences[$src][$rng.Next($hostPreferences[$src].Count)]
            $dst = $pref.DstIp
            $port = $pref.Port
        } else {
            $dst = $backgroundExternalIPs[$rng.Next($backgroundExternalIPs.Count)]
            $port = $commonPorts[$rng.Next($commonPorts.Count)]
        }
    } else {
        # Inbound: external -> internal
        $dst = $allInternal[$rng.Next($allInternal.Count)]
        $src = $backgroundExternalIPs[$rng.Next($backgroundExternalIPs.Count)]
        $port = $commonPorts[$rng.Next($commonPorts.Count)]
        $action = if ($rng.Next(100) -lt 60) { "ALLOW" } else { "DROP" }
    }
    
    $srcPort = 40000 + $rng.Next(25000)
    $size = 40 + $rng.Next(1400)
    
    $lines.Add("$($ts.ToString('yyyy-MM-dd HH:mm:ss')) $action TCP $src $dst $srcPort $port $size A $(1000000000 + $i) $(1000000000 + $i) 65535 - - - SEND")
}

# Write output
$lines | Out-File -FilePath $OutputPath -Encoding UTF8 -Force

$sw.Stop()
$actualLines = $lines.Count - 4  # subtract header
Write-Host ""
Write-Host "Done in $($sw.ElapsedMilliseconds)ms"
Write-Host "Output: $OutputPath"
Write-Host "Total data lines: $actualLines"
Write-Host "Embedded patterns:"
Write-Host "  - Port scan: 150 lines (scanner hitting 150 ports in 5 min)"
Write-Host "  - Beaconing: 24 lines (C2 callback every 300s for 2 hours)"
Write-Host "  - Lateral movement: 10 lines (internal admin port scanning)"
Write-Host "  - Flood: 500 lines (high-volume burst)"
Write-Host "  - Policy violations: 8 lines (outbound on disallowed ports)"
Write-Host "  - Novelty: 5 lines (one-time unique external connections)"
Write-Host "  - Background noise: $remainingLines lines (normal mixed traffic)"
