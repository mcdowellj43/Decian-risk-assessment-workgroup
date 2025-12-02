<#
    winPEAS-Lite.ps1
    FINAL VERSION — 14 NON-ADMIN CHECKS
    • PASS / FAIL only (no unknowns)
    • All checks wrapped in try/catch
    • Guaranteed PASS/FAIL summary
    • Full evidence saved to text report
#>

Write-Host "`n==================================================" -ForegroundColor Cyan
Write-Host "                DECIAN SECURITY AUDIT"
Write-Host "==================================================`n" -ForegroundColor Cyan

# --------------------------------------------------------
# SETUP
# --------------------------------------------------------
$ComputerName = $env:COMPUTERNAME
$DateStamp = Get-Date -Format "yyyy-MM-dd_HH-mm"
$ReportDir = "$env:USERPROFILE\AuditReports"

if (!(Test-Path $ReportDir)) { New-Item -Path $ReportDir -ItemType Directory | Out-Null }

$ReportFile = "$ReportDir\System_Audit_${ComputerName}_$DateStamp.txt"

function Out-Report {
    param([Parameter(ValueFromPipeline=$true)] $Text)
    $Text | Out-String | Add-Content -Path $ReportFile
}

# --------------------------------------------------------
# PASS / FAIL TRACKING
# --------------------------------------------------------
$Results = New-Object System.Collections.ArrayList

function Add-Result {
    param(
        [int]$ID,
        [string]$Status,
        [string]$Reason
    )
    $newResult = [PSCustomObject]@{
        Check = $ID
        Status = $Status
        Reason = $Reason
    }
    $null = $Results.Add($newResult)

    # Display real-time status in terminal
    $color = if ($Status -eq "PASS") { "Green" } else { "Red" }
    Write-Host "[$Status] Check $ID - $Reason" -ForegroundColor $color
}

# --------------------------------------------------------
# BEGIN REPORT
# --------------------------------------------------------
Out-Report "=================================================="
Out-Report " DECIAN SECURITY AUDIT REPORT"
Out-Report "=================================================="
Out-Report "Hostname: $ComputerName"
Out-Report "Date: $(Get-Date)"
Out-Report "`n"


# --------------------------------------------------------
# 1. SYSTEM INFO — OS SUPPORT
# --------------------------------------------------------
Write-Host "`n[RUNNING] Check 1 - System Info..." -ForegroundColor Yellow
Out-Report "`n=== 1. SYSTEM INFO ===`n"
try {
    $sys = systeminfo
    $sys | Out-Report

    $supported = @(
        "Windows 11 24H2","Windows 11 23H2","Windows 11 22H2",
        "Windows 11 Enterprise","Windows 11 Pro","Windows 11 Home",
        "Windows 11 Education","Windows 11 IoT Enterprise",
        "Windows Server 2025","Windows Server 2022","Windows Server 2019",
        "Windows Server 2016","Windows Server Core 2022",
        "Windows Server Core 2019","Windows Server Core 2016",
        "Windows Server IoT 2022","Windows 10 IoT Enterprise LTSC 2021",
        "Windows 10 IoT Enterprise LTSC 2019"
    )

    $unsupported = @(
        "Windows 10 21H2","Windows 10 21H1","Windows 10 20H2","Windows 10 2004",
        "Windows 10 1909","Windows 10 1903","Windows 10 1809","Windows 10 1803",
        "Windows 10 1709","Windows 10 1703","Windows 10 1607","Windows 10 1511",
        "Windows 10 1507","Windows 8.1","Windows 8","Windows 7","Windows Vista",
        "Windows XP","Windows 2000","Windows NT","Windows 98","Windows 95",
        "Windows Server 2012","Windows Server 2012 R2","Windows Server 2008",
        "Windows Server 2008 R2","Windows Server 2003","Windows Server 2003 R2",
        "Windows Embedded"
    )

    $osLine = ($sys | Select-String "OS Name").ToString()
    $detectedOS = $osLine.Split(":")[1].Trim()

    # Check for supported patterns in the OS name
    $isSupported = $false
    $supportedPatterns = @(
        "Windows 11", "Windows Server 2025", "Windows Server 2022",
        "Windows Server 2019", "Windows Server 2016", "Windows 10 IoT Enterprise LTSC"
    )

    foreach ($pattern in $supportedPatterns) {
        if ($detectedOS -like "*$pattern*") {
            $isSupported = $true
            break
        }
    }

    if ($isSupported) {
        Add-Result 1 "PASS" "Supported OS: $detectedOS"
    } else {
        Add-Result 1 "FAIL" "Unsupported OS: $detectedOS"
    }
}
catch {
    Add-Result 1 "FAIL" "System info could not be read"
}

# --------------------------------------------------------
# 2. HOTFIX CURRENCY
# --------------------------------------------------------
Write-Host "`n[RUNNING] Check 2 - Hotfix Currency..." -ForegroundColor Yellow
Out-Report "`n=== 2. INSTALLED HOTFIXES ===`n"
try {
    $hotfix = Get-HotFix | Sort-Object -Property InstalledOn -Descending
    $hotfix | Out-Report

    if ($hotfix.Count -eq 0) {
        Add-Result 2 "FAIL" "No hotfixes installed"
    }
    else {
        $days = (New-TimeSpan -Start $hotfix[0].InstalledOn -End (Get-Date)).Days
        if ($days -le 30) { Add-Result 2 "PASS" "Last update $days days ago" }
        else { Add-Result 2 "FAIL" "Last update $days days ago" }
    }
}
catch {
    Add-Result 2 "FAIL" "Hotfix list could not be retrieved"
}

# --------------------------------------------------------
# 3. DRIVE SPACE
# --------------------------------------------------------
Write-Host "`n[RUNNING] Check 3 - Drive Space..." -ForegroundColor Yellow
Out-Report "`n=== 3. DRIVE SPACE ===`n"
try {
    $drive = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Name -eq "C" }
    $drive | Out-Report

    $pct = [math]::Round(($drive.Free / ($drive.Used + $drive.Free)) * 100, 2)

    if ($pct -gt 15) { Add-Result 3 "PASS" "Free space: $pct%" }
    else { Add-Result 3 "FAIL" "Free space low: $pct%" }
}
catch {
    Add-Result 3 "FAIL" "Drive information unavailable"
}

# --------------------------------------------------------
# 4. ANTIVIRUS STATUS
# --------------------------------------------------------
Write-Host "`n[RUNNING] Check 4 - Antivirus Status..." -ForegroundColor Yellow
Out-Report "`n=== 4. ANTIVIRUS STATUS ===`n"
try {
    $av = Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName AntivirusProduct
    $av | Out-Report

    $goodAV = @("Defender","Sentinel","CrowdStrike","Sophos","Bitdefender","Carbon","Cisco")

    $active = $av.displayName | Where-Object { $goodAV | ForEach-Object { $av.displayName -match $_ } }

    if ($active) { Add-Result 4 "PASS" "Detected: $($av.displayName -join ', ')" }
    else { Add-Result 4 "FAIL" "No reputable AV detected" }
}
catch {
    Add-Result 4 "FAIL" "Unable to query antivirus"
}

# --------------------------------------------------------
# 5. LISTENING PORTS
# --------------------------------------------------------
Write-Host "`n[RUNNING] Check 5 - Listening Ports..." -ForegroundColor Yellow
Out-Report "`n=== 5. LISTENING PORTS ===`n"
try {
    $ports = Get-NetTCPConnection -State Listen
    $ports | Out-Report

    $risky = @(21,22,23,25,3389)
    $bad = $ports | Where-Object { $risky -contains $_.LocalPort -and $_.LocalAddress -ne "127.0.0.1" }

    if ($bad.Count -eq 0) { Add-Result 5 "PASS" "No risky ports exposed" }
    else { Add-Result 5 "FAIL" "Risky ports exposed: $($bad.LocalPort -join ', ')" }
}
catch {
    Add-Result 5 "FAIL" "Unable to query listening ports"
}

# --------------------------------------------------------
# 6. FIREWALL PROFILES
# --------------------------------------------------------
Write-Host "`n[RUNNING] Check 6 - Firewall Profiles..." -ForegroundColor Yellow
Out-Report "`n=== 6. FIREWALL PROFILES ===`n"
try {
    $fw = Get-NetFirewallProfile
    $fw | Out-Report

    if ($fw.Enabled -contains $false) {
        Add-Result 6 "FAIL" "One or more firewall profiles disabled"
    }
    else {
        Add-Result 6 "PASS" "All firewall profiles enabled"
    }
}
catch {
    Add-Result 6 "FAIL" "Unable to retrieve firewall profiles"
}

# --------------------------------------------------------
# 7. FIREWALL RULES
# --------------------------------------------------------
Write-Host "`n[RUNNING] Check 7 - Firewall Rules..." -ForegroundColor Yellow
Out-Report "`n=== 7. FIREWALL RULES ===`n"
try {
    $rules = Get-NetFirewallRule | Where-Object { $_.Direction -eq "Inbound" -and $_.Action -eq "Allow" }
    $rules | Out-Report

    $allowAll = $rules | Where-Object { $_.DisplayName -match "Any" }

    if ($allowAll.Count -eq 0) { Add-Result 7 "PASS" "No allow-all inbound rules" }
    else { Add-Result 7 "FAIL" "Insecure inbound allow-all detected" }
}
catch {
    Add-Result 7 "FAIL" "Unable to read firewall rules"
}

# --------------------------------------------------------
# 8. WHOAMI PRIVILEGES
# --------------------------------------------------------
Write-Host "`n[RUNNING] Check 8 - User Privileges..." -ForegroundColor Yellow
Out-Report "`n=== 8. WHOAMI PRIVILEGES ===`n"
try {
    $who = whoami /all
    $who | Out-Report

    $danger = @(
        "SeDebugPrivilege","SeImpersonatePrivilege","SeBackupPrivilege",
        "SeRestorePrivilege","SeTakeOwnershipPrivilege","SeLoadDriverPrivilege",
        "SeTcbPrivilege","SeCreateTokenPrivilege","SeSecurityPrivilege",
        "SeSystemEnvironmentPrivilege","SeSystemProfilePrivilege",
        "SeRelabelPrivilege","SeAssignPrimaryTokenPrivilege",
        "SeManageVolumePrivilege","SeRemoteShutdownPrivilege",
        "SeSyncAgentPrivilege","SeUndockPrivilege",
        "SeIncreaseBasePriorityPrivilege","SeIncreaseQuotaPrivilege"
    )

    $bad = $danger | Where-Object { $who -match $_ }

    if ($bad.Count -eq 0) { Add-Result 8 "PASS" "No dangerous privileges assigned" }
    else { Add-Result 8 "FAIL" "Dangerous privileges: $($bad -join ', ')" }
}
catch {
    Add-Result 8 "FAIL" "Unable to check user privileges"
}

# --------------------------------------------------------
# 9. LOCAL USERS
# --------------------------------------------------------
Write-Host "`n[RUNNING] Check 9 - Local Users..." -ForegroundColor Yellow
Out-Report "`n=== 9. LOCAL USERS ===`n"
try {
    $users = Get-LocalUser
    $users | Out-Report

    $stale = $users | Where-Object { $_.LastLogon -and ((Get-Date) - $_.LastLogon).Days -gt 60 }
    $guestEnabled = $users | Where-Object { $_.Name -eq "Guest" -and $_.Enabled -eq $true }

    if ($stale -or $guestEnabled) {
        Add-Result 9 "FAIL" "Stale or insecure accounts detected"
    }
    else {
        Add-Result 9 "PASS" "Local accounts OK"
    }
}
catch {
    Add-Result 9 "FAIL" "Unable to retrieve local users"
}

# --------------------------------------------------------
# 10. LOCAL ADMIN GROUP
# --------------------------------------------------------
Write-Host "`n[RUNNING] Check 10 - Local Administrators..." -ForegroundColor Yellow
Out-Report "`n=== 10. LOCAL ADMINISTRATORS ===`n"
try {
    $admins = Get-LocalGroupMember -Group "Administrators"
    $admins | Out-Report

    $unexpected = $admins | Where-Object { $_.Name -notmatch "Administrator|Domain Admins" }

    if ($unexpected.Count -eq 0) { Add-Result 10 "PASS" "No unauthorized admins" }
    else { Add-Result 10 "FAIL" "Unauthorized admins: $($unexpected.Name -join ', ')" }
}
catch {
    Add-Result 10 "FAIL" "Unable to read Administrators group"
}

# --------------------------------------------------------
# 11. INSTALLED SOFTWARE
# --------------------------------------------------------
Write-Host "`n[RUNNING] Check 11 - Installed Software..." -ForegroundColor Yellow
Out-Report "`n=== 11. INSTALLED SOFTWARE ===`n"
try {
    $soft = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*,
                     HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
                     Select DisplayName,DisplayVersion

    $soft | Out-Report

    $badSoft = @("Java","Flash","uTorrent","BitTorrent","Thunderbird","7-Zip","VLC")

    $badFound = $soft | Where-Object {
        $name = $_.DisplayName
        if ($name) { $badSoft | ForEach-Object { if ($name -like "*$_*") { $true } } }
    }

    if ($badFound.Count -eq 0) { Add-Result 11 "PASS" "No insecure/outdated software" }
    else { Add-Result 11 "FAIL" "Insecure/outdated software present" }
}
catch {
    Add-Result 11 "FAIL" "Unable to query installed software"
}

# --------------------------------------------------------
# 12. EVENT LOG CHANNELS
# --------------------------------------------------------
Write-Host "`n[RUNNING] Check 12 - Event Log Channels..." -ForegroundColor Yellow
Out-Report "`n=== 12. EVENT LOG CHANNELS ===`n"
try {
    $channels = wevtutil el
    $channels | Out-Report

    if (
        $channels -contains "Security" -and
        $channels -contains "System" -and
        $channels -contains "Application"
    ) {
        Add-Result 12 "PASS" "Required logs enabled"
    }
    else {
        Add-Result 12 "FAIL" "Core logs missing"
    }
}
catch {
    Add-Result 12 "FAIL" "Unable to retrieve event log channels"
}

# --------------------------------------------------------
# 13. WINDOWS UPDATE POLICY
# --------------------------------------------------------
Write-Host "`n[RUNNING] Check 13 - Windows Update Policy..." -ForegroundColor Yellow
Out-Report "`n=== 13. WINDOWS UPDATE POLICY ===`n"
try {
    $wu = Get-ItemProperty HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -ErrorAction Stop
    $wu | Out-Report

    if ($wu.AUOptions -ge 3) { Add-Result 13 "PASS" "Automatic updates enabled" }
    else { Add-Result 13 "FAIL" "Automatic updates disabled" }
}
catch {
    Add-Result 13 "FAIL" "Unable to retrieve update policy"
}

# --------------------------------------------------------
# 14. POWERSHELL CONFIGURATION
# --------------------------------------------------------
Write-Host "`n[RUNNING] Check 14 - PowerShell Configuration..." -ForegroundColor Yellow
Out-Report "`n=== 14. POWERSHELL CONFIGURATION ===`n"
try {
    $psv = $PSVersionTable
    $psv | Out-Report

    $ep = Get-ExecutionPolicy -List
    $ep | Out-Report

    if ($psv.PSVersion.Major -lt 5) {
        Add-Result 14 "FAIL" "PowerShell version < 5.1"
    }
    elseif ($ep.LocalMachine -eq "Unrestricted" -or $ep.CurrentUser -eq "Unrestricted") {
        Add-Result 14 "FAIL" "ExecutionPolicy is Unrestricted"
    }
    else {
        Add-Result 14 "PASS" "PowerShell config OK"
    }
}
catch {
    Add-Result 14 "FAIL" "Unable to read PowerShell configuration"
}


# --------------------------------------------------------
# SUMMARY OUTPUT
# --------------------------------------------------------
Write-Host "`n==================================================" -ForegroundColor Cyan
Write-Host "                     SUMMARY"
Write-Host "==================================================`n" -ForegroundColor Cyan

$passed = ($Results | Where-Object { $_.Status -eq "PASS" })
$failed = ($Results | Where-Object { $_.Status -eq "FAIL" })

Write-Host "TOTAL PASSED: $($passed.Count)" -ForegroundColor Green
Write-Host "TOTAL FAILED: $($failed.Count)" -ForegroundColor Red

if ($passed.Count -gt 0) {
    Write-Host "`nPASSED CHECKS:" -ForegroundColor Green
    foreach ($p in $passed) {
        Write-Host "  [+] Check $($p.Check): $($p.Reason)" -ForegroundColor Green
    }
}

if ($failed.Count -gt 0) {
    Write-Host "`nFAILED CHECKS:" -ForegroundColor Red
    foreach ($f in $failed) {
        Write-Host "  [-] Check $($f.Check): $($f.Reason)" -ForegroundColor Red
    }
}

Write-Host "`nFull evidence saved to:" -ForegroundColor Yellow
Write-Host "$ReportFile" -ForegroundColor White
Write-Host ""
