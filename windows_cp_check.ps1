<# 
CyberPatriot Windows Initial Checklist & Report Script
Run as Administrator (Right-click PowerShell -> Run as administrator)
This script only READS and REPORTS vulnerabilities with suggested fix commands.
Generates 3 report files in the current directory.
Author: Adapted for CyberPatriot Windows
Date: 2025
#>

Write-Host "============================================================"
Write-Host "    CyberPatriot Windows Hardening Checklist Script"
Write-Host "    This script only READS and REPORTS (and suggests fixes)"
Write-Host "============================================================"
Write-Host ""

# Create report files
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$SYS_REPORT  = Join-Path (Get-Location) "cyberpatriot_sys_report_$Timestamp.txt"
$USER_REPORT = Join-Path (Get-Location) "cyberpatriot_user_report_$Timestamp.txt"
$APP_REPORT  = Join-Path (Get-Location) "cyberpatriot_app_report_$Timestamp.txt"

@"
CyberPatriot Windows Hardening Application Report - $(Get-Date)
Hostname: $(hostname)
OS: $((Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ProductName) $((Get-WmiObject Win32_OperatingSystem).Version)
===========================================

"@ | Out-File -FilePath $APP_REPORT -Encoding UTF8

@"
CyberPatriot Windows Hardening User Report - $(Get-Date)
Hostname: $(hostname)
OS: $((Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ProductName) $((Get-WmiObject Win32_OperatingSystem).Version)
===========================================

"@ | Out-File -FilePath $USER_REPORT -Encoding UTF8

@"
CyberPatriot Windows Hardening System Report - $(Get-Date)
Hostname: $(hostname)
OS: $((Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ProductName) $((Get-WmiObject Win32_OperatingSystem).Version)
===========================================

"@ | Out-File -FilePath $SYS_REPORT -Encoding UTF8

# ------------------------------------------------------------------
# 1. Search for forbidden media files (common in CyberPatriot images)
# ------------------------------------------------------------------
Write-Host "[1] Searching for forbidden media files (.mp3, .mp4, .jpg, etc.)"
@"
[1] Forbidden media files found (if any):
Remove unwanted files manually using: Remove-Item <path>
"@ | Out-File -FilePath $APP_REPORT -Append -Encoding UTF8

$MediaExtensions = @("*.mp3","*.mp4","*.avi","*.mkv","*.jpg","*.jpeg","*.png","*.gif","*.torrent")
$SearchPaths = @("C:\Users","C:\Windows\Temp","C:\Temp","C:\Inetpub\wwwroot") | Where-Object { Test-Path $_ }

foreach ($path in $SearchPaths) {
    Get-ChildItem -Path $path -Include $MediaExtensions -Recurse -File -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty FullName |
        Out-File -FilePath $APP_REPORT -Append -Encoding UTF8
}
"`n" | Out-File -FilePath $APP_REPORT -Append -Encoding UTF8

# ------------------------------------------------------------------
# 2. Check user accounts
# ------------------------------------------------------------------
Write-Host "[2] Checking user accounts"
@"
[2] Local user accounts:
===========================================
"@ | Out-File -FilePath $USER_REPORT -Append -Encoding UTF8

Get-LocalUser | Where-Object {$_.Enabled -eq $true} | 
    Select-Object Name,SID,Description,LastLogon |
    Format-Table -AutoSize |
    Out-String | Out-File -FilePath $USER_REPORT -Append -Encoding UTF8

# Common unnecessary or risky accounts in CyberPatriot images
$BadUsers = @("Guest","DefaultAccount","WDAGUtilityAccount","Admin","Backup","HelpAssistant")

foreach ($user in $BadUsers) {
    if (Get-LocalUser -Name $user -ErrorAction SilentlyContinue) {
        @"
WARNING: Potentially unnecessary/risky account found: $user
Fix: Disable with: net user $user /active:no
     Or delete: net user $user /delete
"@ | Out-File -FilePath $USER_REPORT -Append -Encoding UTF8
    }
}

# Check for extra Administrator accounts (beyond built-in Administrator)
$AdminGroup = Get-LocalGroupMember -Group "Administrators"
@"
Administrators group members:
$($AdminGroup | Format-Table -AutoSize | Out-String)
If there are unexpected users with admin rights, remove them:
Fix: net localgroup Administrators "username" /delete
"@ | Out-File -FilePath $USER_REPORT -Append -Encoding UTF8

# ------------------------------------------------------------------
# 3. Check local groups and sensitive memberships
# ------------------------------------------------------------------
Write-Host "[3] Checking local groups"
@"
[3] Local groups and members (focus on privileged groups):
===========================================
To remove user from group: net localgroup "GroupName" "username" /delete
"@ | Out-File -FilePath $USER_REPORT -Append -Encoding UTF8

$PrivGroups = @("Administrators","Remote Desktop Users","Power Users","Backup Operators")
foreach ($group in $PrivGroups) {
    if (Get-LocalGroup -Name $group -ErrorAction SilentlyContinue) {
        $members = Get-LocalGroupMember -Group $group -ErrorAction SilentlyContinue
        @"
Group: $group
Members:
$($members | Format-List Name,ObjectClass,SID | Out-String)
"@ | Out-File -FilePath $USER_REPORT -Append -Encoding UTF8
    }
}
"`n" | Out-File -FilePath $USER_REPORT -Append -Encoding UTF8

# ------------------------------------------------------------------
# 4. Password policy check
# ------------------------------------------------------------------
Write-Host "[4] Checking password policy"
$SecPol = secedit /export /cfg "$env:TEMP\secpol.cfg" > $null
$Policy = Get-Content "$env:TEMP\secpol.cfg"

$MaxAge = ($Policy | Select-String "MaximumPasswordAge").Line.Split("=")[1].Trim()
if ([int]$MaxAge -eq 0 -or [int]$MaxAge -gt 90) {
    @"
Password Policy Issue: Maximum password age is $MaxAge days (should be <=90)
Fix: Use Local Security Policy (secpol.msc) -> Account Policies -> Password Policy
     Or via PowerShell: Set-ADDefaultDomainPasswordPolicy -MaxPasswordAge (New-TimeSpan -Days 90)  (for domain)
     For local: Use secpol.msc GUI
"@ | Out-File -FilePath $USER_REPORT -Append -Encoding UTF8
}

Remove-Item "$env:TEMP\secpol.cfg" -Force

# ------------------------------------------------------------------
# 5. Check for accounts with blank passwords or disabled password requirements
# ------------------------------------------------------------------
Write-Host "[5] Checking for accounts with no password requirement"
Get-LocalUser | Where-Object {$_.PasswordRequired -eq $false -and $_.Enabled -eq $true} | ForEach-Object {
    @"
WARNING: User $($_.Name) does not require a password
Fix: net user $($_.Name) *
     (this will prompt to set a password)
"@ | Out-File -FilePath $USER_REPORT -Append -Encoding UTF8
}

# ------------------------------------------------------------------
# 6. Check running services (unnecessary services)
# ------------------------------------------------------------------
Write-Host "[6] Checking for potentially unnecessary services"
$UnwantedServices = @("Telnet","FTPSVC","SNMP","RemoteRegistry","W3SVC","IISADMIN","MSFTPSVC","TrkWks","WSearch","Spooler")

$RunningUnwanted = Get-Service | Where-Object {$UnwantedServices -contains $_.Name -and $_.Status -eq "Running"}

if ($RunningUnwanted) {
    @"
[6] Potentially unnecessary/risky services running:
$($RunningUnwanted | Format-Table Name,DisplayName,Status | Out-String)
Fix example: Stop-Service -Name <ServiceName> -Force
           Set-Service -Name <ServiceName> -StartupType Disabled
"@ | Out-File -FilePath $SYS_REPORT -Append -Encoding UTF8
}

# ------------------------------------------------------------------
# 7. Windows Firewall status
# ------------------------------------------------------------------
Write-Host "[7] Checking Windows Firewall status"
$Profiles = Get-NetFirewallProfile
@"
[7] Windows Firewall status:
$($Profiles | Format-Table Name,Enabled,DefaultInboundAction,DefaultOutboundAction | Out-String)
"@ | Out-File -FilePath $SYS_REPORT -Append -Encoding UTF8

if ($Profiles | Where-Object {$_.Enabled -eq $false}) {
    @"
WARNING: One or more firewall profiles are disabled.
Fix: Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
     Set-NetFirewallProfile -DefaultInboundAction Block -DefaultOutboundAction Allow
"@ | Out-File -FilePath $SYS_REPORT -Append -Encoding UTF8
}

# ------------------------------------------------------------------
# 8. Check for available Windows Updates
# ------------------------------------------------------------------
Write-Host "[8] Checking for Windows Updates"
# Requires PSWindowsUpdate module (common in CyberPatriot prep)
if (Get-Module -ListAvailable -Name PSWindowsUpdate) {
    Import-Module PSWindowsUpdate
    $Updates = Get-WUList
    if ($Updates) {
        @"
[8] Available updates found:
$($Updates | Format-Table Title,Size,KB | Out-String)
Fix: Install-WindowsUpdate -AcceptAll -AutoReboot (or manually via Settings)
"@ | Out-File -FilePath $SYS_REPORT -Append -Encoding UTF8
    } else {
        "No pending updates found." | Out-File -FilePath $SYS_REPORT -Append -Encoding UTF8
    }
} else {
    "PSWindowsUpdate module not available. Manually check Windows Update." | Out-File -FilePath $SYS_REPORT -Append -Encoding UTF8
}

# ------------------------------------------------------------------
# 9. Check Remote Desktop / SSH (OpenSSH) settings
# ------------------------------------------------------------------
Write-Host "[9] Checking Remote Desktop and OpenSSH settings"
if ((Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue).fDenyTSConnections -eq 0) {
    @"
Remote Desktop is ENABLED.
If not required: 
Fix: Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 1
     net stop TermService
"@ | Out-File -FilePath $SYS_REPORT -Append -Encoding UTF8
}

if (Get-Service sshd -ErrorAction SilentlyContinue) {
    @"
OpenSSH Server is installed.
Check configuration in C:\ProgramData\ssh\sshd_config
Common fixes: Set PasswordAuthentication no, PermitRootLogin no (if applicable)
Then: Restart-Service sshd
"@ | Out-File -FilePath $SYS_REPORT -Append -Encoding UTF8
}

# ------------------------------------------------------------------
# 10. Check for known bad/insecure applications
# ------------------------------------------------------------------
Write-Host "[10] Checking for known risky applications"
$BadApps = @("telnet","tftp","john","hydra","nmap","nikto","netcat","nc","wireshark","vuze","frostwire","putty","winscp","tightvnc","realvnc")

$InstalledBad = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
    Where-Object { $BadApps | ForEach-Object { $_.DisplayName -match $_ } }

if ($InstalledBad) {
    @"
[10] Potentially risky applications detected:
$($InstalledBad.DisplayName | Out-String)
Fix: Uninstall via Settings > Apps or msiexec /x {ProductCode}
"@ | Out-File -FilePath $APP_REPORT -Append -Encoding UTF8
}

# ------------------------------------------------------------------
# 11. Check listening ports and services
# ------------------------------------------------------------------
Write-Host "[11] Checking open/listening ports"
$Listening = Get-NetTCPConnection -State Listen | Select-Object LocalPort, OwningProcess, @{Name="ProcessName";Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name}}

@"
[11] Listening ports:
$($Listening | Sort LocalPort | Format-Table LocalPort,ProcessName,OwningProcess -AutoSize | Out-String)
"@ | Out-File -FilePath $SYS_REPORT -Append -Encoding UTF8

@"
General recommendations:
1. Enable Windows Firewall for all profiles and block inbound by default.
2. Apply all Windows Updates.
3. Disable Remote Desktop if not needed.
4. Remove or disable unnecessary users and services.
5. Close non-essential listening ports using firewall rules:
   New-NetFirewallRule -DisplayName "Block Port X" -Direction Inbound -Action Block -LocalPort X -Protocol TCP
6. For CyberPatriot: Only required services/ports should be open (often just scoring engine ports).
"@ | Out-File -FilePath $SYS_REPORT -Append -Encoding UTF8

Write-Host "============================================================"
Write-Host "               CHECKLIST COMPLETE!"
Write-Host "Reports generated:"
Write-Host "   System Report: $SYS_REPORT"
Write-Host "   User Report:   $USER_REPORT"
Write-Host "   App Report:    $APP_REPORT"
Write-Host "============================================================"