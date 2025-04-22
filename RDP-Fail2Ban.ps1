# Script for monitoring and blocking IPs that fail RDP authentication
# This script must be run as administrator
# Version: Single execution (to be scheduled every 5 minutes)

# Settings
$maxFailedAttempts = 3  # Maximum number of failed attempts allowed
$logName = "Security"    # Name of the security event log
$eventID = 4625         # Event ID for authentication failure
$lookbackMinutes = 60   # Minutes to look back in logs
$scriptDir = "$env:APPDATA\Fail2Ban"  # Script directory using %appdata%
$timestamp = Get-Date -Format "yyyy-MM-dd-HHmmss"
$logFolder = "$scriptDir\logs" # Log folder
$logFile = "$logFolder\rdp_block_log-$timestamp.txt"  # Log file with timestamp
$allowlistFile = "$scriptDir\allowlist.txt"  # File to store allowed IPs
$logRetentionDays = 2  # Number of days to retain log files

# Create script directory and log folder if they do not exist
if (-not (Test-Path $scriptDir)) {
    New-Item -ItemType Directory -Path $scriptDir | Out-Null
}

# Create log folder if it does not exist
if (-not (Test-Path $logFolder)) {
    New-Item -ItemType Directory -Path $logFolder | Out-Null
}

# Create allowlist file if it does not exist
if (-not (Test-Path $allowlistFile)) {
    "" | Out-File -FilePath $allowlistFile
    Write-Host "Allowlist file created"
}

# Clear old log files in the log folder
$cutoffDate = (Get-Date).AddDays(-$logRetentionDays)
Get-ChildItem -Path $logFolder -Filter "rdp_block_log-*.txt" | 
    Where-Object { $_.LastWriteTime -lt $cutoffDate } | 
    ForEach-Object {
        Remove-Item -Path $_.FullName -Force
        Write-Host "Old log file removed: $($_.Name)"
    }

# Function to log actions
function Write-Log {
    param (
        [string]$message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $message" | Out-File -FilePath $logFile -Append
    Write-Host "$timestamp - $message"
}

# Log script execution start
Write-Log "Starting RDP blocking script execution."

# Load the list of allowed IPs
$allowlistIPs = @()
if (Test-Path $allowlistFile) {
    $allowlistIPs = Get-Content -Path $allowlistFile | Where-Object { $_ -match '\S' } | ForEach-Object { $_.Trim() }
    Write-Log "Allowlist loaded successfully. Total: $($allowlistIPs.Count) IPs."
}

# Function to check if an IP is in the allowlist
function Is-IPAllowed {
    param (
        [string]$ipAddress
    )
    return $allowlistIPs -contains $ipAddress
}

# Function to get all currently blocked IPs via NetRoute
function Get-BlockedIPs {
    $routes = Get-NetRoute -ErrorAction SilentlyContinue | Where-Object {
        # Identify blocking routes (prefix /32 and NextHop 0.0.0.0)
        $_.DestinationPrefix -match '^\d+\.\d+\.\d+\.\d+/32$' -and $_.NextHop -eq '0.0.0.0'
    }
    
    # Extract only the IPs
    $blockedIPs = $routes | ForEach-Object {
        $_.DestinationPrefix -replace '/32', ''
    }
    
    return $blockedIPs
}

# Function to block an IP using the routing table
function Block-IP {
    param (
        [string]$ipAddress
    )
    
    # Check if the IP is in the allowlist
    if (Is-IPAllowed -ipAddress $ipAddress) {
        Write-Log "IP $ipAddress is in the allowlist and will not be blocked."
        return
    }
    
    try {
        # Get active network interface
        $activeInterface = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
        if ($null -eq $activeInterface -or $activeInterface.Count -eq 0) {
            Write-Log "Error: No active network interface found."
            return
        }
        $interface = $activeInterface[0].Name
        
        # Check if the route already exists
        $existingRoute = Get-NetRoute -DestinationPrefix "$ipAddress/32" -ErrorAction SilentlyContinue

        if ($existingRoute) {
            Write-Log "The route to block $ipAddress already exists."
        }
        else {
            # Add a null route to block the IP
            New-NetRoute -DestinationPrefix "$ipAddress/32" -InterfaceAlias $interface -NextHop "0.0.0.0" -RouteMetric 1 | Out-Null
            Write-Log "IP successfully blocked: $ipAddress"
        }
    }
    catch {
        Write-Log "Error blocking IP $ipAddress`: $_"
    }
}

# Initialize hashtable for failed attempts
$failedAttempts = @{}

# Initialize ArrayList for blocked IPs
$blockedIPs = New-Object System.Collections.ArrayList

# Retrieve currently blocked IPs directly from system routes
$currentBlockedIPs = Get-BlockedIPs
foreach ($ip in $currentBlockedIPs) {
    [void]$blockedIPs.Add($ip)
}
Write-Log "Blocked IPs found in system routes: $($blockedIPs.Count) IPs."

# Fetch recent authentication failure events
$startTime = (Get-Date).AddMinutes(-$lookbackMinutes)
Write-Log "Fetching authentication failure events since: $startTime"

try {
    $events = Get-WinEvent -FilterHashtable @{
        LogName = $logName
        ID = $eventID
        StartTime = $startTime
    } -ErrorAction SilentlyContinue
    
    if ($null -eq $events) {
        Write-Log "No authentication failure events found."
        $events = @()
    }
    
    Write-Log "Found $($events.Count) authentication failure events."
    
    # Process authentication failure events with improved error handling
    foreach ($event in $events) {
        try {
            $ipAddress = $null
            $userName = "Unknown"
            
            # Extract the IP address from the event message directly
            # Event 4625 has the source network address in the format "Source Network Address: x.x.x.x"
            if ($event.Message -match "Source Network Address:\s+(\d+\.\d+\.\d+\.\d+)") {
                $ipAddress = $matches[1]
            }
            
            # Extract the username from the event message
            if ($event.Message -match "Account For Which Logon Failed:\s+Security ID:\s+[^\r\n]+\s+Account Name:\s+(\S+)") {
                $userName = $matches[1]
                if ($userName -eq "-") {
                    $userName = "Unknown"
                }
            }
            
            # Check if we found a valid IP and it's not a local or empty IP
            if ($ipAddress -and $ipAddress -ne "-" -and $ipAddress -ne "::1" -and $ipAddress -ne "127.0.0.1" -and $ipAddress -ne "0.0.0.0" -and $ipAddress -match '^\d+\.\d+\.\d+\.\d+$') {
                Write-Log "Authentication failure detected from IP: $ipAddress (Username: $userName)"
                
                # Increment failed attempts counter
                if (-not $failedAttempts.ContainsKey($ipAddress)) {
                    $failedAttempts[$ipAddress] = 1
                }
                else {
                    $failedAttempts[$ipAddress]++
                }
                
                # Check if it exceeded maximum attempts
                if ($failedAttempts[$ipAddress] -ge $maxFailedAttempts) {
                    Write-Log "IP $ipAddress exceeded maximum failed attempts ($maxFailedAttempts)."
                    Block-IP -ipAddress $ipAddress
                    if (-not $blockedIPs.Contains($ipAddress)) {
                        [void]$blockedIPs.Add($ipAddress)
                    }
                }
                else {
                    Write-Log "IP $ipAddress has $($failedAttempts[$ipAddress]) failed attempts."
                }
            }
            else {
                Write-Log "Could not extract valid IP address from event."
            }
        } catch {
            Write-Log "Error processing event: $_"
            # Continue with next event
            continue
        }
    }
}
catch {
    Write-Log "Error fetching events: $_"
}

# Check if any blocked IP is now in the allowlist and remove the block
$ipsToUnblock = @()
foreach ($ip in $blockedIPs) {
    if (Is-IPAllowed -ipAddress $ip) {
        $ipsToUnblock += $ip
    }
}

foreach ($ip in $ipsToUnblock) {
    try {
        Remove-NetRoute -DestinationPrefix "$ip/32" -Confirm:$false -ErrorAction SilentlyContinue
        Write-Log "Route for IP $ip removed because it is now in the allowlist."
        $blockedIPs.Remove($ip)
    }
    catch {
        Write-Log "Error removing route for allowed IP $ip`: $_"
    }
}

Write-Log "Execution completed."
