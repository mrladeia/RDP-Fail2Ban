# Script for monitoring and blocking IPs that fail RDP authentication
# This script must be run as administrator
# Version: Single execution (to be scheduled every 5 minutes)

# Settings
$maxFailedAttempts = 3  # Maximum number of failed attempts allowed
$logName = "Security"    # Name of the security event log
$eventID = 4625         # Event ID for authentication failure
$scriptDir = "$env:APPDATA\Fail2Ban"  # Script directory using %appdata%
$timestamp = Get-Date -Format "yyyy-MM-dd-HHmmss"
$logFolder = "$scriptDir\logs" # Log folder
$logFile = "$logFolder\rdp_block_log-$timestamp.txt"  # Log file with timestamp
$statFile = "$scriptDir\failed_attempts.xml"  # File to store state between executions
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

# Create allowlist file if it does not exist and add the specified IP
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
        $interface = (Get-NetAdapter | Where-Object { $_.Status -eq "Up" }).Name
        
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

# Initialize ArrayList for blocked IPs
$blockedIPs = New-Object System.Collections.ArrayList

# Retrieve currently blocked IPs directly from system routes
$currentBlockedIPs = Get-BlockedIPs
foreach ($ip in $currentBlockedIPs) {
    [void]$blockedIPs.Add($ip)
}
Write-Log "Blocked IPs found in system routes: $($blockedIPs.Count) IPs."

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

# Save current state for next execution
try {
    $failedAttempts | Export-Clixml -Path $statFile -Force
    Write-Log "Current state saved successfully."
}
catch {
    Write-Log "Error saving current state: $_"
}

Write-Log "Execution completed."
