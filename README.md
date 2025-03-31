
# RDP-Fail2Ban

This script provides a Fail2Ban-like protection mechanism for Windows Remote Desktop Protocol (RDP) by automatically blocking IP addresses that repeatedly fail authentication attempts.

## Overview

RDP-Route-Blocker monitors Windows security logs for failed RDP authentication attempts. When an IP exceeds the threshold (default: 3 failed attempts), the script creates a null route to block all traffic from that IP, effectively stopping brute force attacks without using Windows Firewall.

## Why Use This?

- **Lightweight protection** - Uses routing table instead of Windows Firewall
- **Minimal resource usage** - Perfect for systems where you want to disable Windows Firewall for performance reasons
- **Simple but effective** - Automatically blocks IPs trying to brute force your RDP
- **IP allowlist** - Prevent accidental lockouts of trusted IPs

## How It Works

1. The script scans Windows event logs for failed RDP authentication attempts
2. It tracks how many failed attempts each IP address has made
3. After a configurable threshold (default: 3 attempts), it adds a null route for the offending IP address
4. The script maintains a list of allowed IPs that will never be blocked
5. All activities are logged for easy review

## Important Notes

- This script uses Windows routing table instead of Windows Firewall
- It's designed for systems where you want to disable Windows Firewall for performance reasons
- Administrator privileges are required
- Be careful with the allowlist to avoid locking yourself out

## Requirements

- Windows OS with PowerShell 5.1 or higher
- Administrator privileges
- Remote Desktop Protocol enabled
- Task Scheduler for automated execution

## Quick Start

1. Download the `RDP-Fail2Ban.ps1` script
2. Create a scheduled task to run the script every 5 minutes with admin privileges
3. (Optional) Add trusted IP addresses to the allowlist file

## Configuration

The script uses these default settings which can be modified at the top of the file:

```powershell
$maxFailedAttempts = 3      # Number of failed attempts before blocking
$logRetentionDays = 2       # How long to keep log files
$scriptDir = "$env:APPDATA\Fail2Ban"  # Base directory for script files
$logFolder = "$scriptDir\logs"        # Folder for log files
```

## Usage

### Allow Trusted IPs

Edit the allowlist file located at `%APPDATA%\Fail2Ban\allowlist.txt` and add one IP address per line:

```
192.168.1.100
10.0.0.5
```

### Setup as Scheduled Task

1. Open Task Scheduler
2. Create a new task with the following settings:
   - Run with highest privileges
   - Trigger: Every 5 minutes
   - Action: Start a program
     - Program/script: `powershell.exe`
     - Arguments: `-ExecutionPolicy Bypass -File "C:\path\to\RDP-Fail2Ban.ps1"`

### Logs

Log files are stored in `%APPDATA%\Fail2Ban\logs\` with timestamps for easy tracking and troubleshooting.

## Security Considerations

- The script uses IP blocking via routing tables rather than Windows Firewall rules
- Blocked IPs can still reach other services on your server, but RDP attempts will time out
- For complete protection, consider using this alongside other security measures

## License

MIT

