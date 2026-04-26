# PowerShell deployment script for RedBadger
Write-Host "Deploying RedBadger Security Platform..." -ForegroundColor Green

# Check if running as admin
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Please run as Administrator!" -ForegroundColor Red
    exit 1
}

# Install Python packages
pip install requests psutil flask discord.py python-telegram-bot slack-sdk

# Create firewall rules
New-NetFirewallRule -DisplayName "RedBadger Web" -Direction Inbound -Protocol TCP -LocalPort 5000 -Action Allow
New-NetFirewallRule -DisplayName "RedBadger Phish" -Direction Inbound -Protocol TCP -LocalPort 8080 -Action Allow

Write-Host "Deployment complete! Run: python redbadger.py" -ForegroundColor Green