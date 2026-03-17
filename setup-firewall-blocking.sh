#!/bin/bash
# setup-firewall-blocking.sh
# Configures firewall blocking for the Threat Intelligence Dashboard

OS_TYPE=$(uname)
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

echo "🔒 Threat Intelligence Dashboard - Firewall Blocking Setup"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Check if running with sudo
if [ "$EUID" -ne 0 ]; then 
   echo "⚠️  This script should be run with sudo for firewall setup"
   echo "Run: sudo bash setup-firewall-blocking.sh"
   exit 1
fi

case "$OS_TYPE" in
  Darwin)
    echo "🍎 Detected macOS"
    echo ""
    echo "Setting up passwordless sudo for 'route' command..."
    echo ""
    
    # Backup sudoers
    cp /etc/sudoers /etc/sudoers.backup.$(date +%s)
    
    # Add passwordless route access for admin group
    echo "" >> /etc/sudoers
    echo "# Allow route command for firewall blocking" >> /etc/sudoers
    echo "%admin ALL=(ALL) NOPASSWD: /sbin/route" >> /etc/sudoers
    
    echo "✅ macOS setup complete!"
    echo ""
    echo "Next steps:"
    echo "1. Run backend with: python backend.py"
    echo "2. When blocking IPs, you'll be prompted for firewall blocking"
    echo "3. Choose 'OK' to enable system-level blocking"
    echo ""
    ;;
    
  Linux)
    echo "🐧 Detected Linux"
    echo ""
    
    # Check if iptables is installed
    if ! command -v iptables &> /dev/null; then
      echo "Installing iptables..."
      apt-get update
      apt-get install -y iptables iptables-persistent
    fi
    
    echo "Setting up passwordless sudo for iptables..."
    echo ""
    
    # Backup sudoers
    cp /etc/sudoers /etc/sudoers.backup.$(date +%s)
    
    # Add passwordless iptables access for sudo group
    echo "" >> /etc/sudoers
    echo "# Allow iptables command for firewall blocking" >> /etc/sudoers
    echo "%sudo ALL=(ALL) NOPASSWD: /sbin/iptables" >> /etc/sudoers
    
    # Enable iptables-persistent to save rules
    echo "Enabling iptables persistence..."
    systemctl enable iptables
    
    echo "✅ Linux setup complete!"
    echo ""
    echo "Next steps:"
    echo "1. Run backend with: python backend.py"
    echo "2. When blocking IPs, you'll be prompted for firewall blocking"
    echo "3. Choose 'OK' to enable system-level blocking"
    echo ""
    ;;
    
  *)
    echo "❌ Unsupported OS: $OS_TYPE"
    echo ""
    echo "Supported OS:"
    echo "  - macOS (Darwin)"
    echo "  - Linux"
    echo "  - Windows (manual setup required)"
    echo ""
    echo "For Windows:"
    echo "  1. Run PowerShell as Administrator"
    echo "  2. Start your backend: python backend.py"
    echo "  3. Firewall rules are managed by Windows Defender"
    exit 1
    ;;
esac

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Security Note:"
echo "- Rule changes stored in /etc/sudoers"
echo "- Backup created at /etc/sudoers.backup.*"
echo "- To revert: sudo cp /etc/sudoers.backup.* /etc/sudoers"
echo ""
