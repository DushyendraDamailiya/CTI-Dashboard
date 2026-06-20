#!/usr/bin/env bash
set -euo pipefail

# Optional helper for Linux/macOS firewall blocking support.
# Windows users should run backend.py from an Administrator PowerShell instead.

OS_TYPE="$(uname)"
SUDOERS_FILE="/etc/sudoers.d/threat-dashboard-firewall"

echo "Threat Intelligence Dashboard - Firewall Blocking Setup"
echo "-------------------------------------------------------"

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo "This script must be run as root."
    echo "Run: sudo bash setup-firewall-blocking.sh"
    exit 1
fi

write_sudoers_rule() {
    local group_name="$1"
    local command_path="$2"

    if [ ! -x "$command_path" ]; then
        echo "Required command not found or not executable: $command_path"
        exit 1
    fi

    cat > "$SUDOERS_FILE" <<EOF
# Allow the Threat Intelligence Dashboard backend to manage firewall blocks.
%${group_name} ALL=(root) NOPASSWD: ${command_path}
EOF
    chmod 0440 "$SUDOERS_FILE"
    visudo -cf "$SUDOERS_FILE"
}

case "$OS_TYPE" in
    Darwin)
        echo "Detected macOS"
        write_sudoers_rule "admin" "/sbin/route"
        echo "macOS setup complete."
        ;;

    Linux)
        echo "Detected Linux"

        if ! command -v iptables >/dev/null 2>&1; then
            echo "iptables is not installed."
            echo "Install it first, for example: sudo apt-get install iptables"
            exit 1
        fi

        IPTABLES_PATH="$(command -v iptables)"
        write_sudoers_rule "sudo" "$IPTABLES_PATH"
        echo "Linux setup complete."
        ;;

    *)
        echo "Unsupported OS: $OS_TYPE"
        echo "Supported here: macOS and Linux."
        echo "For Windows, run PowerShell as Administrator and start: python backend.py"
        exit 1
        ;;
esac

echo ""
echo "Next steps:"
echo "1. Start backend: python backend.py"
echo "2. Use the dashboard Block action for a public IPv4 address."
echo ""
echo "Security note:"
echo "- Sudoers rule created at: $SUDOERS_FILE"
echo "- To remove it: sudo rm $SUDOERS_FILE"
