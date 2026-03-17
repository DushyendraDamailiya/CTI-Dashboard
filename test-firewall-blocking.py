#!/usr/bin/env python3
"""
Quick Firewall Blocking Test Script
Tests if firewall blocking is working on your system
"""

import subprocess
import platform
import sys
import json

TEST_IP = "203.0.113.1"  # Documentation test IP (TEST-NET-3, not routable)

def test_macos():
    print("🍎 Testing macOS Firewall Blocking")
    print("─" * 50)
    
    try:
        # Check if sudo works without password
        result = subprocess.run(['sudo', '-n', 'true'], capture_output=True, timeout=2)
        if result.returncode != 0:
            print("❌ Sudo password required (run: sudo bash setup-firewall-blocking.sh)")
            return False
        
        print("✅ Sudo passwordless access confirmed")
        
        # Test block
        print(f"\n📋 Testing block rule for {TEST_IP}...")
        result = subprocess.run(
            ['sudo', 'route', 'add', '-net', TEST_IP, '127.0.0.1'],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode == 0:
            print(f"✅ Successfully added route for {TEST_IP}")
            
            # Verify it exists
            result = subprocess.run(['netstat', '-rn'], capture_output=True, text=True)
            if TEST_IP in result.stdout:
                print(f"✅ Route verified with netstat")
            
            # Cleanup
            subprocess.run(['sudo', 'route', 'delete', '-net', TEST_IP], 
                         capture_output=True, timeout=5)
            print(f"✅ Cleaned up test route")
            return True
        else:
            print(f"❌ Route command failed:")
            print(result.stderr)
            return False
    
    except subprocess.TimeoutExpired:
        print("❌ Command timed out")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def test_linux():
    print("🐧 Testing Linux Firewall Blocking")
    print("─" * 50)
    
    try:
        # Check if sudo works without password
        result = subprocess.run(['sudo', '-n', 'true'], capture_output=True, timeout=2)
        if result.returncode != 0:
            print("❌ Sudo password required (run: sudo bash setup-firewall-blocking.sh)")
            return False
        
        print("✅ Sudo passwordless access confirmed")
        
        # Check iptables exists
        result = subprocess.run(['which', 'iptables'], capture_output=True)
        if result.returncode != 0:
            print("❌ iptables not found. Install with: sudo apt-get install iptables")
            return False
        
        print("✅ iptables found")
        
        # Test block
        print(f"\n📋 Testing block rule for {TEST_IP}...")
        result = subprocess.run(
            ['sudo', 'iptables', '-I', 'INPUT', '1', '-s', TEST_IP, '-j', 'DROP'],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode == 0:
            print(f"✅ Successfully added iptables rule for {TEST_IP}")
            
            # Verify it exists
            result = subprocess.run(['sudo', 'iptables', '-L', '-n', '-v'], 
                                  capture_output=True, text=True)
            if TEST_IP in result.stdout:
                print(f"✅ Rule verified with iptables -L")
            
            # Cleanup
            subprocess.run(['sudo', 'iptables', '-D', 'INPUT', '-s', TEST_IP, '-j', 'DROP'], 
                         capture_output=True, timeout=5)
            print(f"✅ Cleaned up test rule")
            return True
        else:
            print(f"❌ iptables command failed:")
            print(result.stderr)
            return False
    
    except subprocess.TimeoutExpired:
        print("❌ Command timed out")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def test_windows():
    print("🪟 Testing Windows Firewall Blocking")
    print("─" * 50)
    
    try:
        # Check if running as admin
        result = subprocess.run(['netsh', 'advfirewall', 'show', 'allprofiles'], 
                              capture_output=True, text=True, timeout=5)
        if 'Access Denied' in result.stderr or result.returncode != 0:
            print("❌ Not running as Administrator")
            print("   Run PowerShell as Admin and start backend with: python backend.py")
            return False
        
        print("✅ Administrator privileges confirmed")
        
        # Test block
        rule_name = f"TEST_BLOCK_{TEST_IP.replace('.', '_')}"
        print(f"\n📋 Testing firewall rule: {rule_name}")
        
        result = subprocess.run(
            ['netsh', 'advfirewall', 'firewall', 'add', 'rule',
             f'name={rule_name}',
             'dir=in', 'action=block',
             f'remoteip={TEST_IP}',
             'protocol=any'],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode == 0:
            print(f"✅ Successfully added firewall rule")
            
            # List to verify
            result = subprocess.run(
                ['netsh', 'advfirewall', 'firewall', 'show', 'rule', f'name={rule_name}'],
                capture_output=True,
                text=True
            )
            if rule_name in result.stdout:
                print(f"✅ Rule verified")
            
            # Cleanup
            subprocess.run(
                ['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name={rule_name}'],
                capture_output=True,
                timeout=5
            )
            print(f"✅ Cleaned up test rule")
            return True
        else:
            print(f"❌ Firewall command failed:")
            print(result.stderr)
            return False
    
    except subprocess.TimeoutExpired:
        print("❌ Command timed out")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def main():
    print("\n🔒 Firewall Blocking Capability Test")
    print("═" * 50)
    print(f"Test IP: {TEST_IP} (documentation test IP)\n")
    
    system = platform.system()
    result = False
    
    if system == 'Darwin':
        result = test_macos()
    elif system == 'Linux':
        result = test_linux()
    elif system == 'Windows':
        result = test_windows()
    else:
        print(f"❌ Unsupported OS: {system}")
        return 1
    
    print("\n" + "═" * 50)
    if result:
        print("✅ FIREWALL BLOCKING IS READY!")
        print("\nYou can now:")
        print("1. Start your backend: python backend.py")
        print("2. Block IPs from the dashboard")
        print("3. This will add real firewall rules to your system")
        return 0
    else:
        print("❌ FIREWALL BLOCKING NOT READY")
        print("\nNext steps:")
        print("  1. Run setup: sudo bash setup-firewall-blocking.sh")
        print("  2. Run this test again")
        return 1

if __name__ == '__main__':
    sys.exit(main())
