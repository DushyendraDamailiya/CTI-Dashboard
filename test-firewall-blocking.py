#!/usr/bin/env python3
"""
Test whether local firewall blocking commands are available.

This script uses the documentation IP 203.0.113.1 and removes any test
rule it creates.
"""

import platform
import shutil
import subprocess
import sys

TEST_IP = "203.0.113.1"  # TEST-NET-3, reserved for documentation.


def run(command, timeout=5):
    return subprocess.run(command, capture_output=True, text=True, timeout=timeout)


def require_sudo():
    try:
        result = run(["sudo", "-n", "true"], timeout=2)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        print("[fail] sudo is not available or timed out")
        return False

    if result.returncode != 0:
        print("[fail] sudo password is required")
        print("       Run setup first: sudo bash setup-firewall-blocking.sh")
        return False

    print("[ok] sudo access confirmed")
    return True


def test_macos():
    print("Testing macOS firewall blocking")
    print("-" * 40)

    if not require_sudo():
        return False

    try:
        result = run(["sudo", "route", "add", "-net", TEST_IP, "127.0.0.1"])
        if result.returncode != 0:
            print("[fail] route add failed")
            print(result.stderr or result.stdout)
            return False

        print(f"[ok] Added test route for {TEST_IP}")
        verify = run(["netstat", "-rn"])
        if TEST_IP in verify.stdout:
            print("[ok] Route verified")
        return True
    except subprocess.TimeoutExpired:
        print("[fail] command timed out")
        return False
    finally:
        subprocess.run(["sudo", "route", "delete", "-net", TEST_IP], capture_output=True, timeout=5)
        print("[ok] Removed test route")


def test_linux():
    print("Testing Linux firewall blocking")
    print("-" * 40)

    if not require_sudo():
        return False

    iptables = shutil.which("iptables")
    if not iptables:
        print("[fail] iptables not found")
        print("       Install it first, for example: sudo apt-get install iptables")
        return False

    try:
        result = run(["sudo", iptables, "-I", "INPUT", "1", "-s", TEST_IP, "-j", "DROP"])
        if result.returncode != 0:
            print("[fail] iptables rule add failed")
            print(result.stderr or result.stdout)
            return False

        print("[ok] Added test iptables rule")
        verify = run(["sudo", iptables, "-L", "-n", "-v"])
        if TEST_IP in verify.stdout:
            print("[ok] Rule verified")
        return True
    except subprocess.TimeoutExpired:
        print("[fail] command timed out")
        return False
    finally:
        subprocess.run(["sudo", iptables, "-D", "INPUT", "-s", TEST_IP, "-j", "DROP"], capture_output=True, timeout=5)
        print("[ok] Removed test rule")


def test_windows():
    print("Testing Windows firewall blocking")
    print("-" * 40)

    try:
        admin_check = run(["netsh", "advfirewall", "show", "allprofiles"])
        if admin_check.returncode != 0 or "Access Denied" in admin_check.stderr:
            print("[fail] Not running as Administrator")
            print("       Start PowerShell as Administrator, then run this test.")
            return False

        rule_name = f"TEST_BLOCK_{TEST_IP.replace('.', '_')}"
        result = run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            "dir=in",
            "action=block",
            f"remoteip={TEST_IP}",
            "protocol=any",
        ])
        if result.returncode != 0:
            print("[fail] Windows Firewall rule add failed")
            print(result.stderr or result.stdout)
            return False

        print("[ok] Added Windows Firewall test rule")
        verify = run(["netsh", "advfirewall", "firewall", "show", "rule", f"name={rule_name}"])
        if rule_name in verify.stdout:
            print("[ok] Rule verified")
        return True
    except subprocess.TimeoutExpired:
        print("[fail] command timed out")
        return False
    finally:
        subprocess.run([
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name=TEST_BLOCK_{TEST_IP.replace('.', '_')}",
        ], capture_output=True, timeout=5)
        print("[ok] Removed test rule")


def main():
    print("Firewall Blocking Capability Test")
    print("=" * 40)
    print(f"Test IP: {TEST_IP}")
    print("")

    system = platform.system()
    if system == "Darwin":
        ok = test_macos()
    elif system == "Linux":
        ok = test_linux()
    elif system == "Windows":
        ok = test_windows()
    else:
        print(f"[fail] Unsupported OS: {system}")
        return 1

    print("")
    print("=" * 40)
    if ok:
        print("[ok] Firewall blocking is ready")
        return 0

    print("[fail] Firewall blocking is not ready")
    return 1


if __name__ == "__main__":
    sys.exit(main())
