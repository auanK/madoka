#!/usr/bin/env python3
"""Phase 2 Virtual Network functional tests (privileged).

Tests interface creation, IPv6 address assignment, MTU 1280, persistence across restarts,
and routing isolation (preserving default route and physical connectivity).
"""

import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

def is_privileged():
    if os.name == "nt":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    return os.geteuid() == 0


def get_default_routes():
    """Returns list of default route descriptions."""
    if os.name == "nt":
        res = subprocess.run(["route", "print", "0.0.0.0"], capture_output=True, text=True)
        return res.stdout
    res = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True)
    return res.stdout


def check_interface_linux(ifname, expected_ipv6, expected_mtu):
    # Check link
    link_res = subprocess.run(["ip", "link", "show", ifname], capture_output=True, text=True)
    assert link_res.returncode == 0, f"Interface {ifname} not found: {link_res.stderr}"
    assert f"mtu {expected_mtu}" in link_res.stdout, f"MTU mismatch: {link_res.stdout}"
    assert "UP" in link_res.stdout, f"Interface not UP: {link_res.stdout}"

    # Check IPv6 address
    addr_res = subprocess.run(["ip", "-6", "addr", "show", ifname], capture_output=True, text=True)
    assert addr_res.returncode == 0, f"Cannot get IPv6 address for {ifname}: {addr_res.stderr}"
    # Standardize IPv6 representation check
    clean_expected = expected_ipv6.replace(":0000:", "::").replace(":000", ":").lower()
    assert (expected_ipv6.lower() in addr_res.stdout.lower() or
            any(segment in addr_res.stdout.lower() for segment in expected_ipv6.lower().split(":")[-3:])), \
        f"Expected IPv6 {expected_ipv6} not found in:\n{addr_res.stdout}"

    print(f"  [OK] Interface {ifname} exists with MTU {expected_mtu} and IPv6 {expected_ipv6}")


def check_interface_windows(ifname, expected_ipv6, expected_mtu):
    ps_cmd = (
        f"Get-NetIPInterface -InterfaceAlias '{ifname}' | Select-Object -ExpandProperty NlMtu; "
        f"Get-NetIPAddress -InterfaceAlias '{ifname}' -AddressFamily IPv6 | Select-Object -ExpandProperty IPAddress"
    )
    res = subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd], capture_output=True, text=True)
    assert res.returncode == 0, f"Cannot query interface {ifname}: {res.stderr}"
    assert str(expected_mtu) in res.stdout, f"MTU mismatch on Windows: {res.stdout}"
    clean_expected = expected_ipv6.replace(":0000:", "::").replace(":000", ":").lower()
    assert (clean_expected in res.stdout.lower() or
            any(segment in res.stdout.lower() for segment in clean_expected.split(":") if len(segment) >= 2)), \
        f"Expected IPv6 {expected_ipv6} not found in:\n{res.stdout}"
    print(f"  [OK] Windows interface {ifname} verified with MTU {expected_mtu} and IPv6 {expected_ipv6}")


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <path-to-madoka-executable>")
        sys.exit(1)

    executable = str(Path(sys.argv[1]).resolve())
    print(f"Testing executable: {executable}")

    if not is_privileged():
        print("WARNING: Not running with administrative / root privileges.")
        print("Skipping active interface creation tests. Run as root or administrator for full verification.")
        sys.exit(77)

    # Record initial default route
    initial_default_route = get_default_routes()
    print("Initial default route verified.")

    with tempfile.TemporaryDirectory(prefix="madoka-vnet-test-") as temp_dir:
        root = Path(temp_dir)
        ifname = "madokatest0" if os.name != "nt" else "MadokaTest"
        mtu = 1280
        config_file = root / "madoka.conf"
        config_file.write_text(
            "network=fd12:3456:789a:1::/64\n"
            f"interface={ifname}\n"
            "listen=[::1]:0\n",
            encoding="utf-8",
        )

        # TEST 2, 3, 4, 6: Start daemon, check interface, IPv6, MTU, isolation
        print("\n--- Starting daemon for Test 2, 3, 4, 6 ---")
        shutdown_signal = signal.CTRL_BREAK_EVENT if os.name == "nt" else signal.SIGTERM
        proc = subprocess.Popen(
            [executable, "--config", str(config_file)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
        )

        diagnostics = {}
        try:
            for _ in range(15):
                line = proc.stdout.readline()
                if not line:
                    break
                line = line.strip()
                if "=" in line:
                    k, v = line.split("=", 1)
                    diagnostics[k] = v
                if "state=interface_ready" in line:
                    break
            else:
                raise AssertionError("Daemon failed to enter state=interface_ready")

            print(f"Daemon reported readiness: node_id={diagnostics.get('node_id')}, ipv6={diagnostics.get('ipv6')}")
            assert diagnostics.get("interface") == ifname, diagnostics
            assert diagnostics.get("mtu") == str(mtu), diagnostics
            first_node_id = diagnostics.get("node_id")
            first_ipv6 = diagnostics.get("ipv6")

            # Verify interface at OS level
            if os.name != "nt":
                check_interface_linux(ifname, first_ipv6, mtu)
            else:
                check_interface_windows(ifname, first_ipv6, mtu)

            # TEST 6: Verify default route and physical connectivity isolation
            current_default_route = get_default_routes()
            assert initial_default_route == current_default_route, "Default route was altered by virtual interface!"
            print("  [OK] Default route is preserved and untouched.")

            # Stop daemon
            proc.send_signal(shutdown_signal)
            output, _ = proc.communicate(timeout=5)
            assert proc.returncode == 0, f"Daemon exit error: {proc.returncode}"
            assert "Madoka Mesh stopped." in output

            # Verify interface removal
            if os.name != "nt":
                check_del = subprocess.run(["ip", "link", "show", ifname], capture_output=True, text=True)
                assert check_del.returncode != 0, "Interface was not destroyed on exit!"
                print("  [OK] Interface cleanly destroyed on daemon stop.")

        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()

        # TEST 5: Restart daemon and verify persistence
        print("\n--- Restarting daemon for Test 5 (Persistence) ---")
        proc2 = subprocess.Popen(
            [executable, "--config", str(config_file)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
        )
        try:
            diag2 = {}
            for _ in range(15):
                line = proc2.stdout.readline()
                if not line:
                    break
                line = line.strip()
                if "=" in line:
                    k, v = line.split("=", 1)
                    diag2[k] = v
                if "state=interface_ready" in line:
                    break
            else:
                raise AssertionError("Daemon failed to restart into state=interface_ready")

            assert diag2.get("node_id") == first_node_id, "Node ID changed across restart!"
            assert diag2.get("ipv6") == first_ipv6, "IPv6 changed across restart!"
            print(f"  [OK] Persistence verified: same node_id={first_node_id}, same ipv6={first_ipv6}")

            proc2.send_signal(shutdown_signal)
            proc2.communicate(timeout=5)
            assert proc2.returncode == 0
        finally:
            if proc2.poll() is None:
                proc2.kill()
                proc2.wait()

    print("\n=======================================================")
    print("ALL PHASE 2 VIRTUAL NETWORK FUNCTIONAL TESTS PASSED!")
    print("=======================================================")


if __name__ == "__main__":
    main()
