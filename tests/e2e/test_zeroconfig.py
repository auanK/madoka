#!/usr/bin/env python3
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time


def parse_status(config_path):
    status_file = Path(str(config_path) + ".status")
    if not status_file.exists():
        return {}
    try:
        lines = status_file.read_text(encoding="utf-8").splitlines()
    except OSError:
        return {}
    result = {"peers": [], "routes": []}
    for line in lines:
        if line.startswith("PEER="):
            result["peers"].append(line[5:])
        elif line.startswith("ROUTE="):
            result["routes"].append(line[6:])
        elif "=" in line:
            key, value = line.split("=", 1)
            result[key] = value
    return result


def wait_for(predicate, description, timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.2)
    raise TimeoutError(f"Timed out waiting for {description}")


def spawn(executable, arguments, log_path, env):
    log = open(log_path, "a", encoding="utf-8")
    process = subprocess.Popen(
        [executable, *map(str, arguments)],
        env=env,
        stdout=log,
        stderr=log,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
    )
    process._madoka_log = log
    return process


def stop(process):
    if process.poll() is None:
        process.send_signal(signal.CTRL_BREAK_EVENT if os.name == "nt" else signal.SIGTERM)
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)
    process._madoka_log.close()


def available_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


def main():
    executable = str(Path(sys.argv[1]).resolve())

    with tempfile.TemporaryDirectory(prefix="madoka-zeroconfig-") as directory:
        root = Path(directory)
        node1_dir = root / "node1"
        node2_dir = root / "node2"
        node3_dir = root / "node3"
        node1_dir.mkdir()
        node2_dir.mkdir()
        node3_dir.mkdir()

        env1 = os.environ.copy()
        env1["MADOKA_STATE_DIR"] = str(node1_dir)
        env1["MADOKA_MOCK_TUN"] = "1"

        env2 = os.environ.copy()
        env2["MADOKA_STATE_DIR"] = str(node2_dir)
        env2["MADOKA_MOCK_TUN"] = "1"

        env3 = os.environ.copy()
        env3["MADOKA_STATE_DIR"] = str(node3_dir)
        env3["MADOKA_MOCK_TUN"] = "1"

        port1 = available_port()
        port2 = available_port()
        while port2 == port1:
            port2 = available_port()
        port3 = available_port()

        processes = {}
        logs = {
            "node1": root / "node1.log",
            "node2": root / "node2.log",
            "node3": root / "node3.log",
        }

        try:
            processes["node1"] = spawn(
                executable, ["--listen", f"127.0.0.1:{port1}"], logs["node1"], env1
            )
            node1_config = node1_dir / "madoka.conf"
            status1 = wait_for(
                lambda: parse_status(node1_config) if node1_config.exists() else None,
                "node 1 auto-initialization",
            )
            assert (node1_dir / "identity.pem").exists(), "Node 1 identity not persisted"
            assert node1_config.exists(), "Node 1 config not persisted"

            conf1_text = node1_config.read_text(encoding="utf-8")
            assert "network=fd" in conf1_text, f"ULA prefix not generated in config: {conf1_text}"
            assert f"listen=127.0.0.1:{port1}" in conf1_text, conf1_text

            inv_res = subprocess.run(
                [executable, "invite"],
                env=env1,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=5,
            )
            assert inv_res.returncode == 0, inv_res
            token = inv_res.stdout.strip()
            assert token.startswith("madoka://invite/"), f"Expected invite token, got: {token}"
            assert not token.startswith("madoka://invite/v"), f"Expected unversioned invite, got: {token}"

            bad_token = token[:-4] + "AAAA"
            rej_res = subprocess.run(
                [executable, "join", bad_token, "--listen", f"127.0.0.1:{port3}"],
                env=env3,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=8,
            )
            assert rej_res.returncode == 1, rej_res
            assert not (node3_dir / "madoka.conf").exists(), "Rejected join created madoka.conf"
            assert not (node3_dir / "identity.pem").exists(), "Rejected join created identity.pem"

            processes["node2"] = spawn(
                executable,
                ["join", token, "--listen", f"127.0.0.1:{port2}"],
                logs["node2"],
                env2,
            )

            node2_config = node2_dir / "madoka.conf"
            wait_for(
                lambda: node2_config.exists() and (node2_dir / "identity.pem").exists(),
                "node 2 acceptance and persistence",
            )

            conf2_text = node2_config.read_text(encoding="utf-8")
            net1 = [l for l in conf1_text.splitlines() if l.startswith("network=")][0]
            net2 = [l for l in conf2_text.splitlines() if l.startswith("network=")][0]
            assert net1 == net2, f"Network mismatch: {net1} vs {net2}"

            def nodes_connected():
                s1 = parse_status(node1_config)
                s2 = parse_status(node2_config)
                if not s1.get("peers") or not s2.get("peers"):
                    return False
                return (
                    s2["NODE_ID"] in " ".join(s1["peers"])
                    and s1["NODE_ID"] in " ".join(s2["peers"])
                )

            wait_for(nodes_connected, "mesh connection between node 1 and node 2")

            reused = subprocess.run(
                [executable, "join", token, "--listen", f"127.0.0.1:{port3}"],
                env=env3,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=8,
            )
            assert reused.returncode == 1, reused
            assert not (node3_dir / "madoka.conf").exists(), "Reused token join created state"

            stop(processes.pop("node1"))
            wait_for(
                lambda: not parse_status(node2_config).get("peers"),
                "node 2 detects node 1 disconnect",
            )

            processes["node1"] = spawn(
                executable, ["--listen", f"127.0.0.1:{port1}"], logs["node1"], env1
            )
            wait_for(nodes_connected, "mesh reconnection after node 1 restart")

        except Exception:
            for n, p in logs.items():
                if p.exists():
                    print(f"=== LOG {n} ===")
                    print(p.read_text(encoding="utf-8", errors="replace"))
            raise
        finally:
            for process in processes.values():
                stop(process)

    print("Zero-config end-to-end test passed successfully.")


if __name__ == "__main__":
    main()
