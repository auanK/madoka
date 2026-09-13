#!/usr/bin/env python3
"""Invite-based A-B-C mesh, one-time admission and restart recovery."""

import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time


def parse_status(config):
    path = Path(str(config) + ".status")
    if not path.exists():
        return {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
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


def invite(executable, config):
    result = subprocess.run(
        [executable, "invite", "--config", str(config)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=5,
    )
    assert result.returncode == 0, result
    token = result.stdout.strip()
    assert token.startswith("madoka://invite/"), result
    return token


def config(path, port):
    path.write_text(
        "network=fd12:3456:789a:1::/64\n"
        f"listen=127.0.0.1:{port}\n",
        encoding="utf-8",
    )


def available_ports(count):
    sockets = []
    try:
        for _ in range(count):
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.bind(("127.0.0.1", 0))
            sockets.append(listener)
        return [listener.getsockname()[1] for listener in sockets]
    finally:
        for listener in sockets:
            listener.close()


def main():
    executable = str(Path(sys.argv[1]).resolve())
    env = os.environ.copy()
    env["MADOKA_MOCK_TUN"] = "1"

    with tempfile.TemporaryDirectory(prefix="madoka-invite-mesh-") as directory:
        root = Path(directory)
        configs = {}
        for name in ("a", "b", "c", "x"):
            node_directory = root / name
            node_directory.mkdir()
            configs[name] = node_directory / "madoka.conf"
        for name, port in zip(configs, available_ports(len(configs))):
            config(configs[name], port)
        logs = {name: root / f"{name}.log" for name in configs}
        processes = {}

        try:
            processes["a"] = spawn(
                executable, ["--config", configs["a"]], logs["a"], env
            )
            status_a = wait_for(
                lambda: parse_status(configs["a"]) or None, "node A startup"
            )
            token_b = invite(executable, configs["a"])

            processes["b"] = spawn(
                executable,
                ["join", token_b, "--config", configs["b"]],
                logs["b"],
                env,
            )
            wait_for(
                lambda: len(parse_status(configs["a"]).get("peers", [])) == 1,
                "B admission",
            )
            wait_for(
                lambda: parse_status(configs["b"]).get("peers"), "node B startup"
            )
            token_c = invite(executable, configs["b"])

            processes["c"] = spawn(
                executable,
                ["join", token_c, "--config", configs["c"]],
                logs["c"],
                env,
            )

            def converged():
                a = parse_status(configs["a"])
                b = parse_status(configs["b"])
                c = parse_status(configs["c"])
                if not all(state.get("NODE_ID") for state in (a, b, c)):
                    return False
                route_a_c = any(
                    c["NODE_ID"] in route and "metric 2" in route
                    for route in a["routes"]
                )
                route_c_a = any(
                    a["NODE_ID"] in route and "metric 2" in route
                    for route in c["routes"]
                )
                return route_a_c and route_c_a and len(b["peers"]) == 2

            wait_for(converged, "A-B-C route convergence")
            a = parse_status(configs["a"])
            b = parse_status(configs["b"])
            c = parse_status(configs["c"])
            assert all("Trusted" in peer for state in (a, b, c) for peer in state["peers"])
            assert a["TRUSTED"] == "1" and b["TRUSTED"] == "2" and c["TRUSTED"] == "1"
            assert c["NODE_ID"] not in " ".join(a["peers"])

            reused = subprocess.run(
                [executable, "join", token_c, "--config", str(configs["x"])],
                env=env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=8,
            )
            assert reused.returncode == 1, reused
            assert "rejected" in (reused.stdout + reused.stderr).lower(), reused

            status_command = subprocess.run(
                [executable, "status", "--config", str(configs["a"])],
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=5,
            )
            assert status_command.returncode == 0
            assert b["NODE_ID"] in status_command.stdout
            assert c["NODE_ID"] in status_command.stdout

            stop(processes.pop("b"))
            wait_for(
                lambda: not parse_status(configs["a"]).get("peers")
                and not parse_status(configs["c"]).get("peers"),
                "route withdrawal",
            )
            processes["b"] = spawn(
                executable, ["--config", configs["b"]], logs["b"], env
            )
            wait_for(converged, "automatic trusted-peer reconnection")
        except Exception:
            for n, p in logs.items():
                if p.exists():
                    print(f"=== LOG {n} ===")
                    print(p.read_text(encoding="utf-8", errors="replace"))
            raise
        finally:
            for process in processes.values():
                stop(process)

        for path in configs.values():
            assert not Path(str(path) + ".status").exists()
        for name in ("a", "b", "c"):
            values = [
                int(value)
                for value in re.findall(
                    r"route_advertisements_sent=(\d+)",
                    logs[name].read_text(encoding="utf-8"),
                )
            ]
            assert values and max(values) < 100, values

    print("Invite-based three-node mesh test passed.")


if __name__ == "__main__":
    main()
