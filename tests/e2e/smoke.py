"""Configuration, persisted identity and fail-closed runtime checks; stdlib only."""

import base64
import hashlib
import ipaddress
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile


executable = str(Path(sys.argv[1]).resolve())


def run(*arguments, cwd=None):
    return subprocess.run(
        [executable, *map(str, arguments)], capture_output=True, text=True,
        encoding="utf-8", timeout=5, cwd=cwd
    )


def check(config, success=True):
    result = run("--config", config, "--check")
    assert result.returncode == (0 if success else 1), result
    assert "PRIVATE KEY" not in result.stdout + result.stderr, result
    return dict(line.split("=", 1) for line in result.stdout.splitlines()) if success else result


help_result = run("--help")
assert help_result.returncode == 0 and "Usage:" in help_result.stdout, help_result
for arguments in (["--unknown"], ["--help", "unexpected"], ["--config"],
                  ["--config", "--check"], ["--check", "--check"],
                  ["--config", "", "--config", "valid.conf"],
                  ["--config", "one.conf", "--config", "two.conf"]):
    result = run(*arguments)
    assert result.returncode == 2 and "Usage:" in result.stderr, result

with tempfile.TemporaryDirectory(prefix="madoka-phase1-") as directory:
    root = Path(directory)
    config = root / "node configuração.conf"
    key = root / "identity.pem"
    base_config = (
        "network=fd12:3456:789a:1::/64\n"
        "identity=identity.pem\n"
        "listen=[::1]:0\n"
    )
    check(config, success=False)

    default_config = root / "madoka.conf"
    default_config.write_text(
        base_config.replace("identity.pem", "default-identity.pem"),
        encoding="utf-8")
    default_check = run("--check", cwd=root)
    assert default_check.returncode == 0, default_check
    no_arguments = run(cwd=root)
    assert no_arguments.returncode == 1, no_arguments
    assert "usage:" not in no_arguments.stderr.lower(), no_arguments
    offline_status = run("status", cwd=root)
    assert offline_status.returncode == 1, offline_status
    assert "stopped" in offline_status.stdout.lower(), offline_status

    invalid_configs = [
        "", "identity=identity.pem\n",
        base_config + "unknown=value\n", base_config + "identity=another.pem\n",
        base_config.replace("/64", "/48"), base_config.replace("/64", "/64/64"),
        base_config.replace("::/64", "::1/64"), base_config.replace("fd12", "2001"),
        base_config + "allow=not-an-id\n", base_config + "allow=" + "A" * 64 + "\n",
        base_config + "allow=" + "0" * 64 + "\n", base_config + "broken-line\n",
        base_config + "\0", "#" * 65537,
        base_config.replace("identity.pem", config.name),
        base_config + "interface=\n",
        base_config + "interface=too_long_interface_name_over_15\n",
        base_config + "interface=bad-char!\n",
        base_config + "mtu=1200\n",
        base_config + "mtu=not_a_number\n",
        base_config + "interface=tun0\ninterface=tun1\n",
        base_config + "mtu=1280\nmtu=1500\n",
        base_config + "listen=[::1]\n",
        base_config + "listen=::1:9000\n",
        base_config + "listen=[::1]:65536\n",
        base_config + "listen=[::1]:abc\n",
        base_config + "listen_port=9000\n",
    ]
    for contents in invalid_configs:
        config.write_text(contents, encoding="utf-8")
        check(config, success=False)
        assert not key.exists(), "Invalid configuration created an identity"

    config.write_text(base_config, encoding="utf-8")
    first = check(config)
    persisted = key.read_bytes()
    assert first == check(config), "Identity or address changed after restart"
    assert persisted == key.read_bytes(), "Restart rewrote the key"
    assert first["state"] == "ready" and first["trusted_peers"] == "0", first
    assert first["interface"] == "madoka0" and first["mtu"] == "1280", first
    assert Path(first["identity_file"]) == key, first
    assert ipaddress.IPv6Address(first["ipv6"]) in ipaddress.IPv6Network("fd12:3456:789a:1::/64")
    assert len(first["node_id"]) == 64

    config.write_text(base_config + "interface=custom0\nmtu=1400\n", encoding="utf-8")
    custom = check(config)
    assert custom["interface"] == "custom0" and custom["mtu"] == "1400", custom
    config.write_text(base_config, encoding="utf-8")

    config.write_text(base_config.replace("fd12:", "fd13:"), encoding="utf-8")
    changed_network = check(config)
    assert changed_network["node_id"] == first["node_id"]
    assert changed_network["ipv6"] != first["ipv6"]
    config.write_text(base_config.replace("identity.pem", "other.pem"), encoding="utf-8")
    other = check(config)
    assert other["node_id"] != first["node_id"] and other["ipv6"] != first["ipv6"]
    config.write_text(base_config.replace("identity.pem", "identidade-ação.pem"), encoding="utf-8")
    assert Path(check(config)["identity_file"]) == root / "identidade-ação.pem"
    config.write_text(base_config, encoding="utf-8")

    # RFC 8032 section 7.1, test 1. This published key is ONLY a test vector.
    seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    public = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    expected_id = hashlib.sha256(public).hexdigest()
    der = bytes.fromhex("302e020100300506032b657004220420") + seed
    known_key = (
        f"Madoka-Identity: 1\nNode-ID: {expected_id}\nGeneration: 1\n"
        "-----BEGIN PRIVATE KEY-----\n"
        + base64.b64encode(der).decode("ascii") + "\n-----END PRIVATE KEY-----\n"
    ).encode("ascii")
    key.write_bytes(known_key)  # Keep the private permissions established by Madoka.
    vector = check(config)
    assert vector["node_id"] == expected_id, vector
    expected_ip = ipaddress.IPv6Address(bytes.fromhex("fd123456789a0001" + expected_id[:16]))
    assert ipaddress.IPv6Address(vector["ipv6"]) == expected_ip, vector

    corrupted = [b"", b"invalid", b"x" * 4097, known_key + b"garbage\n",
                 known_key.replace(expected_id.encode(), b"0" * 64),
                 known_key.replace(base64.b64encode(der), base64.b64encode(der[:-1] + bytes([der[-1] ^ 1]))),
                 known_key.replace(b"Madoka-Identity: 1", b"Madoka-Identity: 2")]
    for contents in corrupted:
        key.write_bytes(contents)
        check(config, success=False)
        assert key.read_bytes() == contents, "Corrupt identity was overwritten"
    key.write_bytes(known_key)

    hardlink = root / "linked.pem"
    os.link(key, hardlink)
    check(config, success=False)
    hardlink.unlink()
    if os.name != "nt":
        assert stat.S_IMODE(key.stat().st_mode) == 0o600
        link = root / "symlink.pem"
        link.symlink_to(key)
        config.write_text(base_config.replace("identity.pem", "symlink.pem"), encoding="utf-8")
        check(config, success=False)
        config.write_text(base_config, encoding="utf-8")

print("Configuration, identity and lifecycle checks passed.")
