#!/usr/bin/env python3
"""Destructive, opt-in real SSH E2E using one disposable remote test user.

Required environment:
  E2E_HOST, E2E_BOOTSTRAP_KEY

The bootstrap account defaults to root. The script creates an isolated user and
two temporary high-port sshd instances, then removes them in a finally block.
No supplied or generated credential is printed or persisted in the repository.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request


REPO = Path(__file__).resolve().parents[1]
REMOTE_FIXTURE = REPO / "tests" / "fixtures" / "remote_sshd_e2e.sh"
TEST_USER = "sshmcp-e2e"
PRIMARY_PORT = 22222
ROTATE_PORT = 22223


def required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"missing required environment variable: {name}")
    return value


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def run(command: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(command, check=True, text=True, **kwargs)


class Api:
    def __init__(self, base: str):
        self.base = base

    def request(self, path: str, body=None, method: str | None = None):
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(
            self.base + path,
            data=data,
            method=method or ("POST" if data is not None else "GET"),
            headers={"content-type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return response.status, json.loads(response.read() or b"{}")
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read() or b"{}")


class Mcp:
    def __init__(self, base: str):
        self.base = base
        self.next_id = 1
        status, headers, _ = self._post(
            {
                "jsonrpc": "2.0",
                "id": self.next_id,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "ssh-connector-e2e", "version": "1"},
                },
            },
            session=None,
        )
        assert status == 200
        self.session = headers.get("mcp-session-id")
        assert self.session
        self._post(
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            self.session,
        )

    def _post(self, payload, session):
        url = urllib.parse.urlparse(self.base)
        connection = http.client.HTTPConnection(url.hostname, url.port, timeout=900)
        headers = {
            "content-type": "application/json",
            "accept": "application/json, text/event-stream",
        }
        if session:
            headers["mcp-session-id"] = session
        connection.request("POST", "/mcp", json.dumps(payload), headers)
        response = connection.getresponse()
        body = response.read().decode()
        parsed_headers = {key.lower(): value for key, value in response.getheaders()}
        return response.status, parsed_headers, self._parse_sse(body)

    @staticmethod
    def _parse_sse(body: str):
        events = [
            line[6:]
            for line in body.splitlines()
            if line.startswith("data: ") and line[6:].strip()
        ]
        return json.loads(events[-1]) if events else {}

    def rpc(self, method: str, params=None):
        self.next_id += 1
        payload = {"jsonrpc": "2.0", "id": self.next_id, "method": method}
        if params is not None:
            payload["params"] = params
        status, _, envelope = self._post(payload, self.session)
        assert status == 200, (status, envelope)
        return envelope

    def call(self, name: str, arguments: dict):
        envelope = self.rpc("tools/call", {"name": name, "arguments": arguments})
        if "error" in envelope:
            return {"_error": envelope["error"]}
        result = envelope["result"]
        if result.get("isError"):
            return {"_error": result}
        return json.loads(result["content"][0]["text"])


def assert_error_code(result, expected: str):
    error = result.get("_error")
    assert error, result
    serialized = json.dumps(error)
    assert f'"code":"{expected}"' in serialized.replace(" ", ""), serialized


def wait_http(api: Api, process: subprocess.Popen):
    deadline = time.time() + 30
    while time.time() < deadline:
        if process.poll() is not None:
            raise RuntimeError("connector exited before becoming ready")
        try:
            status, _ = api.request("/api/status")
            if status == 200:
                return
        except OSError:
            pass
        time.sleep(0.1)
    raise RuntimeError("connector did not become ready")


def write_large_binary(path: Path, size: int):
    block = bytes(range(256)) * 4096
    with path.open("wb") as handle:
        remaining = size
        while remaining:
            chunk = block[: min(len(block), remaining)]
            handle.write(chunk)
            remaining -= len(chunk)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> int:
    host = required("E2E_HOST")
    bootstrap_key = Path(required("E2E_BOOTSTRAP_KEY")).resolve()
    bootstrap_user = os.environ.get("E2E_BOOTSTRAP_USER", "root")
    large_file_mib = int(os.environ.get("E2E_LARGE_FILE_MIB", "84"))
    skip_large_download = os.environ.get("E2E_SKIP_LARGE_DOWNLOAD") == "1"
    connector = Path(os.environ.get("CONNECTOR_BIN", REPO / "target/debug/ssh-connector"))
    work = Path(tempfile.mkdtemp(prefix="ssh-connector-e2e-", dir="/tmp"))
    known_hosts = work / "known_hosts"
    ssh_base = [
        "ssh",
        "-T",
        "-i",
        str(bootstrap_key),
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        f"UserKnownHostsFile={known_hosts}",
        "-o",
        "ConnectTimeout=10",
        f"{bootstrap_user}@{host}",
    ]

    client_key = work / "client_key"
    key_passphrase = secrets.token_urlsafe(24)
    test_password = secrets.token_urlsafe(24)
    master_password = secrets.token_urlsafe(24)
    remote_script = "/tmp/ssh-connector-remote-e2e.sh"
    remote_pubkey = "/tmp/client_key.pub"
    daemon = None
    remote_ready = False

    try:
        run(
            [
                "ssh-keygen",
                "-q",
                "-t",
                "ed25519",
                "-N",
                key_passphrase,
                "-f",
                str(client_key),
            ]
        )
        run(
            [
                "scp",
                "-q",
                "-i",
                str(bootstrap_key),
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "StrictHostKeyChecking=accept-new",
                "-o",
                f"UserKnownHostsFile={known_hosts}",
                str(REMOTE_FIXTURE),
                f"{bootstrap_user}@{host}:{remote_script}",
            ]
        )
        run(
            [
                "scp",
                "-q",
                "-i",
                str(bootstrap_key),
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "StrictHostKeyChecking=accept-new",
                "-o",
                f"UserKnownHostsFile={known_hosts}",
                str(client_key) + ".pub",
                f"{bootstrap_user}@{host}:{remote_pubkey}",
            ]
        )
        run(
            ssh_base
            + [
                f"chmod 700 {remote_script} && {remote_script} setup {remote_pubkey}"
            ],
            input=test_password + "\n",
        )
        remote_ready = True

        port = free_port()
        data_dir = work / "data"
        data_dir.mkdir()
        (data_dir / "config.toml").write_text(
            f"web_port = {port}\n"
            "mcp_port = 0\n"
            "exec_timeout_ms = 180000\n"
            "exec_output_cap_bytes = 1048576\n"
            "pty_idle_ttl_secs = 300\n"
            "keepalive_secs = 15\n"
            "max_channels_per_host = 8\n"
        )
        daemon = subprocess.Popen(
            [str(connector), "--data-dir", str(data_dir)],
            cwd=REPO,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        api = Api(f"http://127.0.0.1:{port}")
        wait_http(api, daemon)
        assert api.request("/api/vault/init", {"master_password": master_password})[0] == 200
        mcp = Mcp(api.base)
        encrypted_key_pem = client_key.read_text()
        bootstrap_key_pem = bootstrap_key.read_text()

        def add(alias, target_host, target_port, auth, jumps=None):
            result = mcp.call(
                "host_add",
                {
                    "alias": alias,
                    "host": target_host,
                    "port": target_port,
                    "user": TEST_USER,
                    "auth": auth,
                    "jump_hosts": jumps or [],
                    "env": {},
                },
            )
            assert "host_id" in result, result
            return result["host_id"]

        password_id = add(
            "e2e-password",
            host,
            PRIMARY_PORT,
            {"type": "password", "password": test_password},
        )
        key_id = add(
            "e2e-encrypted-key",
            host,
            PRIMARY_PORT,
            {
                "type": "private_key",
                "key_pem": encrypted_key_pem,
                "passphrase": key_passphrase,
            },
        )
        keyboard_id = add(
            "e2e-keyboard-interactive",
            host,
            PRIMARY_PORT,
            {"type": "keyboard_interactive", "answers": [test_password]},
        )
        jump = {
            "host": host,
            "port": 22,
            "user": bootstrap_user,
            "auth": {"type": "private_key", "key_pem": bootstrap_key_pem},
        }
        jump_id = add(
            "e2e-jump",
            "127.0.0.1",
            PRIMARY_PORT,
            {"type": "password", "password": test_password},
            [jump],
        )
        tofu_id = add(
            "e2e-tofu",
            host,
            ROTATE_PORT,
            {"type": "password", "password": test_password},
        )

        daemon.terminate()
        daemon.wait(timeout=10)
        daemon = subprocess.Popen(
            [str(connector), "--data-dir", str(data_dir)],
            cwd=REPO,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        wait_http(api, daemon)
        assert api.request("/api/status")[1]["vault_unlocked"] is False
        locked_mcp = Mcp(api.base)
        assert_error_code(locked_mcp.call("host_list", {}), "vault_locked")
        assert api.request("/api/vault/unlock", {"master_password": "wrong"})[0] == 401
        assert api.request("/api/vault/unlock", {"master_password": master_password})[0] == 200
        mcp = Mcp(api.base)

        for host_id in [password_id, key_id, keyboard_id, jump_id]:
            result = mcp.call("exec", {"host_id": host_id, "argv": ["id", "-un"]})
            assert result["stdout"].strip() == TEST_USER, result

        missing_passphrase = add(
            "e2e-key-no-passphrase",
            host,
            PRIMARY_PORT,
            {"type": "private_key", "key_pem": encrypted_key_pem},
        )
        assert_error_code(
            mcp.call("host_connect", {"host_id": missing_passphrase}),
            "private_key_passphrase_required",
        )
        wrong_passphrase = add(
            "e2e-key-wrong-passphrase",
            host,
            PRIMARY_PORT,
            {
                "type": "private_key",
                "key_pem": encrypted_key_pem,
                "passphrase": "intentionally-wrong",
            },
        )
        assert_error_code(
            mcp.call("host_connect", {"host_id": wrong_passphrase}),
            "private_key_passphrase_invalid",
        )
        wrong_password = add(
            "e2e-wrong-password",
            host,
            PRIMARY_PORT,
            {"type": "password", "password": "intentionally-wrong"},
        )
        assert_error_code(
            mcp.call("host_connect", {"host_id": wrong_password}), "auth_failed"
        )
        bad_jump_id = add(
            "e2e-bad-jump",
            "127.0.0.1",
            PRIMARY_PORT,
            {"type": "password", "password": test_password},
            [
                {
                    "host": host,
                    "port": 22,
                    "user": bootstrap_user,
                    "auth": {"type": "password", "password": "intentionally-wrong"},
                }
            ],
        )
        assert_error_code(
            mcp.call("host_connect", {"host_id": bad_jump_id}), "jump_failed_at_hop"
        )
        bad_final_id = add(
            "e2e-bad-final",
            "127.0.0.1",
            PRIMARY_PORT,
            {"type": "password", "password": "intentionally-wrong"},
            [jump],
        )
        assert_error_code(
            mcp.call("host_connect", {"host_id": bad_final_id}), "auth_failed"
        )

        source = work / "source.bin"
        download = work / "downloads" / "nested" / "source.bin"
        write_large_binary(source, large_file_mib * 1024 * 1024)
        source_sha = sha256(source)
        started = time.monotonic()
        upload = mcp.call(
            "sftp_upload_file",
            {
                "host_id": key_id,
                "local_path": str(source),
                "remote_path": f"/home/{TEST_USER}/packages/nested/source.bin",
            },
        )
        upload_seconds = time.monotonic() - started
        assert "bytes" in upload, upload
        assert upload["bytes"] == source.stat().st_size
        assert upload["sha256"] == source_sha and upload["verified"] is True
        assert_error_code(
            mcp.call(
                "sftp_upload_file",
                {
                    "host_id": key_id,
                    "local_path": str(source),
                    "remote_path": f"/home/{TEST_USER}/packages/nested/source.bin",
                },
            ),
            "bad_request",
        )
        download_seconds = 0.0
        download_bytes = 0
        if not skip_large_download:
            started = time.monotonic()
            downloaded = mcp.call(
                "sftp_download_file",
                {
                    "host_id": key_id,
                    "remote_path": f"/home/{TEST_USER}/packages/nested/source.bin",
                    "local_path": str(download),
                },
            )
            download_seconds = time.monotonic() - started
            download_bytes = downloaded["bytes"]
            assert downloaded["sha256"] == source_sha and downloaded["verified"] is True
            assert sha256(download) == source_sha

        replacement = work / "replacement.bin"
        write_large_binary(replacement, 1024 * 1024 + 17)
        replacement_sha = sha256(replacement)
        overwritten = mcp.call(
            "sftp_upload_file",
            {
                "host_id": key_id,
                "local_path": str(replacement),
                "remote_path": f"/home/{TEST_USER}/packages/nested/source.bin",
                "overwrite": True,
            },
        )
        assert overwritten["sha256"] == replacement_sha
        if skip_large_download:
            started = time.monotonic()
            downloaded = mcp.call(
                "sftp_download_file",
                {
                    "host_id": key_id,
                    "remote_path": f"/home/{TEST_USER}/packages/nested/source.bin",
                    "local_path": str(download),
                },
            )
            download_seconds = time.monotonic() - started
            download_bytes = downloaded["bytes"]
            assert downloaded["sha256"] == replacement_sha
            assert downloaded["verified"] is True
            assert sha256(download) == replacement_sha
        remote_hash = mcp.call(
            "exec",
            {
                "host_id": key_id,
                "argv": [
                    "sha256sum",
                    f"/home/{TEST_USER}/packages/nested/source.bin",
                ],
            },
        )
        assert remote_hash["stdout"].split()[0] == replacement_sha

        failed_local = work / "downloads" / "bad-chunk.bin"
        assert_error_code(
            mcp.call(
                "sftp_download_file",
                {
                    "host_id": key_id,
                    "remote_path": f"/home/{TEST_USER}/packages/nested/source.bin",
                    "local_path": str(failed_local),
                    "chunk_size_bytes": 1,
                },
            ),
            "bad_request",
        )
        assert not failed_local.exists()
        assert not list(failed_local.parent.glob("*.part"))
        assert_error_code(
            mcp.call(
                "sftp_upload_file",
                {
                    "host_id": key_id,
                    "local_path": str(source),
                    "remote_path": f"/home/{TEST_USER}/packages/nested/bad-chunk.bin",
                    "chunk_size_bytes": 1,
                },
            ),
            "bad_request",
        )
        remnants = mcp.call(
            "exec",
            {
                "host_id": key_id,
                "raw": f"find /home/{TEST_USER}/packages -name '*.part' -o -name '*.backup'",
            },
        )
        assert remnants["stdout"].strip() == "", remnants

        assert mcp.call("host_connect", {"host_id": tofu_id})["status"] == "connected"
        assert mcp.call("host_disconnect", {"host_id": tofu_id})["status"] == "disconnected"
        run(ssh_base + [f"{remote_script} rotate"])
        assert_error_code(
            mcp.call("host_connect", {"host_id": tofu_id}), "host_key_mismatch"
        )

        host_list_text = json.dumps(mcp.call("host_list", {}))
        for secret in [test_password, key_passphrase, encrypted_key_pem, bootstrap_key_pem]:
            assert secret not in host_list_text
        tools_text = json.dumps(mcp.rpc("tools/list"))
        assert "credential_reveal" not in tools_text and '"reveal"' not in tools_text
        assert api.request(
            f"/api/hosts/{password_id}/reveal", {"master_password": "wrong"}
        )[0] == 401
        status, revealed = api.request(
            f"/api/hosts/{password_id}/reveal",
            {"master_password": master_password},
        )
        assert status == 200 and revealed["auth"]["type"] == "password"

        daemon_rss_kib = int(
            subprocess.check_output(
                ["ps", "-o", "rss=", "-p", str(daemon.pid)], text=True
            ).strip()
        )

        print(
            json.dumps(
                {
                    "result": "PASS",
                    "large_file_bytes": source.stat().st_size,
                    "downloaded_file_bytes": download_bytes,
                    "sha256": source_sha,
                    "upload_seconds": round(upload_seconds, 3),
                    "download_seconds": round(download_seconds, 3),
                    "upload_mib_per_second": round(
                        (source.stat().st_size / 1024 / 1024) / upload_seconds, 3
                    ),
                    "download_mib_per_second": round(
                        (download_bytes / 1024 / 1024) / download_seconds, 3
                    ),
                    "daemon_rss_kib_after_transfers": daemon_rss_kib,
                    "auth_modes": [
                        "password",
                        "private_key_passphrase",
                        "keyboard_interactive",
                        "jump_host",
                    ],
                    "vault_locked_unlocked": True,
                    "tofu_mismatch": True,
                    "credential_boundary": True,
                },
                sort_keys=True,
            )
        )
        return 0
    finally:
        if daemon is not None and daemon.poll() is None:
            daemon.terminate()
            try:
                daemon.wait(timeout=10)
            except subprocess.TimeoutExpired:
                daemon.kill()
        if remote_ready:
            subprocess.run(
                ssh_base + [f"{remote_script} cleanup"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        subprocess.run(
            ssh_base
            + [
                f"unlink {remote_script} 2>/dev/null || true; "
                f"unlink {remote_pubkey} 2>/dev/null || true"
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"E2E FAILED: {error}", file=sys.stderr)
        raise
