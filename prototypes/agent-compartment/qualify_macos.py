"""Run actual OS denial probes using only synthetic task-owned fixtures.

Invoke this script through the host scheduler's mac-native lane. It never runs
an unsandboxed agent fallback, changes global settings, or contacts a provider.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import platform
import resource
import select
import signal
import socket
import subprocess
import sys
import tempfile
import time

from broker import Refused, read_frame, write_frame

HERE = Path(__file__).resolve().parent


def limits() -> None:
    resource.setrlimit(resource.RLIMIT_CPU, (2, 2))
    resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))


def qualify(diagnostics: bool = False) -> dict:
    if sys.platform != "darwin" or not Path("/usr/bin/sandbox-exec").is_file():
        raise Refused("unsupported platform: no sandbox fallback")
    if not Path("/usr/bin/clang").is_file():
        raise Refused("missing qualification compiler")
    with tempfile.TemporaryDirectory(prefix="vhalla-compartment-", dir="/private/tmp") as temporary:
        root = Path(temporary).resolve()
        binary = root / "agent-probe"
        built = subprocess.run(
            ["/usr/bin/clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2",
             str(HERE / "agent_probe.c"), "-o", str(binary)],
            capture_output=True, timeout=30, check=False,
        )
        if built.returncode:
            raise Refused("qualification fixture compilation failed")
        canary = root / "synthetic-canary"
        content = b"synthetic room A data, never real custody or credentials\n"
        canary.write_bytes(content)
        canary.chmod(0o600)
        unix_path = root / "fixture.sock"
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp, socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as local:
            tcp.bind(("127.0.0.1", 0))
            tcp.listen(1)
            local.bind(str(unix_path))
            local.listen(1)
            command = [
                "/usr/bin/sandbox-exec", "-f", str(HERE / "macos.sb"),
                "-D", f"PROBE_BINARY={binary}", str(binary), str(canary),
                str(tcp.getsockname()[1]), str(unix_path),
            ]
            # Only explicitly selected pipes cross the boundary. No inherited
            # environment, home path, network FD, store FD or credential is sent.
            child = subprocess.Popen(
                command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, close_fds=True, env={"LC_ALL": "C"},
                cwd=root, start_new_session=True, preexec_fn=limits,
            )
            try:
                assert child.stdin is not None and child.stdout is not None
                os.set_blocking(child.stdin.fileno(), False)
                os.set_blocking(child.stdout.fileno(), False)
                deadline = time.monotonic() + 5
                supplied = b"synthetic room B input selected for this fixed child lifetime"
                write_frame(child.stdin.fileno(), supplied, deadline)
                child.stdin.close()
                response = read_frame(child.stdout.fileno(), deadline)
                if response != bytes([63]) + supplied:
                    raise Refused("a required OS denial probe failed")
                if child.wait(timeout=max(0.01, deadline - time.monotonic())) != 0:
                    raise Refused("sandboxed child failed")
                if child.stdout.read(1) not in (b"", None):
                    raise Refused("unexpected extra child output")
                if select.select([tcp, local], [], [], 0)[0]:
                    raise Refused("forbidden connection reached a fixture listener")
                if canary.read_bytes() != content:
                    raise Refused("synthetic canary was changed")
                return {
                    "status": "qualified-prototype-only",
                    "os": platform.mac_ver()[0],
                    "backend": "deprecated-sandbox-exec",
                    "denied": ["canary-read", "canary-write", "tcp-connect", "unix-connect", "fork", "external-exec"],
                    "inherited_pipe_roundtrip": True,
                    "provider_calls": 0,
                    "production_ready": False,
                }
            finally:
                if child.poll() is None:
                    # Only the exact task-created child process group is stopped.
                    os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=5)
                if diagnostics:
                    print(json.dumps({"fixture_exit": child.returncode}), file=sys.stderr)
                if child.stderr is not None:
                    # Bounded fixture-only diagnostics, never agent room text.
                    error = child.stderr.read(4096)
                    if diagnostics and error:
                        print(json.dumps({"fixture_stderr": error.decode("utf-8", errors="replace")}), file=sys.stderr)
                    child.stderr.close()
                if child.stdin is not None:
                    child.stdin.close()
                if child.stdout is not None:
                    child.stdout.close()


if __name__ == "__main__":
    try:
        print(json.dumps(qualify("--diagnostics" in sys.argv[1:]), sort_keys=True))
    except (Refused, OSError, subprocess.SubprocessError) as error:
        # Exceptions are local closed diagnostics; do not emit child bytes or
        # filesystem paths supplied in a future actual room request.
        print(json.dumps({"status": "refused", "reason": str(error) if isinstance(error, Refused) else type(error).__name__}))
        sys.exit(1)
