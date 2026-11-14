"""Create a short-lived, ignored local CA and server certificate for lab probes."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
RUNTIME = ROOT / "infrastructure/lab/runtime"
CA = RUNTIME / "ca.crt"
SERVER_CERT = RUNTIME / "server.crt"
SERVER_KEY = RUNTIME / "server.key"


def _run(*args: str) -> None:
    subprocess.run(["openssl", *args], cwd=RUNTIME, capture_output=True,
                   text=True, check=True, timeout=20)


def ensure_lab_pki() -> None:
    RUNTIME.mkdir(parents=True, exist_ok=True)
    if all(path.is_file() for path in (CA, SERVER_CERT, SERVER_KEY)):
        try:
            _run("x509", "-checkend", "86400", "-noout", "-in", str(SERVER_CERT))
            return
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass
    extension = RUNTIME / "server.ext"
    extension.write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n"
        "subjectAltName=IP:127.0.0.1,DNS:localhost\n"
    )
    _run("req", "-x509", "-newkey", "rsa:2048", "-noenc", "-sha256", "-days", "7",
         "-subj", "/CN=Sovereign Synthetic Lab CA",
         "-addext", "basicConstraints=critical,CA:TRUE",
         "-addext", "keyUsage=critical,keyCertSign,cRLSign",
         "-keyout", str(RUNTIME / "ca.key"), "-out", str(CA))
    _run("req", "-newkey", "rsa:2048", "-noenc", "-sha256",
         "-subj", "/CN=Sovereign Synthetic Lab",
         "-keyout", str(SERVER_KEY), "-out", str(RUNTIME / "server.csr"))
    _run("x509", "-req", "-in", str(RUNTIME / "server.csr"),
         "-CA", str(CA), "-CAkey", str(RUNTIME / "ca.key"), "-set_serial", "1",
         "-days", "7", "-sha256", "-extfile", str(extension),
         "-out", str(SERVER_CERT))
    os.chmod(RUNTIME / "ca.key", 0o600)
    os.chmod(SERVER_KEY, 0o600)
