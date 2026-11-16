#!/usr/bin/env python3
"""One-command synthetic lab bring-up, probe and teardown."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import ssl
import subprocess
import sys
import time
from urllib.error import URLError
from urllib.request import urlopen

from infrastructure.lab.pki import CA, ensure_lab_pki
from infrastructure.lab.dns import query as dns_query

ROOT = Path(__file__).resolve().parents[1]
TOPOLOGY = json.loads((ROOT / "infrastructure/lab/topology.json").read_text())


def _open(url: str, timeout: float = 30):
    context = ssl.create_default_context(cafile=str(CA))
    return urlopen(url, timeout=timeout, context=context)


def check(quiet: bool = False) -> bool:
    results: dict[str, bool] = {}
    for name, port in TOPOLOGY["services"].items():
        try:
            with _open(f"https://127.0.0.1:{port}/health", timeout=1) as response:
                payload = json.load(response)
                results[name] = payload == {
                    "service": name, "status": "ok", "mode": "synthetic-loopback"
                }
        except (URLError, TimeoutError, ValueError, OSError):
            results[name] = False
    try:
        results["dns"] = dns_query("console.lab.sovereign.test") == "127.0.0.1"
    except (TimeoutError, ValueError, OSError):
        results["dns"] = False
    if not quiet:
        print(json.dumps({"health": results, "all_ok": all(results.values())}, indent=2))
    return all(results.values())


def verify_smoke() -> None:
    with _open("https://127.0.0.1:18080/") as response:
        assert b"synthetic lab health dashboard" in response.read().lower()
    with _open("https://127.0.0.1:18080/lab-status") as response:
        summary = json.load(response)
        assert len(summary["services"]) == len(TOPOLOGY["services"])
        assert all(item["status"] == "ok" for item in summary["services"].values())
    with _open("https://127.0.0.1:18085/events") as response:
        assert len(response.read().splitlines()) >= 4
    for name, port in TOPOLOGY["services"].items():
        with _open(f"https://127.0.0.1:{port}/metrics") as response:
            sample = json.load(response)
            assert sample["service"] == name
            assert "storage_free_bytes" in sample and "gpu" in sample
    assert dns_query("console.lab.sovereign.test") == "127.0.0.1"
    assert dns_query("unknown.lab.sovereign.test") is None
    try:
        urlopen("https://127.0.0.1:18081/health", timeout=3)
    except URLError as exc:
        assert isinstance(exc.reason, ssl.SSLCertVerificationError)
    else:
        raise AssertionError("untrusted lab certificate was accepted")
    from scripts.phase5_install_rehearsal import rehearse
    assert rehearse()["result"] == "pass"


def up(smoke: bool = False) -> bool:
    children: list[subprocess.Popen[bytes]] = []
    try:
        ensure_lab_pki()
        children.append(subprocess.Popen(
            [sys.executable, "-m", "infrastructure.lab.dns"],
            cwd=ROOT, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL if smoke else None,
        ))
        for name in TOPOLOGY["services"]:
            children.append(subprocess.Popen(
                [sys.executable, "-m", "infrastructure.lab.server", name],
                cwd=ROOT,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL if smoke else None,
            ))
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if any(child.poll() is not None for child in children):
                raise RuntimeError("lab service exited during startup")
            if check(quiet=True):
                print("Synthetic lab ready on 127.0.0.1; Console: https://127.0.0.1:18080/")
                if smoke:
                    verify_smoke()
                    print("Smoke checks passed: dashboard, health, metrics, events, local DNS and TLS trust rejection")
                    return True
                while True:
                    time.sleep(0.5)
                    if any(child.poll() is not None for child in children):
                        raise RuntimeError("lab service exited")
            time.sleep(0.2)
        raise RuntimeError("lab health probes timed out")
    except KeyboardInterrupt:
        return True
    except (RuntimeError, AssertionError, URLError, ValueError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return False
    finally:
        for child in children:
            child.terminate()
        for child in children:
            try:
                child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("up", "check", "smoke"))
    args = parser.parse_args()
    ok = check() if args.command == "check" else up(smoke=args.command == "smoke")
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    main()
