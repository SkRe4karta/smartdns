#!/usr/bin/env python3
"""Per-installation ACME renewal and atomic certificate deployment (stdlib only)."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import signal
import subprocess
import time
from pathlib import Path


def run(args: list[str]) -> str:
    with subprocess.Popen(
        args, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True
    ) as process:
        try:
            output, error = process.communicate(timeout=110)
        except BaseException:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate()
            raise
        if process.returncode:
            raise subprocess.CalledProcessError(process.returncode, args, output, error)
        return output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["apply", "prepare", "renew", "dry-run"])
    parser.add_argument("--config", type=Path, default=Path("/etc/smartdns/certificates.json"))
    args = parser.parse_args()
    os.umask(0o077)
    cfg = json.loads(args.config.read_text())
    os.environ.setdefault(
        "ACME_DNS_CREDENTIALS", cfg.get("acme_dns_credentials", "/etc/smartdns/acme-dns.json")
    )
    state = Path(cfg["status_file"])
    state.parent.mkdir(parents=True, exist_ok=True)
    lock = Path(cfg["lock_file"])
    lock.parent.mkdir(parents=True, exist_ok=True)
    with lock.open("a") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        previous = {}
        if state.exists():
            previous = json.loads(state.read_text())
        status = previous | {"last_attempt": int(time.time()), "last_error": None}
        try:
            if args.action in ("renew", "dry-run"):
                command = [
                    "certbot",
                    "renew",
                    "--non-interactive",
                    # systemd already schedules renewal; Certbot's random sleep exceeds our deadline.
                    "--no-random-sleep-on-renew",
                    "--cert-name",
                    cfg["cert_name"],
                    "--config-dir",
                    cfg["config_dir"],
                    "--work-dir",
                    cfg["work_dir"],
                    "--logs-dir",
                    cfg["logs_dir"],
                ]
                if args.action == "dry-run":
                    command += ["--dry-run"]
                # Apply only after Certbot completes; never recurse through a deploy hook holding this lock.
                run(command)
            if args.action != "dry-run":
                lineage = Path(cfg["config_dir"]) / "live" / cfg["cert_name"]
                chain, key = lineage / "fullchain.pem", lineage / "privkey.pem"
                run(["openssl", "x509", "-in", str(chain), "-noout", "-checkend", "86400"])
                names = run(["openssl", "x509", "-in", str(chain), "-noout", "-ext", "subjectAltName"])
                actual = {
                    part.strip().removeprefix("DNS:")
                    for line in names.splitlines()[1:]
                    for part in line.split(",")
                }
                if not {cfg["domain"], "*." + cfg["domain"]} <= actual:
                    raise ValueError("Certificate must cover base and wildcard DNS names")
                cp = run(["openssl", "x509", "-in", str(chain), "-pubkey", "-noout"])
                kp = run(["openssl", "pkey", "-in", str(key), "-pubout"])
                if cp != kp:
                    raise ValueError("Certificate and private key do not match")
                content = chain.read_bytes()
                if b"STAGING" in content or "STAGING" in run(
                    ["openssl", "x509", "-in", str(chain), "-issuer", "-noout"]
                ):
                    raise ValueError("Refusing a staging certificate")
                destination = Path(cfg["certificate_dir"])
                destination.mkdir(parents=True, exist_ok=True)
                fingerprint = hashlib.sha256(content).hexdigest()[:24]
                version = destination / "versions" / fingerprint
                version.mkdir(parents=True, exist_ok=True, mode=0o750)
                import grp

                gid = grp.getgrnam(cfg.get("group", "smartdns")).gr_gid
                for directory in (destination, destination / "versions", version):
                    os.chown(directory, 0, gid)
                    directory.chmod(0o750)
                for source in (chain, key):
                    target = version / source.name
                    data = source.read_bytes()
                    if target.exists():
                        if target.read_bytes() != data:
                            raise ValueError("Managed certificate version was modified")
                        continue
                    pending = target.with_suffix(".new")
                    with pending.open("wb") as output:
                        output.write(data)
                        output.flush()
                        os.fsync(output.fileno())
                    os.chown(pending, 0, gid)
                    pending.chmod(0o640)
                    pending.replace(target)
                link = destination / "current"
                old = link.readlink() if link.is_symlink() else None
                temp = destination / "current.new"
                temp.unlink(missing_ok=True)
                temp.symlink_to(version)
                temp.replace(link)
                try:
                    if args.action == "prepare":
                        status["last_success"] = int(time.time())
                        return
                    run(["nginx", "-t"])
                    run(["systemctl", "reload", "nginx"])
                    run(
                        [
                            "systemctl",
                            "kill",
                            "--kill-whom=main",
                            "--signal=HUP",
                            cfg.get("gateway_unit", "smartdns-gateway"),
                        ]
                    )
                except subprocess.CalledProcessError:
                    if old is not None:
                        temp.symlink_to(old)
                        temp.replace(link)
                        run(["systemctl", "reload", "nginx"])
                    raise
                status["fingerprint"] = fingerprint
                status["last_deployment"] = int(time.time())
            status["last_success"] = int(time.time())
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            # Do not store command output, tokens, paths or account identifiers in diagnostics.
            status["last_error"] = type(exc).__name__
            raise
        finally:
            temp = state.with_suffix(".new")
            temp.write_text(json.dumps(status))
            temp.chmod(0o644)
            temp.replace(state)


if __name__ == "__main__":
    main()
