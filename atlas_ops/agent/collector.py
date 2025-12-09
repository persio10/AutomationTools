from __future__ import annotations

import argparse
import json
import platform
import socket
import subprocess
from datetime import datetime
from typing import Dict, List, Optional

import urllib.error
import urllib.request


def get_host_facts() -> Dict[str, str]:
    return {
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "python_version": platform.python_version(),
    }


def get_gateways() -> List[Dict[str, str]]:
    gateways: List[Dict[str, str]] = []
    try:
        output = subprocess.check_output(["ip", "route"], text=True)
        for line in output.splitlines():
            if line.startswith("default via"):
                parts = line.split()
                gateways.append({"gateway": parts[2], "dev": parts[4] if len(parts) > 4 else "unknown"})
    except Exception:
        pass
    return gateways


def ping_target(target: str, count: int = 2) -> Optional[float]:
    try:
        output = subprocess.check_output(["ping", "-c", str(count), target], text=True)
        for line in output.splitlines():
            if "rtt min/avg/max" in line:
                avg = line.split("=")[-1].split("/")[1]
                return float(avg)
    except Exception:
        return None
    return None


def collect_signal(site_id: str) -> Dict:
    facts = get_host_facts()
    gateways = get_gateways()
    latency = ping_target(gateways[0]["gateway"]) if gateways else None
    return {
        "site_id": site_id,
        "kind": "agent_facts",
        "summary": "Host snapshot + gateway probe",
        "detail": {"facts": facts, "gateways": gateways, "gateway_latency_ms": latency},
        "severity": "info" if latency is None or latency < 100 else "warning",
        "observed_at": datetime.utcnow().isoformat() + "Z",
    }


def post_signal(backend: str, token: Optional[str], signal: Dict) -> Dict:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(
        f"{backend.rstrip('/')}/api/signals",
        data=json.dumps(signal).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:  # nosec: B310 (local network)
            body = resp.read()
            return json.loads(body)
    except urllib.error.HTTPError as exc:  # pragma: no cover - only raised on failure
        raise RuntimeError(f"Failed to post signal: {exc.read().decode()}") from exc


def main() -> None:
    parser = argparse.ArgumentParser(description="Atlas Ops agent collector")
    parser.add_argument("--backend", required=True, help="Backend base URL, e.g. http://localhost:8000")
    parser.add_argument("--site", default="homelab-1", help="Site ID for this agent")
    parser.add_argument("--token", default=None, help="Bearer token (optional)")
    args = parser.parse_args()

    signal = collect_signal(args.site)
    posted = post_signal(args.backend, args.token, signal)
    print("Posted signal", json.dumps(posted, indent=2))


if __name__ == "__main__":
    main()
