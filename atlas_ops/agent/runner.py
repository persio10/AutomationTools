from __future__ import annotations

import argparse
import json
import logging
import os
import platform
import socket
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from urllib import error, request

from ..config import DockerIntegrationConfig, load_agent_config

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("atlas_ops.agent")


def get_host_facts() -> Dict[str, str]:
    return {
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "python_version": platform.python_version(),
    }


def get_gateways() -> List[Dict[str, str]]:
    gateways: List[Dict[str, str]] = []
    try:
        if platform.system().lower().startswith("win"):
            output = subprocess.check_output(["route", "print", "-4"], text=True)
            for line in output.splitlines():
                if line.strip().startswith("0.0.0.0"):
                    parts = line.split()
                    if len(parts) >= 4:
                        gateways.append({"gateway": parts[2], "dev": parts[3]})
        else:
            output = subprocess.check_output(["ip", "route"], text=True)
            for line in output.splitlines():
                if line.startswith("default via"):
                    parts = line.split()
                    gateways.append({"gateway": parts[2], "dev": parts[4] if len(parts) > 4 else "unknown"})
    except Exception:
        logger.debug("Gateway discovery failed", exc_info=True)
    return gateways


def ping_target(target: str, count: int = 2) -> Optional[float]:
    try:
        if platform.system().lower().startswith("win"):
            cmd = ["ping", "-n", str(count), target]
        else:
            cmd = ["ping", "-c", str(count), target]
        output = subprocess.check_output(cmd, text=True)
        for line in output.splitlines():
            if "Average" in line and "ms" in line:
                parts = line.split("Average =")[-1]
                return float(parts.replace("ms", "").strip())
            if "rtt min/avg/max" in line:
                avg = line.split("=")[-1].split("/")[1]
                return float(avg)
    except Exception:
        logger.debug("Ping failed for %s", target, exc_info=True)
        return None
    return None


def load_state(state_path: Path) -> dict:
    if state_path.exists():
        try:
            return json.loads(state_path.read_text())
        except Exception:
            return {}
    return {}


def save_state(state_path: Path, payload: dict) -> None:
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps(payload))


def _docker_client(endpoint: str):
    try:
        import docker  # type: ignore

        client = docker.DockerClient(base_url=endpoint)
        return client
    except Exception as exc:  # pragma: no cover - optional dependency
        logger.warning("Docker SDK unavailable or failed to init for %s: %s", endpoint, exc)
        return None


def collect_docker_signals(docker_hosts: List[DockerIntegrationConfig], state_path: Path) -> List[Dict]:
    signals: List[Dict] = []
    state = load_state(state_path)
    new_state: dict = {"containers": {}}
    for host in docker_hosts:
        client = _docker_client(host.endpoint)
        if not client:
            continue
        try:
            containers = client.containers.list(all=True)
        except Exception as exc:  # pragma: no cover - runtime guard
            logger.warning("Docker list failed for %s: %s", host.endpoint, exc)
            continue
        for container in containers:
            status = container.status
            restart_count = container.attrs.get("RestartCount", 0)
            container_id = container.short_id
            name = container.name
            new_state["containers"][container_id] = {"status": status, "restart": restart_count}
            prev = state.get("containers", {}).get(container_id, {})
            if status != "running" and prev.get("status") == "running":
                signals.append(
                    {
                        "kind": "container_down",
                        "summary": f"Docker container stopped: {name}",
                        "detail": {"container": name, "endpoint": host.endpoint, "status": status},
                        "severity": "warning",
                    }
                )
            if restart_count and restart_count >= host.restart_threshold:
                signals.append(
                    {
                        "kind": "container_restart_count_high",
                        "summary": f"Docker container restart count high: {name}",
                        "detail": {
                            "container": name,
                            "endpoint": host.endpoint,
                            "restart_count": restart_count,
                            "threshold": host.restart_threshold,
                        },
                        "severity": "warning",
                    }
                )
    save_state(state_path, new_state)
    return signals


def collect_signal(site_id: str, docker_hosts: List[DockerIntegrationConfig], state_path: Path) -> List[Dict]:
    facts = get_host_facts()
    gateways = get_gateways()
    latency = ping_target(gateways[0]["gateway"]) if gateways else None
    base_signal = {
        "site_id": site_id,
        "kind": "agent_facts",
        "summary": "Host snapshot + gateway probe",
        "detail": {"facts": facts, "gateways": gateways, "gateway_latency_ms": latency},
        "severity": "info" if latency is None or latency < 100 else "warning",
        "observed_at": datetime.utcnow().isoformat() + "Z",
    }
    signals = [base_signal]
    if docker_hosts:
        docker_signals = collect_docker_signals(docker_hosts, state_path)
        for ds in docker_signals:
            ds.update({"site_id": site_id, "observed_at": datetime.utcnow().isoformat() + "Z", "source": "agent"})
        signals.extend(docker_signals)
    return signals


def post_signal(backend: str, token: Optional[str], signal: Dict) -> Dict:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = request.Request(
        f"{backend.rstrip('/')}/api/signals",
        data=json.dumps(signal).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with request.urlopen(req, timeout=10) as resp:  # nosec B310
            body = resp.read()
            return json.loads(body)
    except error.HTTPError as exc:  # pragma: no cover - failure path
        raise RuntimeError(f"Failed to post signal: {exc.read().decode()}") from exc


def run_once(config_path: Path) -> List[Dict]:
    cfg = load_agent_config(config_path).agent
    state_path = Path(cfg.state_path or (Path(config_path).parent / ".atlas_ops_state.json"))
    signals = collect_signal(cfg.site_id, cfg.docker_hosts, state_path)
    posted = []
    for signal in signals:
        payload = {**signal, "source": signal.get("source", "agent")}
        posted.append(post_signal(cfg.backend_url, cfg.token, payload))
    for item in posted:
        logger.info("Posted signal %s to %s", item.get("id"), cfg.backend_url)
    return posted


def loop(config_path: Path) -> None:
    cfg = load_agent_config(config_path).agent
    while True:
        try:
            run_once(config_path)
        except Exception as exc:  # pragma: no cover - runtime logging
            logger.error("Agent run failed: %s", exc)
        time.sleep(cfg.interval_seconds)


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Atlas Ops agent runner")
    parser.add_argument("--config", required=True, help="Path to agent_config.yaml")
    parser.add_argument("--once", action="store_true", help="Run once instead of loop")
    args = parser.parse_args(argv)

    config_path = Path(args.config)
    if args.once:
        run_once(config_path)
    else:
        loop(config_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
