from __future__ import annotations

import argparse
import secrets
from pathlib import Path
from typing import Optional

import yaml

from .config import (
    AgentConfig,
    AgentFileConfig,
    AppConfig,
    BackendConfig,
    DEFAULT_AGENT_CONFIG_PATH,
    DEFAULT_BACKEND_CONFIG_PATH,
)
from .persistence import bootstrap_database


def prompt(text: str, default: Optional[str] = None) -> str:
    suffix = f" [{default}]" if default is not None else ""
    value = input(f"{text}{suffix}: ").strip()
    return value or (default or "")


def write_yaml(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(payload, handle, sort_keys=False)


def write_systemd_template(path: Path, description: str, command: str) -> None:
    unit = f"""[Unit]
Description={description}
After=network.target

[Service]
Type=simple
ExecStart={command}
Restart=on-failure

[Install]
WantedBy=multi-user.target
"""
    path.write_text(unit)


def write_windows_task_template(path: Path, command: str) -> None:
    xml = f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <CalendarTrigger>
      <Repetition>
        <Interval>PT5M</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
      <StartBoundary>2024-01-01T00:00:00</StartBoundary>
      <Enabled>true</Enabled>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{command}</Command>
    </Exec>
  </Actions>
</Task>
"""
    path.write_text(xml)


def build_backend_config(path: Path) -> Path:
    print("Configuring Atlas Ops backend...")
    host = prompt("Bind host", "0.0.0.0")
    port = int(prompt("Port", "8000"))
    db_path = prompt("SQLite path", "atlas_ops.db")
    site_name = prompt("Default site name", "homelab")
    shared_token = prompt("Shared agent token (leave blank to auto-generate)", "")
    token_value = shared_token or secrets.token_hex(16)

    cfg = AppConfig(
        backend=BackendConfig(
            host=host,
            port=port,
            db_url=f"sqlite:///{Path(db_path).resolve()}",
            shared_token=token_value,
            load_demo=True,
        )
    )
    write_yaml(path, {"backend": cfg.backend.__dict__})
    bootstrap_database(cfg, default_site_name=site_name)
    write_systemd_template(
        Path("atlas-ops-backend.service"),
        description="Atlas Ops Backend",
        command=f"atlas-ops serve --config {path}",
    )
    print(f"Backend config written to {path} with token {token_value}")
    return path


def build_agent_config(path: Path) -> Path:
    print("Configuring Atlas Ops agent...")
    backend_url = prompt("Backend URL", "http://localhost:8000")
    site_id = prompt("Site ID", "site-homelab")
    token = prompt("Agent token (from backend config)", "")
    interval = int(prompt("Send interval seconds", "300"))
    docker_endpoint = prompt("Docker endpoint (leave blank to skip)", "")
    docker_hosts = [{"endpoint": docker_endpoint}] if docker_endpoint else []
    cfg = AgentFileConfig(
        agent=AgentConfig(
            backend_url=backend_url,
            site_id=site_id,
            token=token,
            interval_seconds=interval,
            docker_hosts=docker_hosts,
        )
    )
    write_yaml(path, {"agent": {**cfg.agent.__dict__, "docker_hosts": docker_hosts}})
    write_systemd_template(
        Path("atlas-ops-agent.service"),
        description="Atlas Ops Agent",
        command=f"atlas-ops agent run --config {path}",
    )
    write_windows_task_template(Path("atlas-ops-agent.xml"), command=f"atlas-ops agent run --config {path}")
    print(f"Agent config written to {path}")
    return path


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Atlas Ops installer")
    parser.add_argument("--mode", choices=["backend", "agent"], default="backend")
    parser.add_argument("--config", help="Output config path", default=None)
    args = parser.parse_args(argv)

    if args.mode == "backend":
        cfg_path = Path(args.config) if args.config else DEFAULT_BACKEND_CONFIG_PATH
        build_backend_config(cfg_path)
    else:
        cfg_path = Path(args.config) if args.config else DEFAULT_AGENT_CONFIG_PATH
        build_agent_config(cfg_path)
    print("Installer complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
