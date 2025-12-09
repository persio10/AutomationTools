from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

import yaml

DEFAULT_BACKEND_CONFIG_PATH = Path("atlas_ops.config.yaml")
DEFAULT_AGENT_CONFIG_PATH = Path("agent_config.yaml")


@dataclass
class BackendConfig:
    host: str = "0.0.0.0"
    port: int = 8000
    db_url: str = "sqlite:///atlas_ops.db"
    shared_token: str = ""
    load_demo: bool = True
    frontend_dir: Optional[str] = None
    allowed_origins: Optional[List[str]] = None


@dataclass
class AppConfig:
    backend: BackendConfig = field(default_factory=BackendConfig)


@dataclass
class DockerIntegrationConfig:
    endpoint: str = "unix:///var/run/docker.sock"
    restart_threshold: int = 3


@dataclass
class AgentConfig:
    backend_url: str = "http://localhost:8000"
    site_id: str = "site-homelab"
    token: str = ""
    interval_seconds: int = 300
    docker_hosts: List[DockerIntegrationConfig] = field(default_factory=list)
    state_path: Optional[str] = None


@dataclass
class AgentFileConfig:
    agent: AgentConfig = field(default_factory=AgentConfig)


ENV_OVERRIDES = {
    "host": "ATLAS_OPS_HOST",
    "port": "ATLAS_OPS_PORT",
    "db_url": "ATLAS_OPS_DB_URL",
    "shared_token": "ATLAS_OPS_SHARED_TOKEN",
    "frontend_dir": "ATLAS_OPS_FRONTEND_DIR",
    "allowed_origins": "ATLAS_OPS_ALLOWED_ORIGINS",
}


def _apply_backend_env(cfg: BackendConfig) -> BackendConfig:
    for field_name, env_name in ENV_OVERRIDES.items():
        if env_name not in os.environ:
            continue
        value = os.getenv(env_name)
        if field_name == "port":
            cfg.port = int(value) if value else cfg.port
        elif field_name == "allowed_origins" and value:
            cfg.allowed_origins = [item.strip() for item in value.split(",") if item.strip()]
        elif value:
            setattr(cfg, field_name, value)
    return cfg


def load_config(path: Path | None = None) -> AppConfig:
    cfg_path = path or DEFAULT_BACKEND_CONFIG_PATH
    if not cfg_path.exists():
        backend = BackendConfig()
        return AppConfig(backend=_apply_backend_env(backend))
    payload = yaml.safe_load(cfg_path.read_text()) or {}
    backend_payload = payload.get("backend", {})
    backend = BackendConfig(**backend_payload)
    backend = _apply_backend_env(backend)
    return AppConfig(backend=backend)


def load_agent_config(path: Path | None = None) -> AgentFileConfig:
    cfg_path = path or DEFAULT_AGENT_CONFIG_PATH
    payload = yaml.safe_load(cfg_path.read_text()) if cfg_path.exists() else {}
    agent_payload = payload.get("agent", {}) if payload else {}
    docker_payload = agent_payload.get("docker_hosts", []) or []
    docker_hosts = [DockerIntegrationConfig(**entry) for entry in docker_payload]
    agent_payload["docker_hosts"] = docker_hosts
    cfg = AgentConfig(**agent_payload)
    return AgentFileConfig(agent=cfg)


__all__ = [
    "AppConfig",
    "BackendConfig",
    "AgentConfig",
    "AgentFileConfig",
    "DockerIntegrationConfig",
    "load_config",
    "load_agent_config",
    "DEFAULT_BACKEND_CONFIG_PATH",
    "DEFAULT_AGENT_CONFIG_PATH",
]
