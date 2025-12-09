from __future__ import annotations

import argparse
import logging
from pathlib import Path

from . import install, server
from .agent.runner import loop, run_once
from .config import DEFAULT_AGENT_CONFIG_PATH, DEFAULT_BACKEND_CONFIG_PATH, load_agent_config, load_config
from .persistence import backup_database, bootstrap_database, run_migrations

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("atlas_ops.cli")


def cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="atlas-ops", description="Atlas Ops Copilot CLI")
    sub = parser.add_subparsers(dest="command")

    install_parser = sub.add_parser("install", help="Run guided installer")
    install_sub = install_parser.add_subparsers(dest="mode")
    install_backend = install_sub.add_parser("backend")
    install_backend.add_argument("--config", default=None, help="Config output path")
    install_agent = install_sub.add_parser("agent")
    install_agent.add_argument("--config", default=None, help="Agent config output path")

    serve_parser = sub.add_parser("serve", help="Run backend server")
    serve_parser.add_argument("--config", default=None, help="Path to backend config")

    agent_parser = sub.add_parser("agent", help="Agent operations")
    agent_sub = agent_parser.add_subparsers(dest="agent_cmd")
    agent_run = agent_sub.add_parser("run")
    agent_run.add_argument("--config", default=str(DEFAULT_AGENT_CONFIG_PATH), help="Agent config path")
    agent_run.add_argument("--once", action="store_true", help="Run once then exit")

    db_parser = sub.add_parser("db", help="Database utilities")
    db_sub = db_parser.add_subparsers(dest="db_cmd")
    db_init = db_sub.add_parser("init")
    db_init.add_argument("--config", default=None)
    db_migrate = db_sub.add_parser("migrate")
    db_migrate.add_argument("--config", default=None)
    db_backup = db_sub.add_parser("backup")
    db_backup.add_argument("--config", default=None)
    db_backup.add_argument("--to", required=True)

    demo_seed = sub.add_parser("demo", help="Demo helpers")
    demo_sub = demo_seed.add_subparsers(dest="demo_cmd")
    demo_seed_cmd = demo_sub.add_parser("seed")
    demo_seed_cmd.add_argument("--config", default=None)

    args = parser.parse_args(argv)

    if args.command == "install":
        cfg_path = Path(args.config) if args.config else None
        if args.mode == "backend":
            install.build_backend_config(cfg_path or DEFAULT_BACKEND_CONFIG_PATH)
        elif args.mode == "agent":
            install.build_agent_config(cfg_path or DEFAULT_AGENT_CONFIG_PATH)
        else:
            install.main([])
        return 0

    if args.command == "serve":
        cfg_path = Path(args.config) if args.config else None
        cfg = load_config(cfg_path)
        app = server.create_app(cfg)
        import uvicorn

        uvicorn.run(app, host=cfg.backend.host, port=cfg.backend.port)
        return 0

    if args.command == "agent":
        if args.agent_cmd == "run":
            config_path = Path(args.config)
            if args.once:
                run_once(config_path)
            else:
                loop(config_path)
        return 0

    if args.command == "db":
        cfg_path = Path(args.config) if args.config else None
        cfg = load_config(cfg_path)
        if args.db_cmd == "init":
            bootstrap_database(cfg)
        elif args.db_cmd == "migrate":
            run_migrations(cfg)
        elif args.db_cmd == "backup":
            backup_database(cfg, Path(args.to))
        return 0

    if args.command == "demo" and args.demo_cmd == "seed":
        cfg_path = Path(args.config) if args.config else None
        cfg = load_config(cfg_path)
        bootstrap_database(cfg)
        return 0

    parser.print_help()
    return 1


def main():
    raise SystemExit(cli())


if __name__ == "__main__":
    main()
