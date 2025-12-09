from __future__ import annotations

import json
import logging
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Iterable, List, Sequence

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text, create_engine, inspect, select, text
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker

from .config import AppConfig

logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
LATEST_SCHEMA_VERSION = 1


class Base(DeclarativeBase):
    pass


class SchemaVersion(Base):
    __tablename__ = "schema_version"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    version: Mapped[int] = mapped_column(Integer, default=LATEST_SCHEMA_VERSION)
    applied_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class Site(Base):
    __tablename__ = "sites"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    name: Mapped[str] = mapped_column(String)
    description: Mapped[str | None]
    networks: Mapped[dict | None] = mapped_column(JSON)

    integrations: Mapped[List["Integration"]] = relationship(back_populates="site", cascade="all, delete-orphan")
    signals: Mapped[List["Signal"]] = relationship(back_populates="site")


class Integration(Base):
    __tablename__ = "integrations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    site_id: Mapped[str] = mapped_column(ForeignKey("sites.id"))
    type: Mapped[str] = mapped_column(String)
    endpoint: Mapped[str | None]
    status: Mapped[str | None]
    name: Mapped[str | None] = mapped_column(String)
    config: Mapped[dict | None] = mapped_column(JSON)

    site: Mapped[Site] = relationship(back_populates="integrations")


class Runbook(Base):
    __tablename__ = "runbooks"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    title: Mapped[str] = mapped_column(String)
    summary: Mapped[str]
    tags: Mapped[Sequence[str] | None] = mapped_column(JSON)
    steps: Mapped[Sequence[dict]] = mapped_column(JSON)
    prompt_template: Mapped[str | None] = mapped_column(Text)


class Signal(Base):
    __tablename__ = "signals"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    source: Mapped[str] = mapped_column(String, default="agent")
    site_id: Mapped[str] = mapped_column(ForeignKey("sites.id"))
    kind: Mapped[str] = mapped_column(String)
    summary: Mapped[str]
    detail: Mapped[dict] = mapped_column(JSON)
    severity: Mapped[str] = mapped_column(String, default="info")
    observed_at: Mapped[datetime] = mapped_column(DateTime)

    site: Mapped[Site] = relationship(back_populates="signals")


class AgentToken(Base):
    __tablename__ = "agent_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    token: Mapped[str] = mapped_column(String, unique=True)
    site_id: Mapped[str | None]
    label: Mapped[str | None]


class Database:
    def __init__(self, config: AppConfig):
        self.engine = create_engine(config.backend.db_url, future=True)
        self.SessionLocal = sessionmaker(self.engine, expire_on_commit=False)

    @contextmanager
    def session(self) -> Iterable[Session]:
        session = self.SessionLocal()
        try:
            yield session
            session.commit()
        except Exception:  # pragma: no cover - simple helper
            session.rollback()
            raise
        finally:
            session.close()


def _current_version(engine) -> int:
    inspector = inspect(engine)
    if not inspector.has_table("schema_version"):
        return 0
    with engine.connect() as conn:
        row = conn.execute(text("SELECT version FROM schema_version ORDER BY id DESC LIMIT 1"))
        result = row.scalar()
        return int(result) if result is not None else 0


def _apply_migration_1(engine) -> None:
    # Ensure new tables exist
    Base.metadata.create_all(engine)
    inspector = inspect(engine)
    columns = {table: {col["name"] for col in inspector.get_columns(table)} for table in inspector.get_table_names()}

    if "runbooks" in columns and "prompt_template" not in columns["runbooks"]:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE runbooks ADD COLUMN prompt_template TEXT"))
    if "integrations" in columns:
        if "name" not in columns["integrations"]:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE integrations ADD COLUMN name VARCHAR"))
        if "config" not in columns["integrations"]:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE integrations ADD COLUMN config JSON"))
    if not inspector.has_table("agent_tokens"):
        AgentToken.__table__.create(engine)

    with engine.begin() as conn:
        conn.execute(text("INSERT INTO schema_version (version, applied_at) VALUES (:v, :ts)"), {"v": 1, "ts": datetime.utcnow()})


MIGRATIONS = {
    1: _apply_migration_1,
}


def run_migrations(config: AppConfig) -> None:
    engine = create_engine(config.backend.db_url, future=True)
    current = _current_version(engine)
    if current >= LATEST_SCHEMA_VERSION:
        return
    for version in range(current + 1, LATEST_SCHEMA_VERSION + 1):
        logger.info("Applying migration %s", version)
        MIGRATIONS[version](engine)
    logger.info("Database migrated to version %s", LATEST_SCHEMA_VERSION)


def bootstrap_database(config: AppConfig, default_site_name: str = "homelab") -> None:
    run_migrations(config)
    db = Database(config)
    Base.metadata.create_all(db.engine)
    with db.session() as session:
        has_sites = session.scalar(select(Site)) is not None
        if not has_sites and config.backend.load_demo:
            _seed_demo(session, default_site_name)
    logger.info("Database ready at %s", config.backend.db_url)


def _load_json(name: str) -> list | dict:
    path = DATA_DIR / name
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _seed_demo(session: Session, default_site_name: str) -> None:
    sites_payload = _load_json("sites.json")
    runbooks_payload = _load_json("runbooks.json")
    signals_payload = _load_json("signals.json")

    if not sites_payload:
        sites_payload = [
            {
                "id": "site-homelab",
                "name": default_site_name,
                "description": "Default site",
                "networks": {"lan": {"cidr": "192.168.1.0/24", "gateway": "192.168.1.1"}},
                "integrations": [
                    {"type": "docker", "endpoint": "unix:///var/run/docker.sock", "status": "configured", "name": "docker-local"}
                ],
            }
        ]
    for site in sites_payload:
        integrations_payload = site.pop("integrations", [])
        s = Site(**site)
        session.add(s)
        for integ in integrations_payload:
            session.add(Integration(site=s, **integ))

    for rb in runbooks_payload:
        session.add(Runbook(**rb))

    for sig in signals_payload:
        observed = sig.get("observed_at")
        observed_dt = datetime.fromisoformat(observed.replace("Z", "+00:00")) if isinstance(observed, str) else datetime.utcnow()
        session.add(
            Signal(
                source=sig.get("source", "agent"),
                site_id=sig.get("site_id", "site-homelab"),
                kind=sig.get("kind", "unknown"),
                summary=sig.get("summary", ""),
                detail=sig.get("detail", {}),
                severity=sig.get("severity", "info"),
                observed_at=observed_dt,
            )
        )
    session.commit()
    logger.info("Seeded demo data: %s sites, %s runbooks, %s signals", len(sites_payload), len(runbooks_payload), len(signals_payload))


def backup_database(config: AppConfig, dest: Path) -> Path:
    db_path = config.backend.db_url.replace("sqlite:///", "")
    source = Path(db_path)
    dest = dest.expanduser().resolve()
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(source.read_bytes())
    logger.info("Database backup written to %s", dest)
    return dest


__all__ = [
    "Database",
    "Site",
    "Integration",
    "Runbook",
    "Signal",
    "AgentToken",
    "SchemaVersion",
    "bootstrap_database",
    "backup_database",
    "run_migrations",
    "LATEST_SCHEMA_VERSION",
]
