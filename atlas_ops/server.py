from __future__ import annotations

import argparse
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import List

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .config import AppConfig, BackendConfig, load_config
from .persistence import AgentToken, Database, Integration, Runbook, Signal, Site, bootstrap_database

logger = logging.getLogger("atlas_ops")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")


class RunbookOut(BaseModel):
    id: str
    title: str
    summary: str
    tags: List[str] | None
    steps: List[dict]
    prompt_template: str | None = None


class SiteOut(BaseModel):
    id: str
    name: str
    description: str | None
    networks: dict | None
    integrations: List[dict]


class IntegrationOut(BaseModel):
    id: int
    site_id: str
    type: str
    endpoint: str | None
    status: str | None
    name: str | None
    config: dict | None


class SignalIn(BaseModel):
    site_id: str
    kind: str
    summary: str
    detail: dict
    severity: str = "info"
    source: str = "agent"
    observed_at: datetime | None = None


class SignalOut(SignalIn):
    id: int


class SuggestionOut(BaseModel):
    summary: str
    reason: str
    related_runbook_ids: List[str]
    severity: str
    signal_id: int


def _match_runbooks(session, signal: Signal) -> List[str]:
    runbooks = session.query(Runbook).all()
    summary_lower = signal.summary.lower()
    detail_keys = " ".join(signal.detail.keys()).lower()
    matched: List[str] = []
    for rb in runbooks:
        tags = rb.tags or []
        if any(tag.lower() in summary_lower for tag in tags):
            matched.append(rb.id)
            continue
        if any(tag.lower() in detail_keys for tag in tags):
            matched.append(rb.id)
    return matched


def _suggestions(session) -> List[SuggestionOut]:
    signals = session.query(Signal).order_by(Signal.observed_at.desc()).limit(50).all()
    results: List[SuggestionOut] = []
    for sig in signals:
        runbook_ids = _match_runbooks(session, sig)
        if not runbook_ids:
            continue
        results.append(
            SuggestionOut(
                summary=f"Consider runbooks for {sig.summary}",
                reason=f"Recent signal from {sig.source} at {sig.observed_at.isoformat()}",
                related_runbook_ids=runbook_ids,
                severity=sig.severity,
                signal_id=sig.id,
            )
        )
    return results


def _validate_token(cfg: BackendConfig, session, provided: str | None) -> None:
    token = provided.split("Bearer ")[-1] if provided else None
    if cfg.shared_token and token == cfg.shared_token:
        return
    if token:
        if session.query(AgentToken).filter(AgentToken.token == token).first():
            return
    raise HTTPException(status_code=401, detail="Invalid or missing token")


def create_app(config: AppConfig | None = None) -> FastAPI:
    cfg = config or load_config()
    bootstrap_database(cfg)
    db = Database(cfg)

    app = FastAPI(title="Atlas Ops Copilot", version="0.4")
    allowed_origins = cfg.backend.allowed_origins or ["http://localhost", "http://localhost:8000"]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    def get_session():
        with db.session() as session:
            yield session

    @app.get("/api/health")
    def health(session=Depends(get_session)):
        session.execute("SELECT 1")
        return {"status": "ok"}

    @app.get("/api/sites", response_model=List[SiteOut])
    def list_sites(session=Depends(get_session)):
        sites = session.query(Site).all()
        return [
            SiteOut(
                id=s.id,
                name=s.name,
                description=s.description,
                networks=s.networks,
                integrations=[
                    {
                        "id": i.id,
                        "type": i.type,
                        "endpoint": i.endpoint,
                        "status": i.status,
                        "name": i.name,
                        "config": i.config,
                    }
                    for i in s.integrations
                ],
            )
            for s in sites
        ]

    @app.get("/api/integrations", response_model=List[IntegrationOut])
    def list_integrations(session=Depends(get_session)):
        integrations = session.query(Integration).all()
        return [
            IntegrationOut(
                id=integ.id,
                site_id=integ.site_id,
                type=integ.type,
                endpoint=integ.endpoint,
                status=integ.status,
                name=integ.name,
                config=integ.config,
            )
            for integ in integrations
        ]

    @app.get("/api/runbooks", response_model=List[RunbookOut])
    def list_runbooks(session=Depends(get_session)):
        runbooks = session.query(Runbook).all()
        return [
            RunbookOut(
                id=rb.id,
                title=rb.title,
                summary=rb.summary,
                tags=list(rb.tags or []),
                steps=list(rb.steps),
                prompt_template=rb.prompt_template,
            )
            for rb in runbooks
        ]

    @app.get("/api/runbooks/{runbook_id}", response_model=RunbookOut)
    def get_runbook(runbook_id: str, session=Depends(get_session)):
        rb = session.get(Runbook, runbook_id)
        if not rb:
            raise HTTPException(status_code=404, detail="Runbook not found")
        return RunbookOut(
            id=rb.id,
            title=rb.title,
            summary=rb.summary,
            tags=list(rb.tags or []),
            steps=list(rb.steps),
            prompt_template=rb.prompt_template,
        )

    @app.get("/api/signals", response_model=List[SignalOut])
    def list_signals(session=Depends(get_session)):
        signals = session.query(Signal).order_by(Signal.observed_at.desc()).limit(300).all()
        return [
            SignalOut(
                id=sig.id,
                site_id=sig.site_id,
                kind=sig.kind,
                summary=sig.summary,
                detail=sig.detail,
                severity=sig.severity,
                source=sig.source,
                observed_at=sig.observed_at,
            )
            for sig in signals
        ]

    @app.post("/api/signals", response_model=SignalOut, status_code=201)
    def ingest_signal(payload: SignalIn, authorization: str | None = Header(default=None), session=Depends(get_session)):
        _validate_token(cfg.backend, session, authorization)
        observed_at = payload.observed_at or datetime.utcnow()
        signal = Signal(
            site_id=payload.site_id,
            kind=payload.kind,
            summary=payload.summary,
            detail=payload.detail,
            severity=payload.severity,
            source=payload.source,
            observed_at=observed_at,
        )
        session.add(signal)
        session.flush()
        logger.info("Accepted signal %s for site %s", signal.id, signal.site_id)
        return SignalOut(
            id=signal.id,
            site_id=signal.site_id,
            kind=signal.kind,
            summary=signal.summary,
            detail=signal.detail,
            severity=signal.severity,
            source=signal.source,
            observed_at=signal.observed_at,
        )

    @app.get("/api/suggestions", response_model=List[SuggestionOut])
    def list_suggestions(session=Depends(get_session)):
        return _suggestions(session)

    @app.get("/api/llm/context_for_signal/{signal_id}")
    def llm_context(signal_id: int, session=Depends(get_session)):
        signal = session.get(Signal, signal_id)
        if not signal:
            raise HTTPException(status_code=404, detail="Signal not found")
        site = session.get(Site, signal.site_id)
        runbooks = [session.get(Runbook, rb_id) for rb_id in _match_runbooks(session, signal)]
        integrations = session.query(Integration).filter(Integration.site_id == signal.site_id).all()
        return {
            "signal": SignalOut(
                id=signal.id,
                site_id=signal.site_id,
                kind=signal.kind,
                summary=signal.summary,
                detail=signal.detail,
                severity=signal.severity,
                source=signal.source,
                observed_at=signal.observed_at,
            ).dict(),
            "site": {
                "id": site.id if site else None,
                "name": site.name if site else None,
                "networks": site.networks if site else None,
            },
            "integrations": [
                {
                    "id": integ.id,
                    "type": integ.type,
                    "endpoint": integ.endpoint,
                    "status": integ.status,
                    "name": integ.name,
                    "config": integ.config,
                }
                for integ in integrations
            ],
            "runbooks": [
                {
                    "id": rb.id,
                    "title": rb.title,
                    "summary": rb.summary,
                    "tags": rb.tags,
                    "steps": rb.steps,
                    "prompt_template": rb.prompt_template,
                }
                for rb in runbooks
                if rb
            ],
        }

    frontend_dir = Path(cfg.backend.frontend_dir or Path(__file__).parent / "frontend")
    if frontend_dir.exists():
        app.mount("/frontend", StaticFiles(directory=frontend_dir, html=True), name="frontend")

    return app


def main():
    import uvicorn

    parser = argparse.ArgumentParser(description="Run Atlas Ops backend")
    parser.add_argument("--config", help="Path to atlas_ops.config.yaml", default=None)
    args = parser.parse_args()

    config_path = args.config or os.getenv("ATLAS_OPS_CONFIG")
    cfg = load_config(Path(config_path)) if config_path else load_config()
    app = create_app(cfg)
    uvicorn.run(app, host=cfg.backend.host, port=cfg.backend.port)


if __name__ == "__main__":
    main()
