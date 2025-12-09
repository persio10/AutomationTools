from pathlib import Path

from fastapi.testclient import TestClient

from atlas_ops.config import AppConfig, BackendConfig
from atlas_ops.persistence import AgentToken, Database, bootstrap_database
from atlas_ops.server import create_app


def build_app(tmp_path: Path):
    cfg = AppConfig(backend=BackendConfig(db_url=f"sqlite:///{tmp_path/'atlas.db'}", shared_token="testtoken", load_demo=True))
    bootstrap_database(cfg)
    return create_app(cfg)


def test_health_and_runbooks(tmp_path):
    app = build_app(tmp_path)
    client = TestClient(app)

    resp = client.get("/api/health")
    assert resp.json()["status"] == "ok"

    runbooks = client.get("/api/runbooks").json()
    assert any(rb["id"] for rb in runbooks)


def test_ingest_signal_and_suggestions(tmp_path):
    app = build_app(tmp_path)
    client = TestClient(app)

    before = client.get("/api/signals").json()
    created = client.post(
        "/api/signals",
        headers={"Authorization": "Bearer testtoken"},
        json={
            "site_id": "site-homelab",
            "kind": "integration",
            "summary": "Proxmox quorum unstable",
            "detail": {"service": "proxmox", "severity": "warning"},
        },
    ).json()
    assert created["id"]
    after = client.get("/api/signals").json()
    assert len(after) == len(before) + 1

    suggestions = client.get("/api/suggestions").json()
    assert any("proxmox" in s.get("summary", "").lower() for s in suggestions)


def test_auth_token_table(tmp_path):
    cfg = AppConfig(backend=BackendConfig(db_url=f"sqlite:///{tmp_path/'atlas.db'}", shared_token="", load_demo=True))
    bootstrap_database(cfg)
    db = Database(cfg)
    with db.session() as session:
        session.add(AgentToken(token="tab-token", site_id="site-homelab", label="test"))
    app = create_app(cfg)
    client = TestClient(app)

    resp = client.post(
        "/api/signals",
        headers={"Authorization": "Bearer tab-token"},
        json={"site_id": "site-homelab", "kind": "ping", "summary": "ok", "detail": {}},
    )
    assert resp.status_code == 201


def test_llm_context(tmp_path):
    app = build_app(tmp_path)
    client = TestClient(app)
    sig = client.post(
        "/api/signals",
        headers={"Authorization": "Bearer testtoken"},
        json={"site_id": "site-homelab", "kind": "docker", "summary": "container down", "detail": {"container": "app"}},
    ).json()
    ctx = client.get(f"/api/llm/context_for_signal/{sig['id']}").json()
    assert ctx["signal"]["id"] == sig["id"]
    assert "runbooks" in ctx
    assert any("docker" in (rb.get("tags") or []) for rb in ctx["runbooks"])
