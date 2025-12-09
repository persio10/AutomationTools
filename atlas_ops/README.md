# Atlas Ops Copilot (0.4)

A local-first, discovery-driven runbook copilot for homelab and small IT teams. Atlas Ops fuses lightweight discovery, agent signals, guided runbooks, and suggestions into a daily “situation board” that you can self-host or run via Docker Compose.

## 0.3 production-minded critique
- Install/upgrade was dev-centric (`python -m` everywhere, manual JSON). No clear Docker path or Windows agent guidance.
- Security was thin (single token, no rotation guidance, permissive CORS) and HTTPS/TLS expectations were implicit.
- Real-world usefulness hinged on demo data; there was no concrete integration producing actionable signals.
- AI readiness was minimal (runbooks lacked LLM hints and no context endpoint). Backups/migrations were not explicit.

## What’s new in 0.4
- **Single CLI**: `atlas-ops` with `install`, `serve`, `agent run`, `db migrate|backup`, and `demo seed`. `python -m` still works but docs prefer the CLI.
- **Docker-first**: Dockerfile + Docker Compose with `/data` volume, env-driven config, and automatic init/seed on first run. `.env.example` included.
- **Config + DB**: YAML config, env overrides, SQLite + migrations, backup helper, and seedable demo data.
- **Security**: Shared token validation plus DB-backed agent tokens, CORS tightening, HTTPS/reverse-proxy guidance, and token rotation notes.
- **Windows-friendly agent**: Portable agent config paths, Task Scheduler XML template, and platform-neutral gateway/ping probes.
- **Real integration (Docker)**: Agent can watch Docker hosts, emit `container_down` and `container_restart_count_high` signals, and align with Docker runbooks.
- **LLM hook**: `/api/llm/context_for_signal/{id}` returns signal + site + integrations + matching runbooks with `prompt_template` hints.

---

## Quick start (Docker Compose)
```bash
git clone <repo>
cd AutomationTools
cp .env.example .env  # edit token/port as needed
docker compose up --build -d
# Open http://localhost:8000/frontend/index.html
```
- Config and DB live in the `/data` volume. The container entrypoint writes `/data/atlas_ops.config.yaml` if missing, runs migrations, then serves.
- Rotate the shared token by updating `.env` (and agent configs) and recreating the container.

## Quick start (CLI on Linux)
```bash
python -m pip install -r atlas_ops/requirements.txt
python -m pip install .  # installs the atlas-ops CLI
atlas-ops install backend --config atlas_ops.config.yaml
atlas-ops serve --config atlas_ops.config.yaml
# browse http://localhost:8000/frontend/index.html
```

## Linux agent setup
```bash
atlas-ops install agent --config agent_config.yaml
atlas-ops agent run --config agent_config.yaml --once  # test
atlas-ops agent run --config agent_config.yaml         # loop (use systemd or supervisor)
```
- Systemd unit template: `atlas-ops-agent.service` (created by the installer). Place in `/etc/systemd/system/` and enable.
- Agent config supports Docker polling:
```yaml
agent:
  backend_url: http://atlas-backend:8000
  site_id: site-homelab
  token: YOUR_SHARED_TOKEN
  interval_seconds: 300
  docker_hosts:
    - endpoint: unix:///var/run/docker.sock
      restart_threshold: 3
```

## Windows agent setup
- Install Python 3.10+ (`py -m pip install --upgrade pip`), then install Atlas Ops: `py -m pip install -r atlas_ops/requirements.txt` followed by `py -m pip install .`.
- Generate config: `atlas-ops install agent --config %PROGRAMDATA%\AtlasOps\agent_config.yaml`
- Run once to verify: `atlas-ops agent run --config %PROGRAMDATA%\AtlasOps\agent_config.yaml --once`
- Schedule via Task Scheduler using the provided `atlas-ops-agent.xml` (import and point to the CLI). Logs are written to stdout; capture via Task Scheduler history or wrap with `>> C:\ProgramData\AtlasOps\agent.log`.

## Security & TLS
- Agent ingestion requires `Authorization: Bearer <token>`. Tokens can be rotated by updating config/DB and agent configs. You can pre-create additional tokens in the `agent_tokens` table.
- Recommended reverse proxy (NGINX example):
```nginx
server {
  listen 443 ssl;
  server_name atlas.example.com;
  ssl_certificate /etc/letsencrypt/live/atlas/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/atlas/privkey.pem;
  location / {
    proxy_pass http://127.0.0.1:8000;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto https;
  }
}
```
- Restrict `/api/signals` to internal networks/VPN when possible. Default CORS allows localhost origins; set `ATLAS_OPS_ALLOWED_ORIGINS` to tighten.

## Docker integration example
- Add a Docker host to the agent config (see above). The agent emits signals like:
```json
{
  "site_id": "site-homelab",
  "kind": "container_down",
  "summary": "Docker container stopped: myapp",
  "detail": {"container": "myapp", "endpoint": "unix:///var/run/docker.sock", "status": "exited"},
  "severity": "warning"
}
```
- Runbooks `rb-docker-container-down` and `rb-docker-restart-count` match those signals and appear as suggestions in the dashboard.

## LLM integration hook
- `GET /api/llm/context_for_signal/{id}` returns: the signal, its site, integrations for that site, and runbooks (with `prompt_template`) that match the signal tags. Use this to feed an external LLM service or chat bot.

## Database, backup, and migration
- Schema managed via lightweight migrations. Run `atlas-ops db migrate --config atlas_ops.config.yaml` during upgrades.
- Backup SQLite by copying the DB: `atlas-ops db backup --config atlas_ops.config.yaml --to backups/atlas_ops.db` (stop the service first for clean copies, or use SQLite online backup tooling).

## Commands
- `atlas-ops install backend|agent [--config path]`
- `atlas-ops serve [--config path]`
- `atlas-ops agent run --config path [--once]`
- `atlas-ops db init|migrate|backup --config path`
- `atlas-ops demo seed [--config path]`

## Frontend highlights
- Filters by site, severity, and time window; shared search across signals/runbooks.
- Inline suggestions on each signal plus runbook hit counts.
- Per-site cards showing integrations, IDs, and networks.
- Ready to live behind a reverse proxy at `/frontend/index.html`.
