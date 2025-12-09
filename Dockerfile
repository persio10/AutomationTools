FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    ATLAS_OPS_CONFIG=/data/atlas_ops.config.yaml \
    ATLAS_OPS_DB_URL=sqlite:////data/atlas_ops.db \
    ATLAS_OPS_HOST=0.0.0.0 \
    ATLAS_OPS_PORT=8000 \
    ATLAS_OPS_SHARED_TOKEN=changeme \
    ATLAS_OPS_LOAD_DEMO=true

WORKDIR /app
COPY atlas_ops/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY . ./
RUN pip install --no-cache-dir .

RUN mkdir -p /data
COPY atlas_ops/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 8000
VOLUME ["/data"]
ENTRYPOINT ["/entrypoint.sh"]
CMD ["atlas-ops", "serve", "--config", "/data/atlas_ops.config.yaml"]
