# syntax=docker/dockerfile:1.7
FROM python:3.12-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/opt/aiops-auditor/src

RUN groupadd --gid 10002 auditor \
    && useradd --uid 10002 --gid auditor --shell /usr/sbin/nologin --create-home auditor

WORKDIR /opt/aiops-auditor
COPY --chown=auditor:auditor pyproject.toml requirements.txt ./
COPY --chown=auditor:auditor config ./config
COPY --chown=auditor:auditor src ./src

USER 10002:10002

ENTRYPOINT ["python", "-m", "aiops_auditor"]
CMD ["--help"]

