# syntax=docker/dockerfile:1
FROM python:3.13-alpine

COPY --from=ghcr.io/astral-sh/uv:0.12.5 /uv /uvx /usr/local/bin/

ENV UV_LINK_MODE=copy

RUN --mount=type=cache,target=/var/cache/apk,sharing=locked \
    apk add --update gcc musl-dev libffi-dev libgit2-dev

WORKDIR /app

COPY pyproject.toml /app/
RUN --mount=type=cache,target=/root/.cache/uv \
    mkdir -p /app/src/penforge && \
    touch /app/src/penforge/__init__.py && \
    uv pip install --system --break-system-packages -e /app
COPY src/ /app/src/

COPY web/static/ /app/src/penforge/web/static/

ARG PENTEST_UID=1000
ARG PENTEST_GID=1000
ARG DOCKER_GID=999
RUN addgroup -g ${PENTEST_GID} pentest && \
    adduser -u ${PENTEST_UID} -G pentest -D -h /home/pentest -s /sbin/nologin pentest && \
    addgroup -g ${DOCKER_GID} docker 2>/dev/null || true && \
    adduser pentest docker && \
    chown -R pentest:pentest /app /home/pentest
USER pentest

EXPOSE 8080

CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--worker-class", "gthread", "--workers", "1", "--threads", "16", "--certfile", "/certs/cert.pem", "--keyfile", "/certs/key.pem", "penforge.web.factory:create_app()"]
