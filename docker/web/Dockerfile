# syntax=docker/dockerfile:1
FROM archlinux:latest

COPY --from=ghcr.io/astral-sh/uv:0.12.5 /uv /uvx /usr/local/bin/

ENV UV_LINK_MODE=copy

RUN --mount=type=cache,target=/var/cache/pacman/pkg,sharing=locked \
    pacman -Syu --noconfirm --needed --disable-sandbox python gcc postgresql-libs && \
    rm -rf /var/lib/pacman/sync/

WORKDIR /app

# P3 : installer les dépendances AVANT de copier le code source
# → tout changement dans src/ n'invalide pas le layer uv pip install
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
RUN groupadd -g ${PENTEST_GID} pentest && \
    useradd -u ${PENTEST_UID} -g ${PENTEST_GID} -m -d /home/pentest -s /usr/sbin/nologin pentest && \
    groupadd -g ${DOCKER_GID} docker 2>/dev/null || \
        groupmod -g ${DOCKER_GID} docker 2>/dev/null || true && \
    usermod -aG docker pentest && \
    chown -R pentest:pentest /app /home/pentest
USER pentest

EXPOSE 8080

CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--worker-class", "gthread", "--workers", "1", "--threads", "16", "--certfile", "/certs/cert.pem", "--keyfile", "/certs/key.pem", "penforge.web.factory:create_app()"]
