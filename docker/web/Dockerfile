FROM archlinux:latest

COPY --from=ghcr.io/astral-sh/uv:0.12.5 /uv /uvx /usr/local/bin/

RUN pacman -Syu --noconfirm --needed --disable-sandbox python gcc postgresql-libs

WORKDIR /app

COPY pyproject.toml /app/
COPY src/ /app/src/
RUN uv pip install --system --break-system-packages --no-cache -e /app

COPY web/static/ /app/static/

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
