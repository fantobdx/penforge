FROM python:3.13-slim

COPY --from=ghcr.io/astral-sh/uv:0.12.5 /uv /uvx /usr/local/bin/

WORKDIR /app

COPY pyproject.toml /app/
COPY src/ /app/src/
RUN uv pip install --system --break-system-packages --no-cache -e /app

# Shims de compatibilité (pentest_mcp.py importe db_insert, pentest, tasks sans prefixe)
COPY scripts/db_insert.py scripts/ioc_extract.py pentest.py tasks.py pentest_mcp.py /app/

ARG PENTEST_UID=1000
ARG PENTEST_GID=1000
RUN groupadd -g ${PENTEST_GID} pentest && \
    useradd -u ${PENTEST_UID} -g ${PENTEST_GID} -M -s /sbin/nologin pentest && \
    chown -R pentest:pentest /app
USER pentest

EXPOSE 8766

CMD ["python", "pentest_mcp.py"]
