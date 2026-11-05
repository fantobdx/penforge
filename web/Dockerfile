FROM archlinux:latest

# uv remplace pip pour l'installation des dépendances Python (binaire officiel, pas de
# dépendance supplémentaire côté pacman).
COPY --from=ghcr.io/astral-sh/uv:0.12.5 /uv /uvx /usr/local/bin/

# gcc + postgresql-libs (pg_config/libpq) : Arch ship un Python trop récent pour que
# psycopg2-binary trouve une wheel manylinux précompilée ; uv retombe alors sur une
# compilation depuis les sources, qui a besoin de ces deux-là.
RUN pacman -Syu --noconfirm --needed --disable-sandbox python gcc postgresql-libs

WORKDIR /app

COPY web/requirements.txt .
RUN uv pip install --system --break-system-packages --no-cache -r requirements.txt

COPY scripts/db_insert.py scripts/ioc_extract.py pentest.py tasks.py /app/
COPY web/app.py /app/
COPY web/templates/ /app/templates/
COPY web/static/ /app/static/

EXPOSE 8080

CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--worker-class", "gthread", "--workers", "1", "--threads", "16", "--certfile", "/certs/cert.pem", "--keyfile", "/certs/key.pem", "app:app"]
