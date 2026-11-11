# syntax=docker/dockerfile:1
FROM archlinux:latest

LABEL maintainer=Fantomas

COPY --from=ghcr.io/astral-sh/uv:0.12.5 /uv /uvx /usr/local/bin/

# lxml 5.x et pycurl ne compilent pas sur Python 3.14 + GCC 14 sans ce flag
ENV CFLAGS="-Wno-incompatible-pointer-types"
ENV UV_LINK_MODE=copy
ENV VIRTUAL_ENV=/venv
ENV PATH="/venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/playwright

# Bootstrap : paru-bin (makepkg interdit en root → user aurbuild permanent)
RUN --mount=type=cache,target=/var/cache/pacman/pkg,sharing=locked \
    grep -q 'DisableSandbox' /etc/pacman.conf || sed -i '/^\[options\]/a DisableSandbox' /etc/pacman.conf && \
    echo "OPTIONS=(!debug !strip)" >> /etc/makepkg.conf && \
    pacman -Syu --noconfirm --needed --disable-sandbox base-devel git && \
    useradd -r -m aurbuild && \
    echo 'aurbuild ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers && \
    su - aurbuild -c 'git clone https://aur.archlinux.org/paru-bin.git ~/paru-bin && cd ~/paru-bin && makepkg -si --noconfirm' && \
    rm -rf /home/aurbuild/paru-bin

# P1 : tous les packages via paru (dépôts officiels + AUR en un seul appel)
RUN --mount=type=cache,target=/var/cache/pacman/pkg,sharing=locked \
    su - aurbuild -c 'paru -S --noconfirm --skipreview --noprovides --needed --mflags "--nocheck" \
      python curl openssl ca-certificates traceroute whois unzip go \
      postgresql-libs libgit2 libssh libpcap libxslt \
      python-lxml python-opencv python-numpy python-pillow python-legacy-cgi python-defusedxml \
      perl-libwww perl-lwp-protocol-https perl-json perl-xml-writer \
      ruby ruby-bundler \
      tor proxychains-ng \
      gitleaks nmap hydra sqlmap python-netaddr python-psycopg2 \
      perl-image-exiftool \
      nss nspr alsa-lib at-spi2-core libxcomposite libxdamage \
      libxfixes libxrandr libdrm mesa pango cairo libxkbcommon \
      dirb ffuf sslscan nuclei-bin katana-bin trufflehog-bin phoneinfoga-bin subfinder-bin \
      wafw00f whatweb wpscan joomscan sherlock-git holehe-git maigret' && \
    rm -rf /home/aurbuild/.cache/paru && \
    rm -rf /var/lib/pacman/sync/

# WhatWeb + gems + nikto + joomscan (opérations root → chemins fixes, non packagés)
RUN git clone --depth 1 https://github.com/sullo/nikto /opt/nikto && \
    rm -rf /opt/nikto/.git && \
    chmod +x /opt/nikto/program/nikto.pl && \
    ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto

# Metasploit (dépôt extra Arch)
RUN --mount=type=cache,target=/var/cache/pacman/pkg,sharing=locked \
    pacman -Sy --noconfirm --needed metasploit

RUN CGO_ENABLED=0 GOPATH=/tmp/go go install github.com/projectdiscovery/httpx/cmd/httpx@v1.6.10 && \
    cp /tmp/go/bin/httpx /usr/local/bin/ && \
    rm -rf /tmp/go

RUN curl -sL "https://github.com/sundowndev/phoneinfoga/releases/download/v2.11.0/phoneinfoga_Linux_x86_64.tar.gz" \
    | tar -xz -C /usr/local/bin phoneinfoga && \
    chmod +x /usr/local/bin/phoneinfoga

# Environnement Python virtuel
RUN uv venv /venv

# pycurl (compilation C, layer séparé car lent)
RUN --mount=type=cache,target=/root/.cache/uv \
    uv pip install -p /venv pycurl

# Dépendances stables
RUN --mount=type=cache,target=/root/.cache/uv \
    uv pip install -p /venv \
    mechanize psycopg2-binary "celery[redis]==5.6.3" pysaucenao \
    dirsearch

# theHarvester (requirements/base.txt supprimé → package flit installable)
RUN --mount=type=cache,target=/root/.cache/uv \
    git clone --depth 1 https://github.com/laramies/theHarvester.git /src/theHarvester && \
    uv pip install -p /venv /src/theHarvester && \
    rm -rf /src/theHarvester/.git

# metagoofil (script direct, pas de package installable)
RUN --mount=type=cache,target=/root/.cache/uv \
    git clone --depth 1 https://github.com/opsdisk/metagoofil.git /src/metagoofil && \
    [ -f /src/metagoofil/requirements.txt ] && uv pip install -p /venv -r /src/metagoofil/requirements.txt || true && \
    chmod +x /src/metagoofil/metagoofil.py && \
    ln -sf /src/metagoofil/metagoofil.py /usr/local/bin/metagoofil && \
    rm -rf /src/metagoofil/.git

# a2sv (clone + patch Python 2→3)
RUN git clone --depth 1 https://github.com/hahwul/a2sv.git /src/a2sv && \
    find /src/a2sv -name '*.py' -exec sh -c 'for f; do expand -t 8 "$f" > "$f.tmp" && mv "$f.tmp" "$f"; done' sh {} + && \
    find /src/a2sv -name '*.py' -exec sed -i 's/^\( *\)print \(.*\)$/\1print(\2)/;s/iteritems()/items()/g;s/urllib2/urllib.request/g;s/from urlparse import/from urllib.parse import/;s/^import Queue$/import queue as Queue/;s/xrange(/range(/g;s/\.encode(.hex.)/.hex()/g;s/ord(recv\[0\])/recv[0]/g;s/ord(strLastMessage\[-7\])/strLastMessage[-7]/g;s/\.communicate()\[0\]/.communicate()[0].decode(errors="replace")/g' {} + && \
    rm -rf /src/a2sv/.git

# XSSZypheron (commit fixé → blobless clone)
RUN --mount=type=cache,target=/root/.cache/uv \
    git clone --filter=blob:none https://github.com/CyberPrince-hub/XSSZypheron.git /src/XSSZypheron && \
    git -C /src/XSSZypheron checkout ba4fec89cf9aa133eccb0bf08f0c241e23eb9e5a && \
    uv pip install -p /venv -r /src/XSSZypheron/requirements.txt && \
    rm -rf /src/XSSZypheron/.git

# XSStrike
RUN --mount=type=cache,target=/root/.cache/uv \
    git clone --depth 1 https://github.com/s0md3v/XSStrike.git /src/XSStrike && \
    uv pip install -p /venv -r /src/XSStrike/requirements.txt && \
    rm -rf /src/XSStrike/.git

# Packages principaux
RUN --mount=type=cache,target=/root/.cache/uv \
    uv pip install -p /venv \
    "setuptools==81.0.0" droopescan "cement<3" wapiti3 defusedxml defusedcsv requests-ntlm requests-toolbelt \
    "sslyze>=6,<7" "cryptography>=43,<47" "zombie-imp" stamina git-dumper PicImageSearch pillow \
    googlesearch-python playwright-stealth ddddocr chardet legacy-cgi

# mcp
RUN --mount=type=cache,target=/root/.cache/uv \
    uv pip install -p /venv "mcp<2"

RUN --mount=type=cache,target=/root/.cache/uv \
    uv pip install -p /venv playwright

# Le binaire Go httpx écrase le script Python httpx présent dans /venv/bin
RUN cp /usr/local/bin/httpx /venv/bin/httpx

# Dépendances penforge avant le code source
# → tout changement dans src/ n'invalide pas le layer uv pip install
COPY pyproject.toml /src/penforge/
RUN mkdir -p /src/penforge/src/penforge && \
    touch /src/penforge/src/penforge/__init__.py && \
    uv pip install --no-cache -p /venv -e /src/penforge
COPY src/ /src/penforge/src/

# nuclei templates
RUN nuclei -ut -ud /opt/nuclei-templates

# playwright chromium
RUN /venv/bin/playwright install chromium && \
    rm -rf /root/.cache/


RUN { \
      printf 'round_robin\nchain_len = 1\nproxy_dns\nremote_dns_subnet 224\ntcp_read_time_out 15000\ntcp_connect_time_out 8000\n[ProxyList]\n'; \
      for port in 9050 9051 9052; do echo "socks5 127.0.0.1 $port"; done; \
    } > /etc/proxychains.conf

ARG PENTEST_UID=1000
ARG PENTEST_GID=1000
RUN groupadd -g ${PENTEST_GID} pentest && \
    useradd -u ${PENTEST_UID} -g ${PENTEST_GID} -M -s /usr/sbin/nologin pentest && \
    chown -R pentest:pentest /venv /src /opt/nuclei-templates /opt/playwright && \
    mkdir -p /reports /osint && \
    chown pentest:pentest /reports /osint

COPY --chown=pentest:pentest a2sv-overrides/ /src/a2sv/module/

COPY --chown=pentest:pentest scripts/db_insert.py scripts/ioc_extract.py osint.py /src/

COPY scripts/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

CMD ["/entrypoint.sh"]
