# syntax=docker/dockerfile:1
FROM blackarchlinux/blackarch

LABEL maintainer=Fantomas

COPY --from=ghcr.io/astral-sh/uv:0.12.5 /uv /uvx /usr/local/bin/

# lxml 5.x et pycurl ne compilent pas sur Python 3.14 + GCC 14 sans ce flag
ENV CFLAGS="-Wno-incompatible-pointer-types"
ENV UV_LINK_MODE=copy
ENV VIRTUAL_ENV=/venv
ENV PATH="/venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/playwright

# P1 : tous les packages système en un seul layer (reste en cache même si le venv ou le code changent)
RUN --mount=type=cache,target=/var/cache/pacman/pkg,sharing=locked \
    pacman -Syu --noconfirm --needed --disable-sandbox \
    python base-devel curl openssl ca-certificates traceroute whois \
    git unzip go \
    postgresql-libs libgit2 \
    python-lxml python-opencv python-numpy python-pillow python-legacy-cgi python-defusedxml \
    theharvester dirsearch dirb wafw00f \
    nikto perl-libwww perl-lwp-protocol-https perl-json perl-xml-writer \
    whatweb wpscan joomscan ruby \
    sslscan wfuzz dirbuster metagoofil tor proxychains-ng \
    gitleaks sqlmap sploitctl \
    metasploit nmap hydra \
    perl-image-exiftool \
    nss nspr alsa-lib at-spi2-core libxcomposite libxdamage \
    libxfixes libxrandr libdrm mesa pango cairo libxkbcommon && \
    gem install --no-user-install getoptlong && \
    sed -i '/resolv-replace/d' /usr/share/whatweb/Gemfile && \
    sed -i '/require.*resolv-replace/d' /usr/share/whatweb/lib/whatweb.rb && \
    grep -q "getoptlong" /usr/share/whatweb/Gemfile || echo "gem 'getoptlong'" >> /usr/share/whatweb/Gemfile && \
    cd /usr/share/whatweb && \
    rm -f Gemfile.lock && \
    bundle config set --local without 'mongo rchardet test development' && \
    bundle install --no-cache && \
    rm -rf /root/.gem/ /root/.bundle/cache/ /var/lib/pacman/sync/

# Binaires Go (curl disponible depuis blackarch)
RUN curl -fsSL -o /tmp/nuclei.zip https://github.com/projectdiscovery/nuclei/releases/download/v3.11.1/nuclei_3.11.1_linux_amd64.zip && \
    echo "ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6  /tmp/nuclei.zip" | sha256sum -c - && \
    unzip -o /tmp/nuclei.zip nuclei -d /usr/local/bin && \
    rm /tmp/nuclei.zip

RUN curl -fsSL -o /tmp/katana.zip https://github.com/projectdiscovery/katana/releases/download/v1.8.0/katana_1.8.0_linux_amd64.zip && \
    echo "cb027ae99d0757061b70c07a15c7a80f62c5a535ab52c4a329f80c4b0a7309d2  /tmp/katana.zip" | sha256sum -c - && \
    unzip -o /tmp/katana.zip katana -d /usr/local/bin && \
    rm /tmp/katana.zip

RUN curl -fsSL -o /tmp/trufflehog.tar.gz https://github.com/trufflesecurity/trufflehog/releases/download/v3.99.7/trufflehog_3.99.7_linux_amd64.tar.gz && \
    echo "bdbea0508e439b144f49de14e775908de5f902f3d14ea7ae8354bae72b0b72ef  /tmp/trufflehog.tar.gz" | sha256sum -c - && \
    tar -xzf /tmp/trufflehog.tar.gz -C /usr/local/bin trufflehog && \
    rm /tmp/trufflehog.tar.gz

RUN curl -fsSL -o /tmp/subfinder.zip \
      https://github.com/projectdiscovery/subfinder/releases/download/v2.17.0/subfinder_2.17.0_linux_amd64.zip && \
    echo "a39c3e5c7a26ef3c430915c4d6cbf7716a00f26769a75e9405aba796142eba37  /tmp/subfinder.zip" | sha256sum -c - && \
    unzip -o /tmp/subfinder.zip subfinder -d /usr/local/bin && \
    rm /tmp/subfinder.zip

RUN curl -fsSL -o /tmp/phoneinfoga.tar.gz \
      https://github.com/sundowndev/phoneinfoga/releases/download/v2.11.0/phoneinfoga_Linux_x86_64.tar.gz && \
    echo "6173dfc4ec009a6fe688068bac5a250646f5a8f56409098f5edcc7e404b12a52  /tmp/phoneinfoga.tar.gz" | sha256sum -c - && \
    tar -xzf /tmp/phoneinfoga.tar.gz -C /usr/local/bin phoneinfoga && \
    rm /tmp/phoneinfoga.tar.gz

RUN CGO_ENABLED=0 GOPATH=/tmp/go go install github.com/projectdiscovery/httpx/cmd/httpx@v1.6.10 && \
    cp /tmp/go/bin/httpx /usr/local/bin/ && \
    rm -rf /tmp/go

RUN git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/seclists && \
    rm -rf /usr/share/seclists/.git

# Environnement Python virtuel
RUN uv venv /venv

# pycurl (compilation C, layer séparé car lent)
RUN --mount=type=cache,target=/root/.cache/uv \
    uv pip install -p /venv pycurl

# Dépendances de base stables
RUN --mount=type=cache,target=/root/.cache/uv \
    uv pip install -p /venv \
    argparse netaddr mechanize psycopg2-binary "celery[redis]==5.6.3" sherlock-project holehe maigret pysaucenao

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

# blackarch-mcp + mcp
RUN --mount=type=cache,target=/root/.cache/uv \
    git clone --depth 1 https://github.com/L0ced/blackarch-mcp.git /opt/blackarch-mcp && \
    uv pip install -p /venv "mcp<2" && \
    rm -rf /opt/blackarch-mcp/.git

RUN --mount=type=cache,target=/root/.cache/uv \
    uv pip install -p /venv playwright

# Le binaire Go httpx écrase le script Python httpx présent dans /venv/bin
RUN cp /usr/local/bin/httpx /venv/bin/httpx

# P3 : installer les dépendances AVANT de copier le code source
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

# Patch metagoofil : incompatibilité avec googlesearch-python (ancienne API)
RUN python3 <<'PYEOF'
import re
with open('/usr/sbin/metagoofil') as f:
    s = f.read()
for kw in ('tbs', 'start', 'stop', 'user_agent'):
    s = re.sub(r',\s*' + kw + r'\s*=[^,)\n]+', '', s)
s = re.sub(r'\bpause=', 'sleep_interval=', s)
s = re.sub(r'\bnum=', 'num_results=', s)
s = s.replace('e.code', 'getattr(e, "code", None)')
with open('/usr/sbin/metagoofil', 'w') as f:
    f.write(s)
PYEOF

RUN { \
      printf 'round_robin\nchain_len = 1\nproxy_dns\nremote_dns_subnet 224\ntcp_read_time_out 15000\ntcp_connect_time_out 8000\n[ProxyList]\n'; \
      for port in 9050 9051 9052; do echo "socks5 127.0.0.1 $port"; done; \
    } > /etc/proxychains.conf

ARG PENTEST_UID=1000
ARG PENTEST_GID=1000
RUN groupadd -g ${PENTEST_GID} pentest && \
    useradd -u ${PENTEST_UID} -g ${PENTEST_GID} -M -s /usr/sbin/nologin pentest && \
    mkdir -p /opt/blackarch-mcp && \
    chown -R pentest:pentest /venv /src /opt/blackarch-mcp /opt/nuclei-templates /opt/playwright && \
    mkdir -p /reports /osint /usr/share/exploits /var/lib/blackarch-mcp && \
    chown pentest:pentest /reports /osint /usr/share/exploits /var/lib/blackarch-mcp

COPY --chown=pentest:pentest a2sv-overrides/ /src/a2sv/module/

COPY --chown=pentest:pentest scripts/db_insert.py scripts/ioc_extract.py osint.py /src/

COPY scripts/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

CMD ["/entrypoint.sh"]
