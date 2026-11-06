FROM parrotsec/core:latest

MAINTAINER Vishnu Nair

# uv remplace pip pour toutes les installations Python de ce Dockerfile (binaire officiel,
# pas de dépendance supplémentaire côté apt).
COPY --from=ghcr.io/astral-sh/uv:0.12.5 /uv /uvx /usr/local/bin/

RUN rm -f /etc/apt/sources.list.d/*;\
    echo "deb https://parrot.mirror.garr.it/parrot echo main contrib non-free non-free-firmware" > /etc/apt/sources.list;\
    apt-get -o Acquire::Retries=5 update && apt-get -o Acquire::Retries=5 -qq -y install wget python3 python3-dev

RUN echo > /etc/apt/sources.list;\
    echo "deb https://parrot.mirror.garr.it/parrot echo main contrib non-free non-free-firmware" > /etc/apt/sources.list.d/parrot.list;\
    echo "deb-src https://parrot.mirror.garr.it/parrot echo main contrib non-free non-free-firmware" > /etc/apt/sources.list.d/parrot1.list;\
    wget -qO - https://archive.parrotsec.org/parrot/misc/parrotsec.gpg | apt-key add -;\
    apt-get update;\
    apt-get -y --no-install-recommends install -y traceroute dirbuster dirb nikto websploit libwww-perl wfuzz whois metagoofil theharvester wafw00f wpscan sslscan whatweb joomscan seclists git apt-transport-https dirmngr gnupg apt-utils ca-certificates curl build-essential libpq-dev python3-pkg-resources python3-setuptools openssl python-is-python3 libjson-perl libxml-writer-perl tor proxychains4 && echo "resolvconf resolvconf/linkify-resolvconf boolean false" | debconf-set-selections;

RUN sed -i 's/^socks4.*/socks5 127.0.0.1 9050/' /etc/proxychains4.conf

RUN mkdir -p /src

WORKDIR /src

# wfuzz dépend du pycurl fourni par apt, lié à GnuTLS : "Pycurl is not compiled
# against Openssl. Wfuzz might not work correctly when fuzzing SSL sites."
# Le wheel manylinux de PyPI embarque son propre libcurl lié à OpenSSL, donc on
# le réinstalle par-dessus sans dépendance supplémentaire.
RUN uv pip install --system --break-system-packages --no-cache --reinstall-package pycurl pycurl

RUN uv pip install --system --break-system-packages --no-cache argparse netaddr mechanize psycopg2-binary;\
    git clone https://github.com/hahwul/a2sv.git &&\
    find /src/a2sv -name '*.py' -exec sed -i 's/\t/    /g;s/^\( *\)print \(.*\)$/\1print(\2)/;s/iteritems()/items()/g;s/urllib2/urllib.request/g;s/from urlparse import/from urllib.parse import/;s/^import Queue$/import queue as Queue/;s/xrange(/range(/g;s/\.encode(.hex.)/.hex()/g;s/ord(recv\[0\])/recv[0]/g;s/ord(strLastMessage\[-7\])/strLastMessage[-7]/g' {} + &&\
    git clone https://github.com/CyberPrince-hub/XSSZypheron.git /src/XSSZypheron &&\
    git -C /src/XSSZypheron checkout ba4fec89cf9aa133eccb0bf08f0c241e23eb9e5a &&\
    uv pip install --system --break-system-packages --no-cache -r /src/XSSZypheron/requirements.txt &&\
    git clone https://github.com/s0md3v/XSStrike.git && uv pip install --system --break-system-packages --no-cache -r /src/XSStrike/requirements.txt;\
    uv pip install --system --break-system-packages --no-cache setuptools droopescan "cement<3" wapiti3 "sslyze>=6,<7" "cryptography>=43,<47" "zombie-imp" stamina

COPY a2sv-overrides/ /src/a2sv/module/

COPY pentest.py db_insert.py /src/

ENTRYPOINT ["tail", "-f", "/dev/null"]
