FROM python:3.13-slim

LABEL org.opencontainers.image.source="https://github.com/branislav0/network-scanner" \
      org.opencontainers.image.description="Watch your home network for unknown devices" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    NETSCAN_HOME=/data \
    XDG_CACHE_HOME=/tmp/cache

# ARP needs raw sockets. Instead of running as root, give Python just the
# NET_RAW capability; the container then runs as an ordinary user.
RUN apt-get update \
 && apt-get install -y --no-install-recommends libcap2-bin \
 && setcap cap_net_raw+ep "$(readlink -f /usr/local/bin/python3)" \
 && apt-get purge -y libcap2-bin \
 && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md LICENSE /src/
COPY src /src/src
RUN pip install /src && rm -rf /src && mkdir /data && chown 1000:1000 /data

# devices.toml, the vendor list and the watch state live here
VOLUME /data
WORKDIR /data
USER 1000:1000

ENTRYPOINT ["netscan"]
CMD ["--watch", "300"]
