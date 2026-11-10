FROM python:3.13-slim

LABEL org.opencontainers.image.source="https://github.com/branislav0/network-scanner" \
      org.opencontainers.image.description="Watch your home network for unknown devices" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    NETSCAN_HOME=/data

COPY pyproject.toml README.md LICENSE /src/
COPY src /src/src
RUN pip install /src && rm -rf /src

# devices.toml, the vendor list and the watch state live here
VOLUME /data
WORKDIR /data

# Runs as root: sending raw ARP packets needs it (with the NET_RAW capability)
ENTRYPOINT ["netscan"]
CMD ["--watch", "300"]
