# syntax=docker/dockerfile:1.7

ARG UBUNTU_VERSION=24.04
ARG ESBMC_VERSION=8.4
ARG ESBMC_SHA256=68bb71128e0c3c2db090955e7a302533a8a11a9d898df7f169c22311a0ec5078

FROM ubuntu:${UBUNTU_VERSION} AS esbmc-fetch
ARG ESBMC_VERSION
ARG ESBMC_SHA256
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates curl unzip \
    && rm -rf /var/lib/apt/lists/*
RUN curl --fail --location --retry 5 \
        "https://github.com/esbmc/esbmc/releases/download/v${ESBMC_VERSION}/esbmc-linux.zip" \
        --output /tmp/esbmc-linux.zip \
    && echo "${ESBMC_SHA256}  /tmp/esbmc-linux.zip" | sha256sum --check --strict \
    && mkdir -p /opt/esbmc \
    && unzip -q /tmp/esbmc-linux.zip -d /opt/esbmc \
    && chmod 0755 /opt/esbmc/bin/esbmc \
    && rm /tmp/esbmc-linux.zip

FROM ubuntu:${UBUNTU_VERSION} AS runtime
LABEL org.opencontainers.image.source="https://github.com/dusterbloom/lucebox-esbmc-ai"
LABEL org.opencontainers.image.licenses="AGPL-3.0-or-later"
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates git python3-minimal python3-venv \
    && rm -rf /var/lib/apt/lists/*
COPY --from=esbmc-fetch /opt/esbmc/bin/esbmc /usr/local/bin/esbmc
COPY --from=esbmc-fetch /opt/esbmc/license /usr/share/licenses/esbmc
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:${PATH}"
ENTRYPOINT ["lucebox-formal"]

FROM runtime AS verifier
COPY . /opt/lucebox-esbmc-ai-src
RUN /opt/venv/bin/pip install --no-cache-dir /opt/lucebox-esbmc-ai-src \
    && rm -rf /opt/lucebox-esbmc-ai-src

FROM runtime AS repair-dependencies
ARG ESBMC_AI_COMMIT=982f3ae0328e4b8906c3264b00e6541cd93356d8
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        g++ \
    && rm -rf /var/lib/apt/lists/* \
    && /opt/venv/bin/pip install --no-cache-dir \
        torch --index-url https://download.pytorch.org/whl/cpu \
    && /opt/venv/bin/pip install --no-cache-dir \
        "git+https://github.com/esbmc/esbmc-ai.git@${ESBMC_AI_COMMIT}"

FROM repair-dependencies AS repair
COPY . /opt/lucebox-esbmc-ai-src
RUN /opt/venv/bin/pip install --no-cache-dir /opt/lucebox-esbmc-ai-src \
    && rm -rf /opt/lucebox-esbmc-ai-src
