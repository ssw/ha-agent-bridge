ARG BUILD_FROM
FROM ${BUILD_FROM}

ARG BUILD_ARCH
ARG CLOUDFLARED_VERSION

# cloudflared, pinned and checksum-verified.
COPY cloudflared.sha256 /tmp/cloudflared.sha256
RUN set -eu; \
    case "${BUILD_ARCH}" in \
      aarch64) asset=cloudflared-linux-arm64 ;; \
      amd64) asset=cloudflared-linux-amd64 ;; \
      *) echo "unsupported arch ${BUILD_ARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o "/tmp/${asset}" \
      "https://github.com/cloudflare/cloudflared/releases/download/${CLOUDFLARED_VERSION}/${asset}"; \
    (cd /tmp && grep " ${asset}\$" cloudflared.sha256 | sha256sum -c -); \
    install -m 0755 "/tmp/${asset}" /usr/local/bin/cloudflared; \
    rm -f "/tmp/${asset}" /tmp/cloudflared.sha256

COPY requirements.lock /app/requirements.lock
RUN pip install --no-cache-dir --require-hashes -r /app/requirements.lock

COPY src /app/src
COPY run.sh /run.sh
RUN chmod 0755 /run.sh

CMD ["/run.sh"]
