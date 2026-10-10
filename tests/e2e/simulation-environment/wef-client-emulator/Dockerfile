# Windows WEF client emulator. Build context: this directory.
#   docker build -t wef-client-emulator .
FROM python:3.11-slim AS builder
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libkrb5-dev \
    && rm -rf /var/lib/apt/lists/*
RUN pip wheel --no-cache-dir --wheel-dir /wheels "pyspnego[kerberos]" requests

FROM python:3.11-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends krb5-user libgssapi-krb5-2 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl && rm -rf /wheels
WORKDIR /app
COPY wefemu ./wefemu
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
