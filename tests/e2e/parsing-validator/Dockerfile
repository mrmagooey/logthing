FROM python:3.11-slim

WORKDIR /app

# Install dependencies for pyarrow
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip install --no-cache-dir \
    boto3 \
    pyarrow \
    pyyaml \
    requests

# Copy entrypoint script
COPY parsing-validator/entrypoint.py ./entrypoint.py
COPY config/event_parsers ./parsers

ENTRYPOINT ["python", "entrypoint.py"]
