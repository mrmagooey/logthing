FROM python:3.11-slim

WORKDIR /app

# Install dependencies for pyarrow
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip install --no-cache-dir \
    boto3 \
    pandas \
    pyarrow \
    pyyaml \
    requests

# Copy entrypoint script
COPY parsing-validator/entrypoint.py ./entrypoint.py

ENTRYPOINT ["python", "entrypoint.py"]
