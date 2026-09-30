# Iceberg descriptor committer for logthing.
#
# Build context is committer/ (not the repo root) -- this image has nothing
# to do with the Rust binary or its Dockerfiles. See committer/README.md for
# what this does and its required environment variables.
FROM python:3.12-slim

LABEL org.opencontainers.image.title="logthing-committer" \
      org.opencontainers.image.description="Drains logthing's Iceberg descriptor queue into an Iceberg REST catalog via add_files" \
      org.opencontainers.image.source="https://github.com/mrmagooey/logthing"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY commit.py .

# Non-root: this container only ever talks to S3 and an Iceberg REST catalog
# over the network, no reason to run as root.
RUN useradd --system --no-create-home --uid 10001 committer
USER committer

ENTRYPOINT ["python", "/app/commit.py"]
