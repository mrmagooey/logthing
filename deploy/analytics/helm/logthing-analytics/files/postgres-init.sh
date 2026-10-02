#!/bin/bash
# Runs once, on first initialisation of the Postgres data directory.
set -euo pipefail
psql -v ON_ERROR_STOP=1 -v lk_pw="$LAKEKEEPER_DB_PASSWORD" -v hue_pw="$HUE_DB_PASSWORD" \
  -U "$POSTGRES_USER" -d postgres <<'SQL'
CREATE USER lakekeeper WITH PASSWORD :'lk_pw';
CREATE DATABASE lakekeeper OWNER lakekeeper;
CREATE USER hue WITH PASSWORD :'hue_pw';
CREATE DATABASE hue OWNER hue;
SQL
