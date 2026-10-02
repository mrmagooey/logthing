#!/bin/bash
# Runs once, on first initialisation of the Postgres data directory.
set -euo pipefail
psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d postgres <<SQL
CREATE USER lakekeeper WITH PASSWORD '${LAKEKEEPER_DB_PASSWORD}';
CREATE DATABASE lakekeeper OWNER lakekeeper;
CREATE USER hue WITH PASSWORD '${HUE_DB_PASSWORD}';
CREATE DATABASE hue OWNER hue;
SQL
