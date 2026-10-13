#!/bin/bash
# Create the isolated lab database on first init (M-6).
# Runs only when the postgres volume is created; use
# `docker compose --profile secure --profile lab down -v` to re-init it.
set -e
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    SELECT 'CREATE DATABASE authzlab_lab' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'authzlab_lab')\gexec
EOSQL
