#!/bin/sh
# Runs once, when the Postgres data volume is first initialised (after 01-roles.sh).
#
# Creates `sentinel_test`, a separate database for the integration tests
# (`docker compose --profile test run --rm test`). It mirrors the main
# database's role setup, so tests exercise the real grants and triggers.
#
# Why a separate database: the audit tests deliberately tamper with
# audit_events (as the owner, with the trigger disabled) to prove the hash
# chain detects it. That must never touch the dev database's audit trail.
#
# For an existing volume, run it by hand once:
#   docker compose exec postgres sh /docker-entrypoint-initdb.d/02-test-db.sh
set -eu

DB=sentinel_test

exists=$(psql --username "$POSTGRES_USER" --dbname postgres -tAc \
    "SELECT 1 FROM pg_database WHERE datname = '$DB'")
if [ "$exists" = "1" ]; then
    echo "$DB already exists"
    exit 0
fi

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres -v db="$DB" <<'SQL'
CREATE DATABASE :"db" OWNER sentinel_owner;
REVOKE ALL ON DATABASE :"db" FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE :"db" TO sentinel_owner, sentinel_app;
SQL

# Default privileges are per database, so they are repeated here.
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$DB" <<'SQL'
ALTER SCHEMA public OWNER TO sentinel_owner;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO sentinel_app;
ALTER DEFAULT PRIVILEGES FOR ROLE sentinel_owner IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO sentinel_app;
ALTER DEFAULT PRIVILEGES FOR ROLE sentinel_owner IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO sentinel_app;
SQL
