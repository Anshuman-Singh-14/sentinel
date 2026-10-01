#!/bin/sh
# Runs once, when the Postgres data volume is first initialised.
#
# Creates two roles so the application never connects as a superuser:
#   sentinel_owner  owns the schema, runs Alembic migrations
#   sentinel_app    runtime role for api/worker; gets DML only, no DDL
# Phase 2 narrows sentinel_app further on audit_events (INSERT, SELECT only).
#
# Passwords are passed as psql variables and quoted with :'var', so they are
# never spliced into SQL text (no injection via a crafted password).
set -eu

: "${SENTINEL_DB_OWNER_PASSWORD:?must be set}"
: "${SENTINEL_DB_APP_PASSWORD:?must be set}"

psql -v ON_ERROR_STOP=1 \
     --username "$POSTGRES_USER" \
     --dbname "$POSTGRES_DB" \
     -v db="$POSTGRES_DB" \
     -v owner_pw="$SENTINEL_DB_OWNER_PASSWORD" \
     -v app_pw="$SENTINEL_DB_APP_PASSWORD" <<'SQL'
CREATE ROLE sentinel_owner LOGIN PASSWORD :'owner_pw';
CREATE ROLE sentinel_app LOGIN PASSWORD :'app_pw';

-- Bound runaway queries from the app (CLAUDE.md rule 7).
ALTER ROLE sentinel_app SET statement_timeout = '30s';
ALTER ROLE sentinel_app SET idle_in_transaction_session_timeout = '60s';

ALTER DATABASE :"db" OWNER TO sentinel_owner;
REVOKE ALL ON DATABASE :"db" FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE :"db" TO sentinel_owner, sentinel_app;

ALTER SCHEMA public OWNER TO sentinel_owner;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO sentinel_app;

-- Tables created by migrations (as sentinel_owner) are usable by the app,
-- but the app cannot create, alter or drop anything itself.
ALTER DEFAULT PRIVILEGES FOR ROLE sentinel_owner IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO sentinel_app;
ALTER DEFAULT PRIVILEGES FOR ROLE sentinel_owner IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO sentinel_app;
SQL
