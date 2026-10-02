# Sentinel

A defensive security orchestration and education platform. Sentinel runs
diagnostics, audits, file-integrity checks and threat-intel lookups, then
translates raw output into plain-language findings with severity rationale and
remediation.

> Sentinel is for defensive and educational use only. Run active tools only
> against systems you own or have written permission to test.

**Status:** Phase 2 (identity, RBAC & audit trail). See [`docs/PROGRESS.md`](docs/PROGRESS.md).

## Quick start

Requires Docker Desktop (or Docker Engine with Compose v2).

```bash
cp .env.example .env     # then replace every CHANGE_ME (see comments in the file)
docker compose up --build
```

- Frontend: http://localhost:5173
- API health: http://localhost:8000/health · readiness: http://localhost:8000/ready
- API docs (non-production only): http://localhost:8000/docs
- Tool catalogue: http://localhost:8000/api/v1/tools

`docker compose up` runs database migrations first (the one-shot `migrate`
service), then starts the API and worker.

Create the first administrator (there is no default account or password):

```bash
docker compose exec api python -m app.cli create-admin --username admin
```

Then log in with `POST /api/v1/auth/login`. The web login page arrives in Phase 3.

## Development

```bash
docker compose run --rm api pytest                       # backend unit tests (integration tests skip)
docker compose --profile test run --rm test              # unit + integration tests (real Postgres/Redis)
docker compose run --rm api sh -c "ruff check . && mypy app tests alembic && bandit -r app -ll -c pyproject.toml"
docker compose run --rm migrate alembic upgrade head     # apply migrations manually
docker compose exec frontend npm run test                # frontend tests
docker compose exec frontend npm run lint
pre-commit install                                       # git hooks (needs frontend/node_modules: cd frontend && npm ci)
```

The integration tests use a separate `sentinel_test` database, created when the
Postgres volume is first initialised. For an older volume, create it once with
`docker compose exec postgres sh /docker-entrypoint-initdb.d/02-test-db.sh`.

If frontend dependencies change, recreate the `node_modules` volume:
`docker compose down && docker volume rm sentinel_frontend_node_modules`.

## Documentation

- [`CLAUDE.md`](CLAUDE.md): engineering rules
- [`docs/spec/`](docs/spec): architecture, modules, logging/audit, security, phases
- [`docs/adr/`](docs/adr): architecture decision records
- [`docs/threat-model.md`](docs/threat-model.md)

## License

MIT. See [LICENSE](LICENSE).
