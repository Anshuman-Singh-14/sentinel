# Sentinel

A defensive security orchestration and education platform. Sentinel runs
diagnostics, audits, file-integrity checks and threat-intel lookups, then
translates raw output into plain-language findings with severity rationale and
remediation.

> Sentinel is for defensive and educational use only. Run active tools only
> against systems you own or have written permission to test.

**Status:** Phase 0 (foundation). See [`docs/PROGRESS.md`](docs/PROGRESS.md).

## Quick start

Requires Docker Desktop (or Docker Engine with Compose v2).

```bash
cp .env.example .env     # then replace every CHANGE_ME (see comments in the file)
docker compose up --build
```

- Frontend: http://localhost:5173
- API health: http://localhost:8000/health · readiness: http://localhost:8000/ready
- API docs (non-production only): http://localhost:8000/docs

## Development

```bash
docker compose run --rm api pytest                       # backend tests
docker compose run --rm api sh -c "ruff check . && mypy app tests && bandit -r app -ll -c pyproject.toml"
docker compose exec frontend npm run test                # frontend tests
docker compose exec frontend npm run lint
pre-commit install                                       # git hooks (needs frontend/node_modules: cd frontend && npm ci)
```

If frontend dependencies change, recreate the `node_modules` volume:
`docker compose down && docker volume rm sentinel_frontend_node_modules`.

## Documentation

- [`CLAUDE.md`](CLAUDE.md): engineering rules
- [`docs/spec/`](docs/spec): architecture, modules, logging/audit, security, phases
- [`docs/adr/`](docs/adr): architecture decision records
- [`docs/threat-model.md`](docs/threat-model.md)

## License

MIT. See [LICENSE](LICENSE).
