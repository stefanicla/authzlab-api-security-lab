# Development Toolchain Notes

This document records project requirements rather than details of an individual
developer's computer.

## Supported setup

- Linux, or Windows with WSL 2 and Ubuntu 24.04 or newer
- Python 3.14 managed by `uv`
- `make`
- Docker Engine with Docker Compose
- PostgreSQL 18 (the Compose setup provides the local database)

On WSL, keeping the checkout in the Linux home filesystem (for example,
`~/src/authzlab-api-security-lab`) avoids the performance overhead of working
through a Windows-mounted filesystem.

## Install and verify

From the repository root:

```bash
uv sync --all-extras --frozen
make lint
make typecheck
```

Start PostgreSQL with `make db-up`. Before running integration or security tests,
point `DATABASE_URL` at a disposable PostgreSQL database: those tests create and
drop tables. See [clean-setup verification](clean-setup-verification.md) for
the database and test setup.

Use the Makefile targets and the project `uv.lock` for reproducible local
commands. Do not commit local environment files, private keys, or machine-
specific paths.
