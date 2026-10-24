# Security policy

COptimizer runs as Administrator and deletes files, so security problems are taken seriously.

## Reporting a vulnerability

Please don't open a public issue. Use GitHub's private vulnerability reporting instead: the repository's **Security** tab → **Report a vulnerability**. Include the version or commit, what you did, and what happened.

## What counts

Especially:

- anything that lets a web page, another user or another program make the server delete or change something outside its rules;
- ways around the safety rules in [docs/plan.md](docs/plan.md) (section 5);
- anything that lets a test touch files outside its own sandbox ([docs/testing.md](docs/testing.md)).

## Supported versions

Until version 1.0, only the latest release and the `master` branch get fixes.
