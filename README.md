# VPSentinel

A lightweight Linux/VPS security auditing tool. It reads a server's live state —
listening ports, SSH configuration, users and privileges, services — and reports
misconfigurations and exposure as ranked, actionable findings.

> **Status: early development (pre-alpha).** The architecture is in place; the
> first checks are being built. It is **not yet a working scanner** — see the
> [Roadmap](#roadmap). Interfaces and output may change without notice.

## What it is

A single static Go binary you drop onto a server and run. No agent, no runtime
dependencies, no database. It inspects the host through `/proc`, `/etc`, systemd
and standard tooling, then prints findings you can act on (with a machine-readable
mode for automation). The long-term goal is a full auditing, drift-detection and
incident-investigation platform for Linux servers.

## ⚠️ Authorisation and scope

- **Run it only on systems you own or are authorised to administer.** This is a
  security-auditing tool; running it against machines you do not control may be
  unlawful.
- **Scan output is sensitive.** A report is effectively a map of a host's
  weaknesses (exposed services, weak SSH, privilege paths). Keep it local. The
  repository's `.gitignore` deliberately excludes reports, baselines, integrity
  databases and evidence so they are never committed — do not override that.
- The tool reports "**no known issues found**", never "secure". Absence of
  findings is not proof of safety.

## Features

Planned for the first release (`v0.1`):

- [ ] Listening-port exposure (public vs loopback, sensitive services) — *in progress*
- [ ] SSH configuration and authorised-key audit
- [ ] Sudo / privilege and escalation-path checks
- [x] Structured findings model with severity ranking
- [ ] Pluggable check architecture (the `Check` interface + scan runner)
- [ ] Human-readable and JSON output

Later (see the roadmap): firewall, services, Docker, and web-stack
(Nginx/PHP/Laravel) checks; SARIF and HTML reports; and drift detection, file
integrity, attack-path analysis and incident investigation.

## Requirements

- Go 1.27 or newer (to build)
- Linux (the checks read Linux-specific interfaces such as `/proc`)

## Build

```bash
git clone git@github.com:devalinaqvi/vpsentinel.git
cd vpsentinel
go build -o vpsentinel ./cmd/vpsentinel
```

This produces a single `vpsentinel` binary (git-ignored) you can copy to any
Linux host of the same architecture.

## Usage

> The `scan` command is under construction. Today the binary only reports its
> version; the interface below is the target for `v0.1`.

```bash
# Audit the local host
vpsentinel scan

# Machine-readable output
vpsentinel scan --json

# Run with root for full coverage (see note below)
sudo vpsentinel scan
```

Run as **root** for complete results: some checks (e.g. mapping every listening
socket to its process) need privileges to read other users' state. Without root
the tool degrades gracefully — it reports what it can see and marks the rest as
unknown, rather than failing.

## Output

Every check emits **findings** with a stable rule ID, a severity
(`info` < `low` < `medium` < `high` < `critical`), the affected resource,
remediation advice, and supporting evidence. Findings are sorted worst-first.

Example (illustrative):

```
[HIGH]   Database exposed to the internet — tcp/0.0.0.0:3306 (mysqld)
         Fix: bind MySQL to 127.0.0.1, or block port 3306 at the firewall.
[MEDIUM] Public listener — tcp/0.0.0.0:6379 (redis-server)
         Fix: bind Redis to loopback; never expose it unauthenticated.
```

## Roadmap

**v0.1 — core scan:** listening ports, SSH audit, sudo/privilege checks; text and
JSON output.

**Later:** firewall/UFW, services, filesystem permissions, Docker, and
Nginx/PHP/Laravel checks; SARIF and HTML reports.

**Platform (long-term):** baseline + drift detection · file-integrity monitoring ·
attack-path analysis (internet → root) · incident investigation. A separate
multi-server dashboard is a possible future project.

## Development

```bash
go build ./...     # compile everything
go test ./...      # run tests
gofmt -w .         # format (required)
go vet ./...       # static checks
```

The codebase is a modular monolith: each check implements a common `Check`
interface and returns `Finding`s; the scanner collects them and renderers turn
them into output. Adding a check means adding one package — no changes to the
core or the renderers.

## License

Not yet chosen. Until a license is added, all rights are reserved.
