# Changelog

All notable changes to VPSentinel are documented in this file.
This project follows [Semantic Versioning](https://semver.org).

## [v0.1.0-alpha.1] — 2026-09-20

First working scan of VPSentinel. This is an early pre-release (alpha): the
foundation and the first check are in place, but it is not the v0.1.0 release
yet — that will add the SSH and sudo/privilege checks.

### What it does
`vpsentinel scan` inspects the local host's listening sockets and reports
network exposure, ranked worst-first, as readable text or JSON.

- Distinguishes listeners on all interfaces (0.0.0.0 / ::) from loopback.
- Flags sensitive services (MySQL, PostgreSQL, Redis, MongoDB, Elasticsearch,
  memcached, RabbitMQ) exposed on all interfaces as high severity.
- Maps sockets to the owning process where possible.
- Every finding carries remediation, a confidence level, and evidence.

### Usage
Requires Go 1.27+ and Linux.

    git clone git@github.com:devalinaqvi/vpsentinel.git
    cd vpsentinel
    go build -o vpsentinel ./cmd/vpsentinel
    ./vpsentinel scan            # human-readable
    ./vpsentinel scan --json     # machine-readable
    sudo ./vpsentinel scan       # full process names

### Known limitations
- Only the listening-ports check exists so far.
- Process names for other users' sockets need root; otherwise shown as "unknown".
- Multicast/link-local addresses are reported at low severity.

### Authorisation
Run only on systems you own or administer. Scan output maps a host's
weaknesses — keep it local.

### Next
Toward v0.1.0: SSH configuration audit and sudo/privilege checks.
