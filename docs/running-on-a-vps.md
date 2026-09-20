# Running VPSentinel on your VPS

VPSentinel is a single, dependency-free binary. You do **not** need Go, Docker, or
any runtime on the server — you download one file and run it.

> ⚠️ Run VPSentinel only on servers you own or are authorised to administer, and
> keep its reports private: a report describes your server's weaknesses.

## Requirements

- Linux, `x86_64` or `arm64`
- `sudo`/root recommended (for full process visibility)
- Nothing else — the binary is statically linked

## 1. Get the binary

Find your architecture first:

    uname -m        # x86_64 -> use amd64,  aarch64 -> use arm64

### Option A — download a prebuilt binary (recommended)

    VER=v0.1.0-alpha.1
    ARCH=amd64      # or arm64
    curl -fsSL -o vpsentinel \
      "https://github.com/devalinaqvi/vpsentinel/releases/download/${VER}/vpsentinel-linux-${ARCH}"
    chmod +x vpsentinel

Verify the download against the published checksums (recommended):

    curl -fsSL -O "https://github.com/devalinaqvi/vpsentinel/releases/download/${VER}/SHA256SUMS"
    sha256sum -c SHA256SUMS --ignore-missing

### Option B — build from source (needs Go 1.27+)

    git clone https://github.com/devalinaqvi/vpsentinel.git
    cd vpsentinel
    go build -o vpsentinel ./cmd/vpsentinel

## 2. Put it on the VPS

If you downloaded/built it elsewhere, copy it up:

    scp vpsentinel user@your-vps:/tmp/

Or run the Option A `curl` command directly on the VPS to fetch it there.

## 3. Run the scan

    sudo /tmp/vpsentinel scan            # human-readable report
    sudo /tmp/vpsentinel scan --json     # JSON, for automation

The scan is **read-only** — it inspects the system and changes nothing. Run it
with `sudo`/root for complete results: some checks need privileges to read other
users' state. Without root it still runs, but unreadable process names show as
`unknown`.

## 4. Read the output

Findings are ranked worst-first by severity:

    CRITICAL  >  HIGH  >  MEDIUM  >  LOW  >  NONE

Example:

    vpsentinel 0.1.0 — scan of web-01 — 2026-09-20T18:30:00Z

    [HIGH]   MySQL exposed on all interfaces — tcp/0.0.0.0:3306 (mysqld)
             fix: Bind MySQL to 127.0.0.1, or restrict port 3306 with a firewall rule.
    [MEDIUM] Service listening on all interfaces — tcp/0.0.0.0:80 (nginx)
             fix: If it's only needed locally, bind it to 127.0.0.1; otherwise ensure a firewall limits access.

    3 findings (1 high, 1 medium, 1 none)

Each finding says what is exposed and how to fix it. `NONE` entries (loopback-only
listeners) are informational — they're reachable only from the machine itself.

## 5. Save or move the report

    sudo /tmp/vpsentinel scan --json > vpsentinel-report.json

Keep this file private — it maps your server's exposure. Don't commit it or paste
it publicly.

## 6. Clean up

    rm -f /tmp/vpsentinel vpsentinel-report.json

## Notes

- VPSentinel currently exits `0` on a successful scan regardless of findings. A
  future release will add a `--fail-on <severity>` flag for CI/monitoring use.
- Prebuilt-binary downloads via `.../releases/latest/download/...` will work once
  a stable (non-pre-release) version is published; until then, use the specific
  release tag as shown above.
