# VPSentinel v0.1 — Build Guide (you code it)

A step-by-step, Go-newcomer-friendly guide to building the first working slice of
VPSentinel: a `vpsentinel scan` binary with a shared findings/checks architecture
and a listening-ports module. Each step has a **concept**, the **code or hints**,
and a **checkpoint** you can run. Foundational/tricky files are given in full (so
you learn correct idioms); repetitive files are skeletons with TODOs for you.

Repo: `~/Development/project-ideas/vpsentinel` · module
`github.com/devalinaqvi/vpsentinel` · Go 1.27.1 (installed at `~/.local/go`).

---

## Step 0 — Get Go on your PATH

Go is installed but your interactive shell may not see it yet.

```bash
source ~/.zprofile          # or open a new terminal
go version                  # expect: go version go1.27.1 linux/amd64
```

If `go` still isn't found: `export PATH="$HOME/.local/go/bin:$HOME/go/bin:$PATH"`.
`~/go/bin` is where `go install` puts tools; worth having on PATH too.

**Go mental model vs PHP/Python:** compiled to one static binary; packages =
folders; every file starts `package <name>`; capitalized identifiers are exported
(public), lowercase are private; errors are returned values, not exceptions.

---

## Step 1 — Module + a hello scan

```bash
cd ~/Development/project-ideas/vpsentinel
go mod init github.com/devalinaqvi/vpsentinel
```

Create `cmd/vpsentinel/main.go`:

```go
package main

import "fmt"

const version = "0.1.0-dev"

func main() {
	fmt.Println("vpsentinel", version)
}
```

**Checkpoint:** `go run ./cmd/vpsentinel` prints `vpsentinel 0.1.0-dev`.
You now have the build/run loop. `go run` compiles+runs; `go build -o vpsentinel
./cmd/vpsentinel` produces the binary.

---

## Step 2 — The Finding model (the shared vocabulary)

**Concept:** every check, now and later, emits `Finding`s with a `Severity`. This
is the backbone of the whole tool, so get it right. You'll learn Go enums (`iota`)
and custom JSON marshalling.

Create `internal/finding/finding.go` (given in full):

```go
package finding

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Severity ranks findings. Order matters: Critical is highest, so plain
// comparison (a > b) and sorting work.
type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

var severityNames = map[Severity]string{
	Info: "info", Low: "low", Medium: "medium", High: "high", Critical: "critical",
}

func (s Severity) String() string {
	if n, ok := severityNames[s]; ok {
		return n
	}
	return "unknown"
}

// MarshalJSON makes JSON show "high" instead of 3.
func (s Severity) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

func (s *Severity) UnmarshalJSON(b []byte) error {
	var name string
	if err := json.Unmarshal(b, &name); err != nil {
		return err
	}
	for sev, n := range severityNames {
		if n == strings.ToLower(name) {
			*s = sev
			return nil
		}
	}
	return fmt.Errorf("unknown severity %q", name)
}

// Finding is one security observation. Keep it flat and serialisable.
type Finding struct {
	RuleID      string            `json:"rule_id"`
	Check       string            `json:"check"`
	Title       string            `json:"title"`
	Severity    Severity          `json:"severity"`
	Resource    string            `json:"resource,omitempty"`
	Description string            `json:"description,omitempty"`
	Remediation string            `json:"remediation,omitempty"`
	Confidence  string            `json:"confidence,omitempty"` // high|medium|low
	Evidence    map[string]string `json:"evidence,omitempty"`
}
```

**Checkpoint:** `go build ./...` compiles. (The `json:"...,omitempty"` tags are
struct tags — metadata read by the JSON encoder; `omitempty` drops empty fields.)

---

## Step 3 — The Check interface + scan orchestrator

**Concept:** an interface is a set of methods; any type with those methods
satisfies it automatically (no `implements` keyword). This is the seam that lets
SSH/sudo modules plug in later untouched.

`internal/checks/check.go`:

```go
package checks

import (
	"context"

	"github.com/devalinaqvi/vpsentinel/internal/finding"
)

type Check interface {
	ID() string   // stable slug, e.g. "ports"
	Name() string // human name
	Run(ctx context.Context) ([]finding.Finding, error)
}
```

`internal/scan/scan.go` (given in full — note graceful degradation: one check
failing doesn't abort the scan):

```go
package scan

import (
	"context"
	"os"
	"sort"
	"time"

	"github.com/devalinaqvi/vpsentinel/internal/checks"
	"github.com/devalinaqvi/vpsentinel/internal/finding"
)

type Meta struct {
	Tool     string    `json:"tool"`
	Version  string    `json:"version"`
	Hostname string    `json:"hostname"`
	Time     time.Time `json:"time"`
}

type CheckError struct {
	Check string `json:"check"`
	Error string `json:"error"`
}

type Result struct {
	Meta     Meta              `json:"meta"`
	Findings []finding.Finding `json:"findings"`
	Errors   []CheckError      `json:"errors,omitempty"`
}

func Run(ctx context.Context, version string, cs []checks.Check) Result {
	host, _ := os.Hostname()
	res := Result{Meta: Meta{
		Tool: "vpsentinel", Version: version, Hostname: host, Time: time.Now().UTC(),
	}}
	for _, c := range cs {
		fs, err := c.Run(ctx)
		if err != nil {
			res.Errors = append(res.Errors, CheckError{Check: c.ID(), Error: err.Error()})
			continue
		}
		res.Findings = append(res.Findings, fs...)
	}
	sort.SliceStable(res.Findings, func(i, j int) bool {
		return res.Findings[i].Severity > res.Findings[j].Severity
	})
	return res
}
```

**Checkpoint:** `go build ./...` still compiles (nothing calls `scan.Run` yet).

---

## Step 4 — The ports parser, test-first (the tricky core)

**Concept:** `/proc/net/tcp` encodes addresses as hex in a confusing byte order.
This is the most bug-prone code, so write it as **pure functions** and test them
with fixtures — no root, no real `/proc` needed. This teaches Go table tests.

`internal/checks/ports/parse.go` (given in full — study the byte-order comments):

```go
package ports

import (
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
)

type socket struct {
	Proto string
	IP    net.IP
	Port  int
	Inode string
}

func parseHexPort(s string) (int, error) {
	v, err := strconv.ParseUint(s, 16, 32)
	return int(v), err
}

// hexToIPv4: 8 hex chars, little-endian. "0100007F" -> 127.0.0.1
func hexToIPv4(s string) (net.IP, error) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 4 {
		return nil, fmt.Errorf("bad ipv4 hex %q", s)
	}
	return net.IPv4(b[3], b[2], b[1], b[0]), nil // reverse
}

// hexToIPv6: 32 hex chars = 16 bytes, but each 4-byte word is little-endian.
func hexToIPv6(s string) (net.IP, error) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 16 {
		return nil, fmt.Errorf("bad ipv6 hex %q", s)
	}
	ip := make(net.IP, 16)
	for w := 0; w < 4; w++ {
		ip[w*4+0] = b[w*4+3]
		ip[w*4+1] = b[w*4+2]
		ip[w*4+2] = b[w*4+1]
		ip[w*4+3] = b[w*4+0]
	}
	return ip, nil
}

// parseProcNet parses /proc/net/{tcp,tcp6,udp,udp6} contents.
// TCP: keep only LISTEN (state 0A). UDP: keep bound sockets (state 07).
func parseProcNet(proto string, data []byte) ([]socket, error) {
	var out []socket
	for i, line := range strings.Split(string(data), "\n") {
		if i == 0 { // header
			continue
		}
		f := strings.Fields(line)
		if len(f) < 10 {
			continue
		}
		local, state, inode := f[1], f[3], f[9]
		isTCP := strings.HasPrefix(proto, "tcp")
		if isTCP && state != "0A" {
			continue
		}
		if !isTCP && state != "07" {
			continue
		}
		hostPort := strings.SplitN(local, ":", 2)
		if len(hostPort) != 2 {
			continue
		}
		var ip net.IP
		var err error
		if strings.Contains(proto, "6") {
			ip, err = hexToIPv6(hostPort[0])
		} else {
			ip, err = hexToIPv4(hostPort[0])
		}
		if err != nil {
			continue
		}
		port, err := parseHexPort(hostPort[1])
		if err != nil {
			continue
		}
		out = append(out, socket{Proto: proto, IP: ip, Port: port, Inode: inode})
	}
	return out, nil
}
```

Now **you write** `internal/checks/ports/parse_test.go`. Skeleton to fill in:

```go
package ports

import "testing"

func TestHexToIPv4(t *testing.T) {
	cases := map[string]string{
		"0100007F": "127.0.0.1",
		"00000000": "0.0.0.0",
		// TODO add one for a real LAN IP, e.g. your machine's
	}
	for in, want := range cases {
		got, err := hexToIPv4(in)
		if err != nil || got.String() != want {
			t.Errorf("hexToIPv4(%q) = %v, %v; want %s", in, got, err, want)
		}
	}
}

// TODO: TestParseHexPort ("0035" -> 53, "1F90" -> 8080)
// TODO: TestParseProcNet — feed a fixture string of 2-3 lines incl. a header,
//       one 0.0.0.0:8080 LISTEN row, one 127.0.0.1 row; assert what comes back.
```

Get a real fixture line to model your test on:
```bash
head -3 /proc/net/tcp
```

**Checkpoint:** `go test ./internal/checks/ports/` passes. This is the moment the
hardest code is proven correct.

---

## Step 5 — Read /proc and map sockets to processes

**You write** `internal/checks/ports/proc.go`. Concept: walk `/proc/<pid>/fd/*`,
`readlink` each, and a link like `socket:[12345]` ties that inode to that PID.
Needs root for *other* users' sockets — so **skip unreadable dirs, don't fail**.

Hints (functions you'll use): `filepath.Glob(filepath.Join(procRoot, "[0-9]*"))`,
`os.ReadDir`, `os.Readlink`, `os.ReadFile(procRoot+"/<pid>/comm")`,
`strings.TrimPrefix/TrimSuffix`.

```go
package ports

// procInfo is who owns a socket inode.
type procInfo struct {
	PID  string
	Comm string
}

// buildInodeProcessMap returns inode -> process. Silently skips what it can't
// read (unprivileged runs see less; that's fine).
func buildInodeProcessMap(procRoot string) map[string]procInfo {
	m := map[string]procInfo{}
	// TODO: glob pids, for each read fd dir, readlink each fd,
	// if link has prefix "socket:[" extract the inode and record procInfo.
	return m
}
```

**Checkpoint:** a throwaway `main` or a test prints a non-empty map on your
machine (you'll see your own processes even without root).

---

## Step 6 — Classification + the Check impl (the security logic)

**You write** `internal/checks/ports/ports.go`. This is where bind-address risk
becomes findings. Structure given; fill the classify logic.

```go
package ports

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/devalinaqvi/vpsentinel/internal/finding"
)

var sensitivePorts = map[int]string{
	3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB",
	9200: "Elasticsearch", 11211: "memcached", 5672: "RabbitMQ",
}

type Check struct{ ProcRoot string }

func New() *Check { return &Check{ProcRoot: "/proc"} }

func (c *Check) ID() string   { return "ports" }
func (c *Check) Name() string { return "Listening ports" }

func (c *Check) Run(ctx context.Context) ([]finding.Finding, error) {
	procs := buildInodeProcessMap(c.ProcRoot)
	var findings []finding.Finding
	for _, proto := range []string{"tcp", "tcp6", "udp", "udp6"} {
		data, err := os.ReadFile(filepath.Join(c.ProcRoot, "net", proto))
		if err != nil {
			continue // some may be absent
		}
		socks, _ := parseProcNet(proto, data)
		for _, s := range socks {
			if f, ok := classify(s, procs[s.Inode]); ok {
				findings = append(findings, f)
			}
		}
	}
	return findings, nil
}

// classify turns a socket into a finding (or ok=false to ignore).
func classify(s socket, p procInfo) (finding.Finding, bool) {
	proc := p.Comm
	if proc == "" {
		proc = "unknown"
	}
	res := fmt.Sprintf("%s/%s:%d (%s)", s.Proto, s.IP, s.Port, proc)

	// TODO:
	// 1. loopback (s.IP.IsLoopback())      -> Info "listener on loopback" (or skip)
	// 2. unspecified (s.IP.IsUnspecified())-> Medium "public listener";
	//    if svc, ok := sensitivePorts[s.Port]; ok -> High, mention svc
	// 3. otherwise                         -> Low/Medium "non-loopback listener"
	// Build finding.Finding{RuleID: "ports/public-listener", Check: "ports",
	//   Title, Severity, Resource: res, Description, Remediation, Evidence{...}}
	_ = res
	return finding.Finding{}, false
}
```

**Checkpoint:** after Step 8 wires the CLI you'll see real findings; for now
`go build ./...` compiles.

---

## Step 7 — Renderers (text + JSON)

**You write** two small files. Concept: take `scan.Result`, write to an
`io.Writer`.

`internal/report/json.go`:
```go
package report

import (
	"encoding/json"
	"io"

	"github.com/devalinaqvi/vpsentinel/internal/scan"
)

func JSON(w io.Writer, r scan.Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
```

`internal/report/text.go` — TODO: print `Meta` header, then each finding as
`[SEVERITY] title — resource` with remediation indented; if
`len(r.Findings)==0` print **"no known issues found"** (never "secure"); list any
`r.Errors` at the end as "checks skipped". Useful funcs: `fmt.Fprintf(w, ...)`,
`strings.ToUpper(f.Severity.String())`.

**Checkpoint:** `go build ./...`.

---

## Step 8 — Wire the CLI

Replace `cmd/vpsentinel/main.go`. Concept: Go's stdlib `flag` package; subcommand
by looking at `os.Args[1]`.

```go
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/devalinaqvi/vpsentinel/internal/checks"
	"github.com/devalinaqvi/vpsentinel/internal/checks/ports"
	"github.com/devalinaqvi/vpsentinel/internal/report"
	"github.com/devalinaqvi/vpsentinel/internal/scan"
)

const version = "0.1.0-dev"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Println("vpsentinel", version)
		return
	}

	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "output JSON")
	procRoot := fs.String("proc", "/proc", "proc filesystem root (testing)")
	// os.Args[2:] because [1] is the subcommand ("scan")
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "scan" {
		args = args[1:]
	}
	_ = fs.Parse(args)

	cs := []checks.Check{&ports.Check{ProcRoot: *procRoot}}
	res := scan.Run(context.Background(), version, cs)

	var err error
	if *asJSON {
		err = report.JSON(os.Stdout, res)
	} else {
		err = report.Text(os.Stdout, res)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
```

---

## Step 9 — Verify end to end

```bash
cd ~/Development/project-ideas/vpsentinel
gofmt -w ./...            # format (Go is strict about this)
go vet ./...             # static checks
go test ./...            # your parser tests pass
go run ./cmd/vpsentinel scan
go run ./cmd/vpsentinel scan --json | python3 -m json.tool
```

**Cross-check correctness** against the kernel's own view:
```bash
ss -tulnp
```
Every `0.0.0.0`/`*` listener `ss` shows should appear as a public-listener
finding; loopback ones should be Info/skipped. If you run without root, some
process names will be `unknown` — expected.

Build the single binary and commit locally (no remote, nothing pushed):
```bash
go build -o vpsentinel ./cmd/vpsentinel
git init && git add -A && git commit -m "vpsentinel v0.1: scan core + ports module"
```

---

## Two rules to bake in from day one (from the spec's cautions)

- **Never print secret values**; report location/type only (matters once the
  secret-exposure check lands).
- **Scope/authorisation** belongs in the README: run only on hosts you own or
  administer; reports are a compromise map — keep them local, no upload features.

## What's next (same repo, later sessions)

SSH-audit module, then sudo/privilege module (finishing the spec's v0.1 trio) —
each is just another `checks.Check`. Then firewall/services, SARIF + HTML
renderers, the `SERVER-SETUP.md`-derived baseline, and the four subsystems
(drift, integrity, attack-path, incident). Ask me to expand any step, review your
code, or write the next module's guide.
