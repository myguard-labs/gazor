# gazor

[![CI](https://github.com/myguard-labs/gazor/actions/workflows/ci.yml/badge.svg)](https://github.com/myguard-labs/gazor/actions/workflows/ci.yml)
[![Release](https://github.com/myguard-labs/gazor/actions/workflows/release.yml/badge.svg)](https://github.com/myguard-labs/gazor/actions/workflows/release.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/myguard-labs/gazor.svg)](https://pkg.go.dev/github.com/myguard-labs/gazor)

> A fast, zero-dependency **Go [Razor 2](https://razor.sourceforge.net/) client**
> — `check` / `report` / `revoke` — for streaming pipelines, with zero on-disk
> message handling. Standard library only.

gazor speaks the Razor2 wire protocol — TCP, the SIS/batched-query format, server
discovery, and the Ephemeral/VR4 and Whiplash/VR8 signature engines —
**byte-for-byte compatibly with the reference `razor-agents` perl client**, so the
public Cloudmark catalogue servers accept its queries. The signatures are the part
that has to be exact; they are verified against real razor in CI.

Use it two ways:

- **As a Go library** — `import "github.com/myguard-labs/gazor/razor"` and call
  `Client.Check/Report/Revoke` in-process. This is how the
  [gozer](https://github.com/myguard-labs/gozer) backend uses it: linked directly,
  no subprocess, no socket.
- **As a CLI** — `gazor check|report|revoke` (message on stdin, never touches
  disk), plus a `gazor serve` HTTP sidecar.

## Quick start

```go
// library
import "github.com/myguard-labs/gazor/razor"

c := &razor.Client{}                 // discovers Cloudmark servers automatically
spam, err := c.Check(msg)            // bool: is this known spam?

c.Ident = &razor.Identity{User: u, Pass: p}
_ = c.Report(msg)                    // report as spam
_ = c.Revoke(msg)                    // retract a report

sigs := razor.Signatures(msg)        // offline: compute the digests, no network
```

```sh
# CLI — exit 0 = listed (spam), 1 = not listed
gazor check < message.eml
```

## The DRP family

Three pure-Go network clients, one orchestrator binary, one Docker deployment —
each wire-compatible with the original perl/python/C tool:

| Repo | Role |
|------|------|
| [gdcc](https://github.com/myguard-labs/gdcc) | DCC client — library + CLI |
| [gazor](https://github.com/myguard-labs/gazor) | Razor 2 client — library + CLI |
| [gyzor](https://github.com/myguard-labs/gyzor) | Pyzor client — library + CLI |
| [gozer](https://github.com/myguard-labs/gozer) | backend binary — links all three in-process behind one HTTP endpoint |
| [rspamd-dcc-razor-pyzor](https://github.com/eilandert/rspamd-dcc-razor-pyzor) | Docker deployment — gozer image + rspamd plugin + dovecot sieve |

The three clients share the same `Client` shape, CLI/env conventions and `serve`
API. Background: [why we rewrote them in Go](https://github.com/eilandert/rspamd-dcc-razor-pyzor#the-go-rewrite-gazor-gyzor-gdcc-gozer).

**Why Go?** The classic razor client is Perl and forks per message — an
interpreter start on every check inside a mail pipeline. gazor is one static
binary: no fork, the message stays in RAM, and every signature is parity-tested
against real razor.

## CLI

```sh
gazor check    < message.eml   # exit 0 = listed (spam), 1 = not listed
gazor report   < message.eml   # report as spam (needs identity)
gazor revoke   < message.eml   # retract a report (needs identity)
gazor register                 # new identity; prints GAZOR_USER=/GAZOR_PASS= AND saves it
gazor sig      < message.eml   # print the computed signatures (offline, debug)
gazor serve                    # HTTP sidecar: /check /report /revoke /metrics /healthz
```

Every option is settable by flag **or** environment variable (flag > env >
identity file > default):

| flag | env | meaning |
|------|-----|---------|
| `--server` | `GAZOR_SERVER` | explicit catalogue/nomination server (skips discovery) |
| `--discovery` | `GAZOR_DISCOVERY` | discovery server(s), comma-separated, tried in order (bypasses Razor2 DNS discovery) |
| `--port` | `GAZOR_PORT` | server port |
| `--timeout` | `GAZOR_TIMEOUT` | per-operation network budget |
| `--min-cf` | `GAZOR_MIN_CF` | min confidence (`ac`, `ac+N`, `ac-N`, or a number) |
| `--homedir` | `GAZOR_HOMEDIR` | Razor2 home for the `identity` file (default `~/.razor`, also honours `RAZOR_HOME`) |
| `--user` / `--pass` | `GAZOR_USER` / `GAZOR_PASS` (or `RAZOR_USER` / `RAZOR_PASS`) | report/revoke identity |
| `--verbose` | `GAZOR_VERBOSE` | per-operation logging (errors are logged either way) |
| `--listen` / `--unix` / `--token` | `GAZOR_LISTEN` / `GAZOR_UNIX` / `GAZOR_TOKEN` | `serve` HTTP listen address `host:port` (default loopback `127.0.0.1:8079`), optional Unix socket, shared secret (**required to bind a non-loopback address**) |
| `--max-concurrent` | `GAZOR_MAX_CONCURRENT` | `serve` max in-flight requests (default 8; over the limit → `503`) |
| `--log-stdout` | `GAZOR_LOG_STDOUT` | `serve` send info/access logs to stdout; **errors/warnings stay on stderr**. `/report`+`/revoke` access logged always, `/check` under `--verbose`. |

### Credentials

`check` works anonymously; `report`/`revoke` need an identity. Resolution order:
`--user`/`--pass` → `GAZOR_*`/`RAZOR_*` env → `<homedir>/identity` (Razor2
`key=value` file).

`gazor register` obtains a new identity from the nomination server and **saves it
and prints it**: on success it writes `<homedir>/identity` (0600) — never
clobbering an existing one (a re-registration lands in `<homedir>/identity-<user>`,
and `--out FILE` overrides the path) — and prints the identity as bare
`GAZOR_USER=`/`GAZOR_PASS=` lines for use via the environment instead
(`gazor register | grep '^GAZOR_' > gazor.env`). `--discovery`/`GAZOR_DISCOVERY`
takes a comma list of discovery servers tried in order, to bypass flaky
DNS discovery.

### serve mode

`gazor serve` runs a plain **HTTP/1.1** server. **Safe by default:** it binds
loopback (`127.0.0.1:8079`) and bounds in-flight requests (`--max-concurrent`,
default 8 → `503` over the limit). Exposing it on another address requires a
`--token` — it refuses a non-loopback bind without one. Set `--listen host:port`
/ `GAZOR_LISTEN` (and/or a Unix socket via `--unix`):

- `POST /check` → `{"action":"reject|accept","spam":bool}` (`reject` = listed spam, `accept` = clean)
- `POST /report` → `{"reported":true}`
- `POST /revoke` → `{"revoked":true}`
- `GET /metrics` → Prometheus exposition (request/verdict counters, latency histogram)
- `GET /healthz`

POST the raw RFC-822 message as the body (`--data-binary` keeps the bytes intact —
the signatures are computed over them):

```sh
gazor serve --listen :8079 --token s3cret &

# query — JSON verdict (drop the header if no --token was set)
curl -s --data-binary @message.eml \
  -H 'X-GAZOR-Token: s3cret' http://127.0.0.1:8079/check
# {"action":"accept","spam":false}

# report as spam / revoke — Bearer works too (report/revoke need an identity)
curl -s --data-binary @spam.eml -H 'Authorization: Bearer s3cret' http://127.0.0.1:8079/report
curl -s --data-binary @ham.eml  -H 'Authorization: Bearer s3cret' http://127.0.0.1:8079/revoke
curl -s http://127.0.0.1:8079/metrics      # no auth
```

A **fresh** `razor.Client` is built per request — Razor2 session state is
per-connection, so this avoids serialising every request behind one client's mutex
(the same way gozer uses the library). An optional `--token`/`GAZOR_TOKEN` requires
a `Bearer` or `X-GAZOR-Token` header on `/check`, `/report` and `/revoke`. Default
bind is loopback `127.0.0.1:8079` (gozer is `8077`, `gyzor serve` `8078`,
`gdcc serve` `8080`). Messages over 16 MiB are rejected (`413`), not silently
truncated.

## Correctness

The signatures are the make-or-break: a wrong signature means the server sees a
different fingerprint and the check/report is useless. The two engines, the
preprocessing chain (deBase64 → deQP → deHTML → deNewline, with a separate VR8
chain that keeps the raw URLs Whiplash needs), `prep_mail`/MIME splitting, the
SIS/batched-query codec and `hextobase64` are faithful ports of `Razor2::*`, gated
by **parity tests** against real razor:

- `razor/sig_test.go` — Ephemeral (drand48) + Whiplash signature engines over a vector set.
- `razor/protocol_test.go` — the full pipeline (raw email → preproc → VR4/VR8 wire signatures) plus `hextobase64`, over sample emails.
- `razor/units_test.go` — SIS, batched-query, HMAC auth and the `se` bitfield, pinned to golden vectors from `Razor2::String`.

Golden vectors live in `razor/testdata/*.tsv` and are committed (razor's Perl
modules are not apt-installable on current Debian); regenerate them with
`razor/testdata/gen_expected.pl` and `gen_protocol.pl`.

Beyond signature parity, the client is defensive on the wire
(`razor/audit_test.go`): reports are split into multiple chunks instead of being
truncated, report and revoke acknowledgements are checked, a response must arrive
within an absolute deadline and under a size cap and must match the number of
queries sent, a failed engine negotiation is a hard error rather than a silent
"not spam", a `Client` is mutex-serialised for concurrent use, and MIME parsing is
depth- and count-limited.

## Build / test

```sh
go build ./cmd/gazor
go test ./...                           # incl. razor signature/protocol parity + serve tests
go test -fuzz=FuzzSignatures ./razor    # MIME/preproc/engine fuzzing
```

## See also

- The rest of the family is in the table above.
- [The Go rewrite: gazor, gyzor, gdcc, gozer](https://github.com/eilandert/rspamd-dcc-razor-pyzor#the-go-rewrite-gazor-gyzor-gdcc-gozer) — why the perl/python/C clients were rewritten in Go
- Blog article: <https://deb.myguard.nl/2026/06/rspamd-dcc-razor-pyzor-docker-backend/>
- Docker Hub: <https://hub.docker.com/r/eilandert/rspamd-dcc-razor-pyzor>

## License

**GPLv3** — see [LICENSE](LICENSE). gazor is a Go port of the razor client
(itself GPL); as a derivative work it is released under the GPL. The signature and
protocol algorithms are verified for byte-for-byte parity against the reference
razor client in CI.
