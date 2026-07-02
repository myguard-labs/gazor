// Command gazor is a Go reimplementation of the razor (Razor2) client
// (check / report / revoke). The core lives in package razor, which the gozer
// backend links in-process behind one HTTP endpoint for rspamd; this command is
// the standalone CLI front-end.
//
// CLI usage (message on stdin, never touches disk):
//
//	gazor check    < message.eml   # exit 0 = listed (spam), 1 = not listed
//	gazor report   < message.eml   # report as spam (needs identity)
//	gazor revoke   < message.eml   # retract a report (needs identity)
//	gazor register                 # obtain a new identity; prints it as
//	                               # GAZOR_USER=/GAZOR_PASS= env lines AND saves
//	                               # it to <homedir>/identity (or --out FILE)
//	gazor sig      < message.eml   # print computed signatures (offline, debug)
//	gazor serve                    # HTTP sidecar: /check /report /revoke /metrics /healthz
//
// Every option is settable by flag OR environment variable (flag > env >
// identity file > default): --server/GAZOR_SERVER, --discovery/GAZOR_DISCOVERY
// (comma list, tried in order), --port/GAZOR_PORT, --timeout/GAZOR_TIMEOUT,
// --min-cf/GAZOR_MIN_CF, --homedir/GAZOR_HOMEDIR, --user/--pass (GAZOR_USER/
// GAZOR_PASS, or RAZOR_USER/RAZOR_PASS), --verbose/GAZOR_VERBOSE, and the
// serve-mode --listen/GAZOR_LISTEN, --unix/GAZOR_UNIX, --token/GAZOR_TOKEN.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/myguard-labs/gazor/razor"
)

var version = "dev"

const repoURL = "https://github.com/myguard-labs/gazor"

// maxStdin bounds the message read from stdin so the CLI cannot be made to
// buffer unbounded input (razor messages are small; prep_part caps parts).
const maxStdin = 16 << 20 // 16 MiB

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gazor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	server := fs.String("server", os.Getenv("GAZOR_SERVER"), "explicit catalogue/nomination server (skips discovery)")
	discovery := fs.String("discovery", envStr("GAZOR_DISCOVERY", razor.DefaultDiscovery), "discovery server(s), comma-separated; tried in order")
	port := fs.Int("port", envIntDefault("GAZOR_PORT", razor.DefaultPort), "server port")
	timeout := fs.Duration("timeout", envDur("GAZOR_TIMEOUT", 15*time.Second), "network timeout")
	minCf := fs.String("min-cf", envStr("GAZOR_MIN_CF", "ac"), "min confidence: ac, ac+N, ac-N, or a number")
	homedir := fs.String("homedir", os.Getenv("GAZOR_HOMEDIR"), "Razor2 home dir for the identity file (default ~/.razor, also honours RAZOR_HOME)")
	user := fs.String("user", "", "identity user (report/revoke; default GAZOR_USER/RAZOR_USER or identity file)")
	pass := fs.String("pass", "", "identity pass (report/revoke; default GAZOR_PASS/RAZOR_PASS or identity file)")
	verbose := fs.Bool("verbose", envBool("GAZOR_VERBOSE"), "log per-operation detail (errors are logged regardless)")
	listen := fs.String("listen", envStr("GAZOR_LISTEN", "127.0.0.1:8079"), "serve: HTTP listen address host:port — serves /check,/report,/revoke,/metrics,/healthz (default loopback 127.0.0.1:8079; '' disables TCP)")
	unixSock := fs.String("unix", os.Getenv("GAZOR_UNIX"), "serve: also serve the HTTP API on this Unix socket path (optional)")
	token := fs.String("token", os.Getenv("GAZOR_TOKEN"), "serve: shared-secret token; required to bind a non-loopback address")
	maxConc := fs.Int("max-concurrent", envIntDefault("GAZOR_MAX_CONCURRENT", runtime.NumCPU()), "serve: max in-flight requests, default = CPU count (over the limit -> 503)")
	logStdout := fs.Bool("log-stdout", envBool("GAZOR_LOG_STDOUT"), "serve: send info/access logs to stdout; errors stay on stderr")
	out := fs.String("out", "", "register: write the new identity (user=/pass=, 0600) to this file (default <homedir>/identity if absent)")
	showVer := fs.Bool("version", false, "print version and exit")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVer {
		fmt.Fprintln(stdout, "gazor", version)
		return 0
	}
	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Fprintln(stderr, "usage: gazor [flags] check|report|revoke|register|sig|serve")
		return 2
	}
	op := rest[0]
	// Allow flags after the subcommand too (gazor serve --listen ...), not just
	// before it — Go's flag package otherwise stops at the first positional.
	if err := fs.Parse(rest[1:]); err != nil {
		return 2
	}

	home := razor.ResolveHome(*homedir)
	ident := razor.ResolveIdentity(*user, *pass, home)

	// newClient builds a Client from the resolved config. serve mode calls it
	// per request (Razor2 session state is per-connection).
	newClient := func() *razor.Client {
		c := &razor.Client{
			Server:      *server,
			Discoveries: splitComma(*discovery),
			Port:        *port,
			Timeout:     *timeout,
			MinCf:       *minCf,
			Ident:       ident,
			Verbose:     *verbose,
			Log:         func(s string) { fmt.Fprintln(stderr, s) },
		}
		return c
	}
	c := newClient()

	switch op {
	case "serve":
		return runServe(serveConfig{
			listen: *listen, unix: *unixSock, token: *token, maxConc: *maxConc,
			timeout: *timeout, logStdout: *logStdout, verbose: *verbose, newClient: newClient,
		}, stderr)
	case "sig":
		raw, err := readCapped(stdin, maxStdin)
		if err != nil {
			fmt.Fprintln(stderr, "read stdin:", err)
			return 2
		}
		for _, ps := range razor.Signatures(raw) {
			if ps.Skip {
				fmt.Fprintf(stdout, "part %d: (skipped, empty)\n", ps.Index)
				continue
			}
			if ps.E4 != "" {
				fmt.Fprintf(stdout, "part %d e4: %s\n", ps.Index, ps.E4)
			}
			for _, s := range ps.E8 {
				fmt.Fprintf(stdout, "part %d e8: %s\n", ps.Index, s)
			}
		}
		return 0
	case "register":
		id, err := c.Register(*user, *pass)
		if err != nil {
			fmt.Fprintln(stderr, "register:", err)
			return 1
		}
		// Print the identity as environment-variable assignments BEFORE saving,
		// so a save failure cannot strand a credential the server already
		// created. Bare KEY=value lines (no prefix) so `grep '^GAZOR_'` extracts
		// them — use them via the env (container/systemd EnvironmentFile)
		// instead of the identity file.
		fmt.Fprintln(stdout, "register: environment variables for this identity (use instead of the file):")
		fmt.Fprintf(stdout, "GAZOR_USER=%s\n", id.User)
		fmt.Fprintf(stdout, "GAZOR_PASS=%s\n", id.Pass)
		// Registration created a real server-side account; persist it so a later
		// `gazor report`/`revoke` can load it (ResolveIdentity reads the home
		// dir). Failing to save would silently strand the new credential.
		saved, err := saveIdentity(home, *out, id)
		if err != nil {
			fmt.Fprintln(stderr, "register: WARNING identity obtained but NOT saved:", err)
			fmt.Fprintln(stderr, "register: copy the GAZOR_USER/GAZOR_PASS lines above — re-registering creates another account")
			return 1
		}
		fmt.Fprintln(stdout, "register: saved identity to", saved)
		return 0
	case "check", "report", "revoke":
		raw, err := readCapped(stdin, maxStdin)
		if err != nil {
			fmt.Fprintln(stderr, "read stdin:", err)
			return 2
		}
		return doMessageOp(c, op, raw, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown op %q\n", op)
		return 2
	}
}

func doMessageOp(c *razor.Client, op string, raw []byte, stdout, stderr io.Writer) int {
	switch op {
	case "check":
		spam, err := c.Check(raw)
		if err != nil {
			fmt.Fprintln(stderr, "check:", err)
			return 2
		}
		if spam {
			fmt.Fprintln(stdout, "spam")
			return 0
		}
		fmt.Fprintln(stdout, "not spam")
		return 1
	case "report":
		if err := c.Report(raw); err != nil {
			fmt.Fprintln(stderr, "report:", err)
			return 1
		}
		return 0
	case "revoke":
		if err := c.Revoke(raw); err != nil {
			fmt.Fprintln(stderr, "revoke:", err)
			return 1
		}
		return 0
	}
	return 2
}

// saveIdentity persists a registered identity to the Razor2 home (or an explicit
// out file), delegating to razor.WriteIdentityFile — the single source of truth
// for the on-disk credential format, shared with the gozer shim.
func saveIdentity(home, out string, id *razor.Identity) (string, error) {
	return razor.WriteIdentityFile(home, out, *id)
}

// errTooLarge is returned by readCapped when the input exceeds the cap, so the
// caller can reject it (413 / usage error) rather than silently processing a
// truncated prefix.
var errTooLarge = errors.New("message exceeds the maximum size")

// readCapped reads up to max bytes and returns errTooLarge if there is more —
// it reads max+1 so an exactly-max message is accepted but an over-cap message
// is rejected, not truncated.
func readCapped(r io.Reader, max int) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, int64(max)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > max {
		return nil, errTooLarge
	}
	return b, nil
}

// --- env-var fallbacks (flag > env > default) and parsing helpers ---

func envStr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envIntDefault(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envDur(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

func envBool(key string) bool {
	switch strings.ToLower(os.Getenv(key)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// splitComma splits a comma-separated list into trimmed non-empty entries; a
// single entry (or empty) yields one (or zero) element(s).
func splitComma(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
