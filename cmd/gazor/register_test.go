package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/myguard-labs/gazor/razor"
)

// TestCLIRegisterEnvAndSave drives `gazor register` against the fake razor
// server and asserts it both prints the new identity as GAZOR_USER=/GAZOR_PASS=
// env lines AND reports the file it saved to.
func TestCLIRegisterEnvAndSave(t *testing.T) {
	h, p := fakeRazor(t, false)
	home := t.TempDir()
	code, out, errb := runCLI(t, []string{
		"--server", h, "--port", strconv.Itoa(p), "--timeout", "3s",
		"--homedir", home, "register",
	}, "")
	if code != 0 {
		t.Fatalf("register exit=%d err=%q out=%q", code, errb, out)
	}
	for _, want := range []string{"GAZOR_USER=newuser", "GAZOR_PASS=newpass", "saved identity to"} {
		if !strings.Contains(out, want) {
			t.Fatalf("register stdout missing %q:\n%s", want, out)
		}
	}
	// The env line must be bare (greppable) — no leading prefix.
	if !strings.Contains(out, "\nGAZOR_USER=newuser\n") && !strings.HasPrefix(out, "GAZOR_USER=newuser\n") {
		t.Fatalf("GAZOR_USER line is not a bare KEY=value line:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(home, "identity")); err != nil {
		t.Fatalf("identity file not saved: %v", err)
	}
}

func TestSaveIdentityExplicitOut(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "creds")
	id := &razor.Identity{User: "bob@example.com", Pass: "s3cret"}
	got, err := saveIdentity(dir, out, id)
	if err != nil || got != out {
		t.Fatalf("got %q err %v", got, err)
	}
	// round-trips through the reader gazor uses to load it
	f, _ := os.Open(out)
	defer f.Close()
	back, ok := razor.ParseIdentityFile(f)
	if !ok || back.User != id.User || back.Pass != id.Pass {
		t.Errorf("round-trip: %+v ok=%v", back, ok)
	}
	if fi, _ := os.Stat(out); fi.Mode().Perm() != 0o600 {
		t.Errorf("perm = %v, want 0600", fi.Mode().Perm())
	}
}

func TestSaveIdentityDefaultsToHomeIdentity(t *testing.T) {
	home := filepath.Join(t.TempDir(), "razorhome") // does not exist yet
	got, err := saveIdentity(home, "", &razor.Identity{User: "u", Pass: "p"})
	if err != nil {
		t.Fatal(err)
	}
	if got != filepath.Join(home, "identity") {
		t.Errorf("got %q", got)
	}
	if _, err := os.Stat(got); err != nil {
		t.Errorf("file not written: %v", err)
	}
}

func TestSaveIdentityNoClobber(t *testing.T) {
	home := t.TempDir()
	// pre-existing active identity
	if err := os.WriteFile(filepath.Join(home, "identity"), []byte("user=old\npass=old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := saveIdentity(home, "", &razor.Identity{User: "new@x", Pass: "np"})
	if err != nil {
		t.Fatal(err)
	}
	if got != filepath.Join(home, "identity-new@x") {
		t.Errorf("expected no-clobber sibling, got %q", got)
	}
	// active identity untouched
	b, _ := os.ReadFile(filepath.Join(home, "identity"))
	if !strings.Contains(string(b), "user=old") {
		t.Errorf("active identity was clobbered: %s", b)
	}
}
