package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/myguard-labs/gazor/razor"
)

// deadClient returns a Client pointed at a closed loopback port so every
// protocol op fails fast — exercises the handlers' error-mapping path without a
// full fake Razor2 server (the happy path is covered by razor/protocol_test.go).
func deadClient() *razor.Client {
	return &razor.Client{
		Server:  "127.0.0.1:1", // nothing listens here
		Timeout: 200 * time.Millisecond,
		Log:     func(string) {},
	}
}

func deadCfg() serveConfig {
	return serveConfig{timeout: 200 * time.Millisecond, newClient: deadClient}
}

const probe = "From: a@b.c\r\nSubject: hi\r\n\r\nhello world this is a test message\r\n"

func TestServeCheckErrorIsUnknown(t *testing.T) {
	m := newMetrics()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/check", strings.NewReader(probe))
	checkHandler(deadCfg(), m)(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Errorf("code = %d, want 502", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "\"action\":\"unknown\"") {
		t.Errorf("body = %s", rec.Body.String())
	}
}

func TestServeReportError(t *testing.T) {
	m := newMetrics()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/report", strings.NewReader(probe))
	reportHandler(deadCfg(), m)(rec, req)
	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "\"reported\":false") {
		t.Errorf("report: code=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestServeRevokeError(t *testing.T) {
	m := newMetrics()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/revoke", strings.NewReader(probe))
	revokeHandler(deadCfg(), m)(rec, req)
	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "\"revoked\":false") {
		t.Errorf("revoke: code=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestServeCheckGETRejected(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/check", nil)
	checkHandler(deadCfg(), newMetrics())(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /check code = %d, want 405", rec.Code)
	}
}

func TestServeAuth(t *testing.T) {
	called := false
	h := serveConfig{token: "sek"}.auth(func(w http.ResponseWriter, r *http.Request) { called = true })

	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest("POST", "/check", nil))
	if rec.Code != http.StatusUnauthorized || called {
		t.Errorf("no token: code=%d called=%v", rec.Code, called)
	}

	rec = httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/check", nil)
	req.Header.Set("X-GAZOR-Token", "sek")
	h(rec, req)
	if !called {
		t.Error("valid X-GAZOR-Token should pass")
	}

	called = false
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/check", nil)
	req.Header.Set("Authorization", "Bearer sek")
	h(rec, req)
	if !called {
		t.Error("valid Bearer token should pass")
	}
}

func TestServeAuthOpenWhenNoToken(t *testing.T) {
	called := false
	serveConfig{}.auth(func(w http.ResponseWriter, r *http.Request) { called = true })(
		httptest.NewRecorder(), httptest.NewRequest("POST", "/check", nil))
	if !called {
		t.Error("no token configured should be open")
	}
}

func TestMetricsExposition(t *testing.T) {
	m := newMetrics()
	m.inc(&m.checkTotal)
	m.verdictInc("reject")
	m.observe(0.02)
	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body := rec.Body.String()
	for _, want := range []string{
		"gazor_check_total 1",
		"gazor_verdict_total{verdict=\"reject\"} 1",
		"gazor_latency_seconds_count 1",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics missing %q\n%s", want, body)
		}
	}
}
