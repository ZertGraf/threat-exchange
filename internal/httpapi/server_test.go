package httpapi

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers/gorillamux"

	"threat-exchange/api"
	"threat-exchange/internal/store"
)

const testMD5 = "d41d8cd98f00b204e9800998ecf8427e"
const testKey = "test-api-key-with-at-least-32-bytes"

type stubRepository struct {
	calls    atomic.Int64
	pings    atomic.Int64
	err      error
	pingGate chan struct{}
}

func sample() api.ThreatResponse {
	return api.ThreatResponse{
		Md5: testMD5, Name: "Trojan.Win32.Generic", Severity: api.SeverityUnknown,
		Type: api.ThreatTypeUnknown, Tags: []string{}, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
}

func (s *stubRepository) Get(context.Context, string) (api.ThreatResponse, error) {
	s.calls.Add(1)
	return sample(), s.err
}
func (s *stubRepository) Create(context.Context, api.ThreatCreateRequest) (api.ThreatResponse, error) {
	s.calls.Add(1)
	return sample(), s.err
}
func (s *stubRepository) Update(context.Context, string, api.ThreatUpdateRequest) (api.ThreatResponse, error) {
	s.calls.Add(1)
	return sample(), s.err
}
func (s *stubRepository) Ping(context.Context) error {
	s.pings.Add(1)
	if s.pingGate != nil {
		<-s.pingGate
	}
	return s.err
}

func newTestHandler(t *testing.T, repo Repository, options Options) http.Handler {
	t.Helper()
	options.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	handler, err := New(repo, options)
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func TestRequestValidation(t *testing.T) {
	valid := `{"md5":"` + testMD5 + `","name":"Trojan"}`
	tests := []struct {
		name, method, path, body, contentType string
		status                                int
	}{
		{"minimal create", "POST", "/info", valid, "application/json", 201},
		{"json charset", "POST", "/info", valid, "application/json; charset=utf-8", 201},
		{"mixed case charset create", "POST", "/info", valid, "application/json; charset=Utf-8", 201},
		{"mixed case charset update", "PUT", "/info/" + testMD5, `{"name":"New"}`, "application/json; charset=uTf-8", 200},
		{"quoted mixed case charset", "POST", "/info", valid, `application/json; charset="UtF-8"`, 201},
		{"uppercase md5", "GET", "/info/" + strings.ToUpper(testMD5), "", "", 200},
		{"update", "PUT", "/info/" + testMD5, `{"name":"New"}`, "application/json", 200},
		{"invalid hash path", "GET", "/info/bad", "", "", 400},
		{"nonhex hash", "GET", "/info/" + strings.Repeat("g", 32), "", "", 400},
		{"missing hash", "POST", "/info", `{"name":"Trojan"}`, "application/json", 400},
		{"invalid hash body", "POST", "/info", `{"md5":"bad","name":"Trojan"}`, "application/json", 400},
		{"null hash", "POST", "/info", `{"md5":null,"name":"Trojan"}`, "application/json", 400},
		{"missing name", "POST", "/info", `{"md5":"` + testMD5 + `"}`, "application/json", 400},
		{"empty name", "PUT", "/info/" + testMD5, `{"name":""}`, "application/json", 400},
		{"blank name", "PUT", "/info/" + testMD5, `{"name":" \t\n"}`, "application/json", 400},
		{"unicode blank name", "PUT", "/info/" + testMD5, `{"name":"\u00a0\u2003"}`, "application/json", 400},
		{"null character name", "PUT", "/info/" + testMD5, `{"name":"bad\u0000name"}`, "application/json", 400},
		{"null character description", "PUT", "/info/" + testMD5, `{"name":"x","description":"\u0000"}`, "application/json", 400},
		{"name type", "PUT", "/info/" + testMD5, `{"name":5}`, "application/json", 400},
		{"null name", "PUT", "/info/" + testMD5, `{"name":null}`, "application/json", 400},
		{"long name", "PUT", "/info/" + testMD5, `{"name":"` + strings.Repeat("я", 256) + `"}`, "application/json", 400},
		{"max unicode name", "PUT", "/info/" + testMD5, `{"name":"` + strings.Repeat("я", 255) + `"}`, "application/json", 200},
		{"long description", "PUT", "/info/" + testMD5, `{"name":"x","description":"` + strings.Repeat("a", 4097) + `"}`, "application/json", 400},
		{"invalid severity", "PUT", "/info/" + testMD5, `{"name":"x","severity":"urgent"}`, "application/json", 400},
		{"invalid type", "PUT", "/info/" + testMD5, `{"name":"x","type":"malware"}`, "application/json", 400},
		{"null optional", "PUT", "/info/" + testMD5, `{"name":"x","severity":null}`, "application/json", 400},
		{"null description", "PUT", "/info/" + testMD5, `{"name":"x","description":null}`, "application/json", 400},
		{"null tags", "PUT", "/info/" + testMD5, `{"name":"x","tags":null}`, "application/json", 400},
		{"duplicate tags", "PUT", "/info/" + testMD5, `{"name":"x","tags":["a","a"]}`, "application/json", 400},
		{"too many tags", "PUT", "/info/" + testMD5, `{"name":"x","tags":["a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u"]}`, "application/json", 400},
		{"invalid tag", "PUT", "/info/" + testMD5, `{"name":"x","tags":["Windows"]}`, "application/json", 400},
		{"empty tag", "PUT", "/info/" + testMD5, `{"name":"x","tags":[""]}`, "application/json", 400},
		{"long tag", "PUT", "/info/" + testMD5, `{"name":"x","tags":["` + strings.Repeat("a", 33) + `"]}`, "application/json", 400},
		{"unknown field", "POST", "/info", strings.TrimSuffix(valid, "}") + `,"extra":true}`, "application/json", 400},
		{"immutable hash", "PUT", "/info/" + testMD5, valid, "application/json", 400},
		{"immutable date", "PUT", "/info/" + testMD5, `{"name":"x","created_at":"2026-01-01T00:00:00Z"}`, "application/json", 400},
		{"invalid JSON", "POST", "/info", `{`, "application/json", 400},
		{"empty body", "POST", "/info", "", "application/json", 400},
		{"trailing JSON", "POST", "/info", valid + ` {}`, "application/json", 400},
		{"top level null", "POST", "/info", `null`, "application/json", 400},
		{"top level array", "POST", "/info", `[]`, "application/json", 400},
		{"invalid utf8", "POST", "/info", `{"name":"` + string([]byte{0xff}) + `"}`, "application/json", 400},
		{"missing media type", "POST", "/info", valid, "", 415},
		{"text media type", "POST", "/info", valid, "text/plain", 415},
		{"unsupported charset", "POST", "/info", valid, "application/json; charset=windows-1251", 415},
		{"unsupported charset update", "PUT", "/info/" + testMD5, `{"name":"New"}`, "application/json; charset=windows-1251", 415},
		{"body limit", "POST", "/info", strings.Repeat(" ", maxBodyBytes) + valid, "application/json", 413},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &stubRepository{}
			handler := newTestHandler(t, repo, Options{})
			req := httptest.NewRequest(tt.method, tt.path, strings.NewReader(tt.body))
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			if w.Code != tt.status {
				t.Fatalf("status %d, want %d: %s", w.Code, tt.status, w.Body.String())
			}
			if tt.status >= 400 && repo.calls.Load() != 0 {
				t.Fatal("invalid request reached persistence")
			}
			if w.Header().Get("Content-Type") != "application/json" {
				t.Fatal("non-JSON response")
			}
			validateResponse(t, tt.method, tt.path, w)
		})
	}
}

func validateResponse(t *testing.T, method, path string, w *httptest.ResponseRecorder) {
	t.Helper()
	spec, err := api.GetSpec()
	if err != nil {
		t.Fatal(err)
	}
	router, err := gorillamux.NewRouter(spec)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(method, path, nil)
	route, params, err := router.FindRoute(req)
	if err != nil {
		t.Fatal(err)
	}
	input := &openapi3filter.ResponseValidationInput{
		RequestValidationInput: &openapi3filter.RequestValidationInput{Request: req, PathParams: params, Route: route},
		Status:                 w.Code, Header: w.Header(), Body: io.NopCloser(strings.NewReader(w.Body.String())),
		Options: &openapi3filter.Options{IncludeResponseStatus: true},
	}
	if err := openapi3filter.ValidateResponse(context.Background(), input); err != nil {
		t.Fatalf("response violates contract: %v", err)
	}
}

func TestRepositoryErrors(t *testing.T) {
	for _, tt := range []struct {
		name, method string
		err          error
		status       int
	}{
		{"get missing", "GET", store.ErrNotFound, 404},
		{"update missing", "PUT", store.ErrNotFound, 404},
		{"duplicate", "POST", store.ErrConflict, 409},
		{"get failure", "GET", errors.New("secret-password"), 500},
		{"create failure", "POST", errors.New("secret-password"), 500},
		{"update failure", "PUT", errors.New("secret-password"), 500},
	} {
		t.Run(tt.name, func(t *testing.T) {
			handler := newTestHandler(t, &stubRepository{err: tt.err}, Options{})
			path, body := "/info/"+testMD5, `{"name":"x"}`
			if tt.method == "POST" {
				path = "/info"
				body = `{"md5":"` + testMD5 + `","name":"x"}`
			}
			req := httptest.NewRequest(tt.method, path, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			if w.Code != tt.status || strings.Contains(w.Body.String(), "secret") {
				t.Fatalf("unexpected response: %d %s", w.Code, w.Body)
			}
			validateResponse(t, tt.method, path, w)
		})
	}
}

func TestSecurityAndOperations(t *testing.T) {
	repo := &stubRepository{}
	handler := newTestHandler(t, repo, Options{APIKey: testKey, RateRPS: 0.001, RateBurst: 3})
	// rejected attempts exhaust only their own bucket; authorized clients keep the full burst.
	for _, tt := range []struct {
		key    string
		status int
	}{
		{"", 401}, {"wrong", 401}, {"", 401}, {"", 429},
		{testKey, 200}, {testKey, 200}, {testKey, 200}, {testKey, 429}, {"wrong", 429},
	} {
		req := httptest.NewRequest("GET", "/info/"+testMD5, nil)
		req.Header.Set("X-API-Key", tt.key)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != tt.status {
			t.Fatalf("status %d, want %d: %s", w.Code, tt.status, w.Body)
		}
		if w.Code == 429 && w.Header().Get("Retry-After") == "" {
			t.Fatal("missing retry header")
		}
	}
	for _, path := range []string{"/healthz", "/readyz", "/openapi.json"} {
		req := httptest.NewRequest("GET", path, nil)
		req.TLS = &tls.ConnectionState{}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != 200 || !json.Valid(w.Body.Bytes()) {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body)
		}
		if w.Header().Get("Strict-Transport-Security") == "" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Fatal("missing security headers")
		}
	}
	if repo.calls.Load() != 3 {
		t.Fatal("unauthorized or limited request reached persistence")
	}
}

func TestRateLimitWithoutAuthentication(t *testing.T) {
	handler := newTestHandler(t, &stubRepository{}, Options{RateRPS: 0.001, RateBurst: 2})
	for _, status := range []int{200, 200, 429} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("GET", "/info/"+testMD5, nil))
		if w.Code != status {
			t.Fatalf("status %d, want %d: %s", w.Code, status, w.Body)
		}
	}
}

func TestReadinessSharesDatabaseChecks(t *testing.T) {
	repo := &stubRepository{pingGate: make(chan struct{})}
	handler := newTestHandler(t, repo, Options{APIKey: testKey, RateRPS: 0.001, RateBurst: 1})
	const count = 32
	statuses := make(chan int, count)
	var wg sync.WaitGroup
	for range count {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, httptest.NewRequest("GET", "/readyz", nil))
			statuses <- w.Code
		}()
	}
	for repo.pings.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	close(repo.pingGate)
	wg.Wait()
	close(statuses)
	for status := range statuses {
		if status != 200 {
			t.Fatalf("readiness status %d", status)
		}
	}
	// late arrivals reuse the cached result instead of pinging again.
	if pings := repo.pings.Load(); pings != 1 {
		t.Fatalf("%d database pings for %d concurrent probes", pings, count)
	}
}

func TestReadinessCache(t *testing.T) {
	var pings atomic.Int64
	var failure atomic.Bool
	failure.Store(true)
	ping := func(context.Context) error {
		pings.Add(1)
		if failure.Load() {
			return errors.New("down")
		}
		return nil
	}
	cached := newReadiness(ping, time.Hour)
	if cached.check(context.Background()) {
		t.Fatal("failed ping reported ready")
	}
	failure.Store(false)
	if cached.check(context.Background()) || pings.Load() != 1 {
		t.Fatal("cached failure was not reused")
	}
	uncached := newReadiness(ping, 0)
	for range 2 {
		if !uncached.check(context.Background()) {
			t.Fatal("successful ping reported unavailable")
		}
	}
	if pings.Load() != 3 {
		t.Fatalf("expired results were reused: %d pings", pings.Load())
	}

	gate := make(chan struct{})
	started := make(chan struct{})
	slow := newReadiness(func(ctx context.Context) error {
		close(started)
		<-gate
		return ctx.Err()
	}, time.Hour)
	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leader := make(chan bool)
	go func() { leader <- slow.check(leaderCtx) }()
	<-started
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if slow.check(canceled) {
		t.Fatal("canceled waiter reported ready")
	}
	cancelLeader()
	close(gate)
	if !<-leader || !slow.check(context.Background()) {
		t.Fatal("a disconnected probe failed the shared check")
	}
}

// panics are covered by TestRecoveryScope.
func TestReadinessFailureIsRedacted(t *testing.T) {
	h := newTestHandler(t, &stubRepository{err: errors.New("private database error")}, Options{})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/readyz", nil))
	if w.Code != 503 || strings.Contains(w.Body.String(), "private") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}
