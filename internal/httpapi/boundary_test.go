package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"threat-exchange/api"
	"threat-exchange/internal/store"
)

type unreadBody struct{}

func (unreadBody) Read([]byte) (int, error) { panic("request body must not be read") }
func (unreadBody) Close() error             { return nil }

func validateErrorResponse(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	spec, err := api.GetSpec()
	if err != nil {
		t.Fatal(err)
	}
	var body any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if err := spec.Components.Schemas["ErrorResponse"].Value.VisitJSON(body); err != nil {
		t.Fatalf("invalid error response: %v", err)
	}
}

func TestRoutingBeforeBody(t *testing.T) {
	for _, tt := range []struct {
		method, path, allow string
		status              int
	}{
		{"POST", "/info/" + testMD5, "GET, PUT", 405},
		{"PUT", "/info", "POST", 405},
		{"POST", "/unknown", "", 404},
		{"PUT", "/missing", "", 404},
	} {
		for _, contentType := range []string{"", "text/plain", "application/json"} {
			t.Run(tt.method+tt.path+"/"+contentType, func(t *testing.T) {
				repo := &stubRepository{}
				h := newTestHandler(t, repo, Options{APIKey: testKey})
				req := httptest.NewRequest(tt.method, tt.path, unreadBody{})
				req.ContentLength = maxBodyBytes + 1
				req.Header.Set("Content-Type", contentType)
				req.Header.Set("X-API-Key", testKey)
				w := httptest.NewRecorder()
				h.ServeHTTP(w, req)
				if w.Code != tt.status || w.Header().Get("Allow") != tt.allow || repo.calls.Load() != 0 {
					t.Fatalf("status=%d allow=%q: %s", w.Code, w.Header().Get("Allow"), w.Body)
				}
				validateErrorResponse(t, w)
			})
		}
	}
}

func TestRouteErrorsFollowProtection(t *testing.T) {
	for _, tt := range []struct {
		method, path, key, allow string
		status                   int
	}{
		{"POST", "/info/" + testMD5, "", "", 401},
		{"GET", "/unknown", "", "", 401},
		{"GET", "//info/" + testMD5, "", "", 401},
		{"GET", "//info/" + testMD5, testKey, "", 404},
		{"GET", "/info/./" + testMD5, testKey, "", 404},
		{"GET", "/healthz/../info/" + testMD5, testKey, "", 404},
		{"HEAD", "/info/" + testMD5, testKey, "GET, PUT", 405},
	} {
		t.Run(tt.method+tt.path+"/"+fmt.Sprint(tt.key != ""), func(t *testing.T) {
			repo := &stubRepository{}
			h := newTestHandler(t, repo, Options{APIKey: testKey})
			req := httptest.NewRequest(tt.method, tt.path, nil)
			req.Header.Set("X-API-Key", tt.key)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != tt.status || w.Header().Get("Allow") != tt.allow || w.Header().Get("Location") != "" || repo.calls.Load() != 0 {
				t.Fatalf("status=%d allow=%q: %s", w.Code, w.Header().Get("Allow"), w.Body)
			}
			validateErrorResponse(t, w)
		})
	}
}

func TestPublicMethodsBypassProtection(t *testing.T) {
	h := newTestHandler(t, &stubRepository{}, Options{APIKey: testKey, RateRPS: 0.001, RateBurst: 1})
	for _, path := range []string{"/healthz", "/readyz", "/openapi.json"} {
		for _, method := range []string{"GET", "HEAD", "POST", "PUT", "DELETE"} {
			t.Run(method+path, func(t *testing.T) {
				w := httptest.NewRecorder()
				h.ServeHTTP(w, httptest.NewRequest(method, path, unreadBody{}))
				if method == "GET" || method == "HEAD" {
					if w.Code != 200 || w.Header().Get("Content-Length") == "" {
						t.Fatalf("public request failed: %d %s", w.Code, w.Body)
					}
					if method == "HEAD" && w.Body.Len() != 0 {
						t.Fatal("HEAD returned a body")
					}
				} else {
					if w.Code != 405 || w.Header().Get("Allow") != "GET, HEAD" {
						t.Fatalf("method handling: %d %s", w.Code, w.Body)
					}
					validateErrorResponse(t, w)
				}
			})
		}
	}
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/info/"+testMD5, nil)
	req.Header.Set("X-API-Key", testKey)
	h.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("public routes consumed API quota: %d", w.Code)
	}
}

func TestBodyBoundsAndCharset(t *testing.T) {
	h := newTestHandler(t, &stubRepository{}, Options{})
	t.Run("declared oversized body", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/info", unreadBody{})
		req.Header.Set("Content-Type", "application/json")
		req.ContentLength = maxBodyBytes + 1
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != 413 || w.Header().Get("Connection") != "close" {
			t.Fatalf("%d: %s", w.Code, w.Body)
		}
	})
	for _, method := range []string{"POST", "PUT"} {
		t.Run(method+" empty charset", func(t *testing.T) {
			path := "/info"
			if method == "PUT" {
				path += "/" + testMD5
			}
			req := httptest.NewRequest(method, path, unreadBody{})
			req.Header.Set("Content-Type", "application/json; charset=\"\"")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != 415 {
				t.Fatalf("%d: %s", w.Code, w.Body)
			}
		})
	}
}

type panicRepository struct {
	stubRepository
	value any
}

func (p *panicRepository) Get(context.Context, string) (api.ThreatResponse, error) {
	panic(p.value)
}
func (p *panicRepository) Ping(context.Context) error { panic(p.value) }

func TestRecoveryScope(t *testing.T) {
	if _, err := New(nil, Options{}); err == nil {
		t.Fatal("accepted nil repository")
	}
	for _, path := range []string{"/readyz", "/info/" + testMD5} {
		t.Run(path, func(t *testing.T) {
			h := newTestHandler(t, &panicRepository{value: "private panic"}, Options{})
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
			if w.Code != 500 || strings.Contains(w.Body.String(), "private") {
				t.Fatalf("%d: %s", w.Code, w.Body)
			}
		})
	}
	t.Run("abort handler", func(t *testing.T) {
		defer func() {
			if value := recover(); value != http.ErrAbortHandler {
				t.Fatalf("abort signal was swallowed: %v", value)
			}
		}()
		h := newTestHandler(t, &panicRepository{value: http.ErrAbortHandler}, Options{})
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/info/"+testMD5, nil))
	})
}

func TestPostgresCancellationClassification(t *testing.T) {
	deadline, stopDeadline := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stopDeadline()
	canceled, stopCanceled := context.WithCancel(context.Background())
	stopCanceled()
	for _, tt := range []struct {
		name     string
		ctx      context.Context
		category string
		status   int
	}{
		{"deadline", deadline, "deadline", 503},
		{"client cancellation", canceled, "canceled", 408},
		{"server cancellation without expired context", context.Background(), "postgres", 500},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := fmt.Errorf("query: %w", &pgconn.PgError{Code: "57014", Message: "private cancellation detail"})
			category, code := storageErrorClass(tt.ctx, err)
			if category != tt.category || code != "57014" {
				t.Fatalf("category=%s sqlstate=%s", category, code)
			}
			h := newTestHandler(t, &stubRepository{err: err}, Options{})
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest("GET", "/info/"+testMD5, nil).WithContext(tt.ctx))
			if w.Code != tt.status {
				t.Fatalf("%d: %s", w.Code, w.Body)
			}
			validateErrorResponse(t, w)
		})
	}
}

func TestErrorDetails(t *testing.T) {
	for _, tt := range []struct {
		name, method, path, body string
		status                   int
		want                     []string
		hidden                   string
	}{
		{"invalid enum", "PUT", "/info/" + testMD5, `{"name":"x","severity":"urgent"}`, 400, []string{"field severity", "allowed values"}, "urgent"},
		{"invalid tag", "PUT", "/info/" + testMD5, `{"name":"x","tags":["ok","Bad-Tag"]}`, 400, []string{"field tags.1", "required format"}, "Bad-Tag"},
		{"blank name", "PUT", "/info/" + testMD5, `{"name":"   "}`, 400, []string{"field name", "must not be blank"}, ""},
		{"missing name", "PUT", "/info/" + testMD5, `{}`, 400, []string{`property "name" is missing`}, ""},
		{"unknown property", "POST", "/info", `{"md5":"` + testMD5 + `","name":"x","secret-field":1}`, 400, []string{"unknown properties"}, "secret-field"},
		{"invalid path hash", "GET", "/info/not-a-hash", "", 400, []string{"path parameter md5", "required format"}, "not-a-hash"},
		{"missing record", "GET", "/info/" + strings.ToUpper(testMD5), "", 404, []string{"No threat with MD5 " + testMD5}, ""},
		{"duplicate record", "POST", "/info", `{"md5":"` + testMD5 + `","name":"x"}`, 409, []string{"MD5 " + testMD5 + " already exists"}, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			repo := &stubRepository{}
			switch tt.status {
			case 404:
				repo.err = store.ErrNotFound
			case 409:
				repo.err = store.ErrConflict
			}
			req := httptest.NewRequest(tt.method, tt.path, strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			newTestHandler(t, repo, Options{}).ServeHTTP(w, req)
			var problem api.ErrorResponse
			if err := json.Unmarshal(w.Body.Bytes(), &problem); err != nil || problem.Details == nil || w.Code != tt.status {
				t.Fatalf("%d: %s", w.Code, w.Body)
			}
			for _, part := range tt.want {
				if !strings.Contains(*problem.Details, part) {
					t.Fatalf("details %q do not mention %q", *problem.Details, part)
				}
			}
			if tt.hidden != "" && strings.Contains(w.Body.String(), tt.hidden) {
				t.Fatalf("response echoed submitted input: %s", w.Body)
			}
			validateErrorResponse(t, w)
		})
	}
}
