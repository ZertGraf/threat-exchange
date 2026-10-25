package httpapi

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestEncodedPathsAndMethods(t *testing.T) {
	for _, tt := range []struct {
		name, method, path, body, allow string
		status                          int
	}{
		// the contract matches the escaped path, so encoded characters never reach storage.
		{"encoded hash", "GET", "/info/%64" + testMD5[1:], "", "", 400},
		{"encoded update", "PUT", "/info/%64" + testMD5[1:], "{\"name\":\"new\"}", "", 400},
		{"encoded route", "POST", "/%69nfo", "{\"md5\":\"" + testMD5 + "\",\"name\":\"new\"}", "", 404},
		{"encoded separator", "GET", "/info/" + testMD5 + "%2f", "", "", 400},
		{"double encoding", "GET", "/info/%2564" + testMD5[1:], "", "", 400},
		{"encoded route separator", "GET", "/info%2f" + testMD5, "", "", 404},
		{"unsupported item method", "DELETE", "/info/" + testMD5, "", "GET, PUT", 405},
		{"unsupported encoded method", "DELETE", "/info/%64" + testMD5[1:], "", "GET, PUT", 405},
		{"unsupported collection method", "GET", "/info", "", "POST", 405},
		{"missing route", "GET", "/missing", "", "", 404},
	} {
		t.Run(tt.name, func(t *testing.T) {
			repo := &stubRepository{}
			handler := newTestHandler(t, repo, Options{})
			req := httptest.NewRequest(tt.method, tt.path, strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			if w.Code != tt.status || w.Header().Get("Allow") != tt.allow {
				t.Fatalf("status=%d allow=%q body=%s", w.Code, w.Header().Get("Allow"), w.Body)
			}
			if !json.Valid(w.Body.Bytes()) || (tt.status >= 400 && repo.calls.Load() != 0) {
				t.Fatal("invalid response or rejected request reached storage")
			}
			if tt.status < 400 {
				validateResponse(t, tt.method, tt.path, w)
			} else {
				validateErrorResponse(t, w)
			}
		})
	}
}

func TestUnicodeBlankName(t *testing.T) {
	handler := newTestHandler(t, &stubRepository{}, Options{})
	// cover every unicode whitespace code point removed by name trimming.
	for c := rune(0); c <= unicode.MaxRune; c++ {
		if !unicode.IsSpace(c) {
			continue
		}
		for _, name := range []string{string(c), string(c) + "label" + string(c)} {
			t.Run(fmt.Sprintf("%U/%t", c, strings.TrimSpace(name) != ""), func(t *testing.T) {
				want := 400
				if strings.TrimSpace(name) != "" {
					want = 200
				}
				body, err := json.Marshal(map[string]string{"name": name})
				if err != nil {
					t.Fatal(err)
				}
				req := httptest.NewRequest("PUT", "/info/"+testMD5, bytes.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, req)
				if w.Code != want {
					t.Fatalf("status=%d want=%d: %s", w.Code, want, w.Body)
				}
			})
		}
	}
}

func TestStorageErrorDiagnostics(t *testing.T) {
	for _, tt := range []struct {
		name, category, sqlstate string
		err                      error
		status                   int
	}{
		{"postgres", "postgres", "23514", &pgconn.PgError{Code: "23514", Message: "private-value"}, 500},
		{"deadline", "deadline", "", context.DeadlineExceeded, 503},
		{"canceled", "canceled", "", context.Canceled, 408},
		{"connection", "connection", "", &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("private-value")}, 500},
		{"other", "internal", "", errors.New("private-value"), 500},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var logs bytes.Buffer
			handler, err := New(&stubRepository{err: fmt.Errorf("private-value: %w", tt.err)}, Options{
				Logger: slog.New(slog.NewJSONHandler(&logs, nil)),
			})
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, httptest.NewRequest("GET", "/info/"+testMD5, nil))
			// the storage error is logged before the access log entry.
			var event map[string]any
			if err := json.NewDecoder(&logs).Decode(&event); err != nil {
				t.Fatal(err)
			}
			if event["error_category"] != tt.category || event["sqlstate"] != tt.sqlstate || event["duration_ms"] == nil {
				t.Fatalf("missing safe diagnostics: %s", &logs)
			}
			if w.Code != tt.status || strings.Contains(logs.String()+w.Body.String(), "private-value") {
				t.Fatalf("unexpected status or leaked data: %d %s %s", w.Code, &logs, w.Body)
			}
			validateResponse(t, "GET", "/info/"+testMD5, w)
		})
	}
}

func TestPublishedAuthentication(t *testing.T) {
	for _, key := range []string{"", testKey} {
		t.Run(fmt.Sprint(key != ""), func(t *testing.T) {
			handler := newTestHandler(t, &stubRepository{}, Options{APIKey: key})
			var previous []byte
			for range 2 {
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, httptest.NewRequest("GET", "/openapi.json", nil))
				var doc struct {
					Security []map[string][]string
				}
				if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
					t.Fatal(err)
				}
				anonymous := len(doc.Security) == 0
				for _, requirement := range doc.Security {
					anonymous = anonymous || len(requirement) == 0
				}
				if anonymous != (key == "") || w.Code != 200 {
					t.Fatalf("incorrect published authentication: %+v", doc.Security)
				}
				if previous != nil && !bytes.Equal(previous, w.Body.Bytes()) {
					t.Fatal("published specification changed between requests")
				}
				previous = append([]byte(nil), w.Body.Bytes()...)
			}
		})
	}
}

func TestPublishedOperationIDs(t *testing.T) {
	source, err := openapi3.NewLoader().LoadFromFile("../../api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	operationIDs := func(doc *openapi3.T) map[string]bool {
		ids := map[string]bool{}
		for _, item := range doc.Paths.Map() {
			for _, operation := range item.Operations() {
				ids[operation.OperationID] = true
			}
		}
		return ids
	}
	w := httptest.NewRecorder()
	newTestHandler(t, &stubRepository{}, Options{}).ServeHTTP(w, httptest.NewRequest("GET", "/openapi.json", nil))
	published, err := openapi3.NewLoader().LoadFromData(w.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	got, want := operationIDs(published), operationIDs(source)
	if !maps.Equal(got, want) || len(want) != 3 {
		t.Fatalf("published operation ids %v, source %v", got, want)
	}
}

func TestBodyReadTimeout(t *testing.T) {
	repo := &stubRepository{}
	server := httptest.NewUnstartedServer(newTestHandler(t, repo, Options{}))
	server.Config.ReadTimeout = 100 * time.Millisecond
	server.Config.WriteTimeout = 2 * time.Second
	server.Start()
	t.Cleanup(server.Close)
	conn, err := net.DialTimeout("tcp", server.Listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, "POST /info HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := response.Body.Close(); err != nil {
			t.Error(err)
		}
	}()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 408 || !json.Valid(body) || repo.calls.Load() != 0 {
		t.Fatalf("status=%d body=%s", response.StatusCode, body)
	}
}
