package httpapi

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type benchmarkWriter struct {
	header http.Header
	status int
}

func (w *benchmarkWriter) Header() http.Header         { return w.header }
func (w *benchmarkWriter) WriteHeader(status int)      { w.status = status }
func (w *benchmarkWriter) Write(p []byte) (int, error) { return len(p), nil }

func BenchmarkHTTP(b *testing.B) {
	handler, err := New(&stubRepository{}, Options{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		b.Fatal(err)
	}
	for _, path := range []string{"/healthz", "/openapi.json", "/info/" + testMD5, "/info/%64" + testMD5[1:]} {
		b.Run(path, func(b *testing.B) {
			req := httptest.NewRequest("GET", path, nil)
			w := &benchmarkWriter{header: make(http.Header)}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				clear(w.header)
				handler.ServeHTTP(w, req)
			}
			if w.status != 200 {
				b.Fatal(w.status)
			}
		})
	}
	for _, size := range []int{8, 4096} {
		b.Run(fmt.Sprintf("create/%d", size), func(b *testing.B) {
			body := "{\"md5\":\"" + testMD5 + "\",\"name\":\"x\",\"description\":\"" + strings.Repeat("a", size) + "\"}"
			req := httptest.NewRequest("POST", "/info", nil)
			req.Header.Set("Content-Type", "application/json")
			w := &benchmarkWriter{header: make(http.Header)}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				clear(w.header)
				// reset the validator's replay function so each iteration models a fresh request.
				req.Body = io.NopCloser(strings.NewReader(body))
				req.GetBody = nil
				handler.ServeHTTP(w, req)
			}
			if w.status != 201 {
				b.Fatal(w.status)
			}
		})
	}
}
