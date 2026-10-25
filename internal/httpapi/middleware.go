package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"mime"
	"net"
	"net/http"
	"runtime/debug"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/time/rate"
)

const maxBodyBytes = 64 << 10

var bodyTooLarge = "Request body exceeds " + strconv.Itoa(maxBodyBytes) + " bytes"

// statusRecorder captures the response status for the access log.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (w *statusRecorder) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (w *statusRecorder) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// logRequests writes one access log entry per request; headers and bodies are not logged.
func logRequests(next http.Handler, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		recorder := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(recorder, r)
		if recorder.status == 0 {
			recorder.status = http.StatusOK
		}
		logger.InfoContext(r.Context(), "request", "method", r.Method, "path", r.URL.Path,
			"status", recorder.status, "duration_ms", float64(time.Since(started))/float64(time.Millisecond))
	})
}

func recoverRequests(next http.Handler, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if value := recover(); value != nil {
				if value == http.ErrAbortHandler {
					panic(value)
				}
				logger.ErrorContext(r.Context(), "request panic recovered", "method", r.Method,
					"panic_type", fmt.Sprintf("%T", value), "stack", string(debug.Stack()))
				writeJSONBytes(w, http.StatusInternalServerError, internalErrorJSON)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// protect authenticates before spending quota: rejected attempts draw from their own
// bucket, so anonymous traffic cannot exhaust the quota of authorized clients.
func protect(next http.Handler, key string, limiter, rejected *rate.Limiter) http.Handler {
	expected := sha256.Sum256([]byte(key))
	retryAfter := ""
	if limiter != nil {
		retry := math.Max(1, math.Ceil(1/float64(limiter.Limit())))
		retryAfter = strconv.FormatFloat(retry, 'f', 0, 64)
	}
	limitedJSON := errorJSON("Too many requests")
	unauthorizedJSON := errorJSON("Invalid API key")
	limited := func(w http.ResponseWriter, bucket *rate.Limiter) bool {
		if bucket == nil || bucket.Allow() {
			return false
		}
		w.Header().Set("Retry-After", retryAfter)
		writeJSONBytes(w, http.StatusTooManyRequests, limitedJSON)
		return true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if key != "" {
			provided := sha256.Sum256([]byte(r.Header.Get("X-API-Key")))
			if subtle.ConstantTimeCompare(expected[:], provided[:]) != 1 {
				if limited(w, rejected) {
					return
				}
				w.Header().Set("WWW-Authenticate", `ApiKey realm="threat-exchange"`)
				writeJSONBytes(w, http.StatusUnauthorized, unauthorizedJSON)
				return
			}
		}
		if limited(w, limiter) {
			return
		}
		next.ServeHTTP(w, r)
	})
}

func prepareRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost || r.Method == http.MethodPut {
			if r.ContentLength > maxBodyBytes {
				if r.ProtoMajor == 1 {
					w.Header().Set("Connection", "close")
				}
				writeError(w, http.StatusRequestEntityTooLarge, bodyTooLarge, "")
				return
			}
			if contentType := r.Header.Get("Content-Type"); contentType != "application/json" {
				mediaType, params, err := mime.ParseMediaType(contentType)
				charset, hasCharset := params["charset"]
				if err != nil || mediaType != "application/json" ||
					(hasCharset && !strings.EqualFold(charset, "utf-8")) {
					writeError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json with UTF-8 encoding", "")
					return
				}
			}
			body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				writeError(w, http.StatusRequestEntityTooLarge, bodyTooLarge, "")
				return
			}
			var timeout net.Error
			if errors.As(err, &timeout) && timeout.Timeout() {
				writeError(w, http.StatusRequestTimeout, "Request body read timed out", "")
				return
			}
			if err != nil || !utf8.Valid(body) || !json.Valid(body) {
				writeError(w, http.StatusBadRequest, "Invalid JSON", "Expected one UTF-8 JSON object")
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
		// uploading the body does not consume the processing and database budget.
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}
