package httpapi

import (
	"context"
	"errors"
	"net"
	"net/http"
	"path"
	"strconv"
	"strings"
)

// wrappingMux registers every generated operation behind one handler chain, built once.
type wrappingMux struct {
	*http.ServeMux
	wrap func(http.Handler) http.Handler
}

func (m wrappingMux) HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request)) {
	m.Handle(pattern, m.wrap(http.HandlerFunc(handler)))
}

// public resources answer GET and HEAD; their other methods are rejected without
// protection, so probes never draw from the API quota.
func handlePublic(mux *http.ServeMux, path string, routeError http.Handler, respond func(*http.Request) (int, []byte)) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		status, body := respond(r)
		writePublicJSON(w, r, status, body)
	})
	mux.Handle(http.MethodGet+" "+path, handler)
	mux.Handle(http.MethodHead+" "+path, handler)
	mux.Handle(path, routeError)
}

// writeRouteError answers requests no route accepts. Only patterns registered for the
// exact method count, so the implicit HEAD of GET routes is not advertised.
func writeRouteError(w http.ResponseWriter, r *http.Request, mux *http.ServeMux, methods []string) {
	var allowed []string
	// a non-canonical path would match through the mux redirect; it names no resource.
	if canonicalPath(r.URL.EscapedPath()) {
		probe := *r
		for _, method := range methods {
			probe.Method = method
			if _, pattern := mux.Handler(&probe); strings.HasPrefix(pattern, method+" ") {
				allowed = append(allowed, method)
			}
		}
	}
	status := http.StatusNotFound
	if len(allowed) != 0 {
		status = http.StatusMethodNotAllowed
		w.Header().Set("Allow", strings.Join(allowed, ", "))
	}
	writeError(w, status, http.StatusText(status), contractMismatch)
}

// canonicalPath reports whether ServeMux serves p without redirecting to a cleaned path.
func canonicalPath(p string) bool {
	if p == "" || p[0] != '/' {
		return false
	}
	clean := path.Clean(p)
	if strings.HasSuffix(p, "/") && clean != "/" {
		clean += "/"
	}
	return clean == p
}

func writePublicJSON(w http.ResponseWriter, r *http.Request, status int, body []byte) {
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	if r.Method == http.MethodHead {
		body = nil
	}
	writeJSONBytes(w, status, body)
}

// report structured metadata without logging database messages, query values, or credentials.
func storageErrorClass(ctx context.Context, err error) (category, sqlstate string) {
	var postgres interface{ SQLState() string }
	var connection net.Error
	if errors.As(err, &postgres) {
		sqlstate = postgres.SQLState()
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.Is(ctx.Err(), context.DeadlineExceeded):
		return "deadline", sqlstate
	case errors.Is(err, context.Canceled), errors.Is(ctx.Err(), context.Canceled):
		return "canceled", sqlstate
	case sqlstate != "":
		return "postgres", sqlstate
	case errors.As(err, &connection):
		return "connection", ""
	default:
		return "internal", ""
	}
}
