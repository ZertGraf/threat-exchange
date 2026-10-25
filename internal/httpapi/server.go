// Package httpapi connects the generated routes, schema validation, and persistence.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	nethttpmiddleware "github.com/oapi-codegen/nethttp-middleware"
	"github.com/oapi-codegen/runtime"
	"golang.org/x/time/rate"

	"threat-exchange/api"
	"threat-exchange/internal/store"
)

// Repository is the storage contract consumed by the http boundary.
type Repository interface {
	Get(context.Context, string) (api.ThreatResponse, error)
	Create(context.Context, api.ThreatCreateRequest) (api.ThreatResponse, error)
	Update(context.Context, string, api.ThreatUpdateRequest) (api.ThreatResponse, error)
	Ping(context.Context) error
}

// Options holds startup-only security settings; the limiters are process-wide.
type Options struct {
	APIKey    string
	RateRPS   float64
	RateBurst int
	Logger    *slog.Logger
}

type server struct {
	repo   Repository
	logger *slog.Logger
}

var _ api.ServerInterface = (*server)(nil)

// New validates the embedded contract before accepting any traffic.
func New(repo Repository, options Options) (http.Handler, error) {
	if repo == nil {
		return nil, errors.New("repository is required")
	}
	if options.Logger == nil {
		options.Logger = slog.Default()
	}
	spec, err := api.GetSpec()
	if err != nil {
		return nil, fmt.Errorf("load api contract: %w", err)
	}
	if options.APIKey != "" {
		spec.Security = openapi3.SecurityRequirements{{"ApiKey": []string{}}}
	} else {
		spec.Security = nil
	}
	if err := spec.Validate(context.Background()); err != nil {
		return nil, fmt.Errorf("validate api contract: %w", err)
	}
	specJSON, err := json.Marshal(spec)
	if err != nil {
		return nil, fmt.Errorf("encode api contract: %w", err)
	}
	specJSON = append(specJSON, '\n')
	// the public resources add GET and HEAD to the contract's methods.
	methodSet := map[string]struct{}{http.MethodGet: {}, http.MethodHead: {}}
	for _, item := range spec.Paths.Map() {
		for method := range item.Operations() {
			methodSet[method] = struct{}{}
		}
	}
	methods := slices.Sorted(maps.Keys(methodSet))
	mux := http.NewServeMux()
	routeError := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeRouteError(w, r, mux, methods)
	})
	validate := nethttpmiddleware.OapiRequestValidatorWithOptions(spec, &nethttpmiddleware.Options{
		Options: openapi3filter.Options{
			// authentication runs before body parsing to avoid spending work on unauthorized requests.
			AuthenticationFunc:  openapi3filter.NoopAuthenticationFunc,
			SkipSettingDefaults: true,
		},
		ErrorHandlerWithOpts: func(_ context.Context, err error, w http.ResponseWriter, r *http.Request, opts nethttpmiddleware.ErrorHandlerOpts) {
			// net/http routes HEAD to GET patterns; the contract does not.
			if errors.Is(err, routers.ErrMethodNotAllowed) {
				writeRouteError(w, r, mux, methods)
				return
			}
			status := opts.StatusCode
			writeError(w, status, http.StatusText(status), validationDetails(err))
		},
	})
	var limiter, rejected *rate.Limiter
	if options.RateRPS > 0 && options.RateBurst > 0 {
		limiter = rate.NewLimiter(rate.Limit(options.RateRPS), options.RateBurst)
		rejected = rate.NewLimiter(rate.Limit(options.RateRPS), options.RateBurst)
	}
	s := &server{repo: repo, logger: options.Logger}
	api.HandlerWithOptions(s, api.StdHTTPServerOptions{
		// access checks first, then body bounds, then the contract and path parameters.
		BaseRouter: wrappingMux{mux, func(operation http.Handler) http.Handler {
			return protect(prepareRequest(validate(operation)), options.APIKey, limiter, rejected)
		}},
		ErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			writeError(w, http.StatusBadRequest, "Bad Request", contractMismatch)
		},
	})
	// unknown resources and methods are rejected after access checks, before any body is read.
	unrouted := protect(routeError, options.APIKey, limiter, rejected)
	mux.Handle("/", unrouted)
	ready := newReadiness(repo.Ping, readinessTTL)
	healthJSON := []byte("{\"status\":\"ok\"}\n")
	readyJSON := []byte("{\"status\":\"ready\"}\n")
	unavailableJSON := errorJSON("Database unavailable")
	handlePublic(mux, "/healthz", routeError, func(*http.Request) (int, []byte) {
		return http.StatusOK, healthJSON
	})
	handlePublic(mux, "/readyz", routeError, func(r *http.Request) (int, []byte) {
		if !ready.check(r.Context()) {
			return http.StatusServiceUnavailable, unavailableJSON
		}
		return http.StatusOK, readyJSON
	})
	handlePublic(mux, "/openapi.json", routeError, func(*http.Request) (int, []byte) {
		return http.StatusOK, specJSON
	})
	return logRequests(recoverRequests(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		// the mux would redirect a non-canonical path before access checks run.
		if !canonicalPath(r.URL.EscapedPath()) {
			unrouted.ServeHTTP(w, r)
			return
		}
		mux.ServeHTTP(w, r)
	}), s.logger), s.logger), nil
}

// GetInfoByMd5 returns a complete canonical record or a typed http error.
func (s *server) GetInfoByMd5(w http.ResponseWriter, r *http.Request, md5 api.Md5) {
	started := time.Now()
	result, err := s.repo.Get(r.Context(), md5)
	s.respond(w, r, http.StatusOK, md5, result, err, started)
}

// CreateThreat returns the persisted representation and its relative location.
func (s *server) CreateThreat(w http.ResponseWriter, r *http.Request) {
	var request api.ThreatCreateRequest
	if err := runtime.BindJSONBody(r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON", "")
		return
	}
	if blankName(w, request.Name) {
		return
	}
	started := time.Now()
	result, err := s.repo.Create(r.Context(), request)
	if err == nil {
		w.Header().Set("Location", "/info/"+result.Md5)
	}
	s.respond(w, r, http.StatusCreated, request.Md5, result, err, started)
}

// UpdateThreat implements replacement semantics; it never creates missing records.
func (s *server) UpdateThreat(w http.ResponseWriter, r *http.Request, md5 api.Md5) {
	var request api.ThreatUpdateRequest
	if err := runtime.BindJSONBody(r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON", "")
		return
	}
	if blankName(w, request.Name) {
		return
	}
	started := time.Now()
	result, err := s.repo.Update(r.Context(), md5, request)
	s.respond(w, r, http.StatusOK, md5, result, err, started)
}

// blankName rejects names that are empty after the trimming applied before storage;
// json schema patterns cannot express unicode whitespace trimming.
func blankName(w http.ResponseWriter, name string) bool {
	if strings.TrimSpace(name) != "" {
		return false
	}
	writeError(w, http.StatusBadRequest, "Bad Request", "body field name: value must not be blank")
	return true
}

// started marks the storage call, so the logged duration excludes body decoding.
// md5 has already passed contract validation, so it is safe to echo in details.
func (s *server) respond(w http.ResponseWriter, r *http.Request, status int, md5 string, result api.ThreatResponse, err error, started time.Time) {
	md5 = strings.ToLower(md5)
	switch {
	case err == nil:
		writeJSON(w, status, result)
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "Threat not found", "No threat with MD5 "+md5+" found")
	case errors.Is(err, store.ErrConflict):
		writeError(w, http.StatusConflict, "Threat already exists", "A threat with MD5 "+md5+" already exists")
	default:
		duration := time.Since(started)
		category, sqlstate := storageErrorClass(r.Context(), err)
		s.logger.ErrorContext(r.Context(), "storage operation failed", "method", r.Method,
			"error_category", category, "sqlstate", sqlstate, "duration_ms", float64(duration)/float64(time.Millisecond))
		switch category {
		case "deadline":
			writeError(w, http.StatusServiceUnavailable, "Database operation timed out", "")
		case "canceled":
			writeError(w, http.StatusRequestTimeout, "Request canceled", "")
		default:
			writeJSONBytes(w, http.StatusInternalServerError, internalErrorJSON)
		}
	}
}

const contractMismatch = "Request does not match the OpenAPI contract"

// validationDetails names the rejected field and rule. kin-openapi keeps submitted
// values out of reasons; unknown property names come from the client, so they are
// not echoed, and long patterns are omitted to keep the message readable.
func validationDetails(err error) string {
	var schemaErr *openapi3.SchemaError
	if !errors.As(err, &schemaErr) {
		return contractMismatch
	}
	reason := schemaErr.Reason
	switch schemaErr.SchemaField {
	case "properties": // reported only for a property the schema does not define.
		reason = "unknown properties are not allowed"
	case "pattern":
		reason = "value does not match the required format"
		if pattern := schemaErr.Schema.Pattern; len(pattern) <= 64 {
			reason += " " + strconv.Quote(pattern)
		}
	}
	location := "body"
	var requestErr *openapi3filter.RequestError
	if errors.As(err, &requestErr) && requestErr.Parameter != nil {
		location = requestErr.Parameter.In + " parameter " + requestErr.Parameter.Name
	}
	if pointer := schemaErr.JSONPointer(); len(pointer) > 0 {
		location += " field " + strings.Join(pointer, ".")
	}
	return location + ": " + reason
}

// internalErrorJSON is also the fallback when a response cannot be encoded.
var internalErrorJSON = errorJSON("Internal server error")

// errorJSON encodes a fixed error body once, for responses repeated on every rejection.
func errorJSON(message string) []byte {
	body, err := json.Marshal(api.ErrorResponse{Message: message})
	if err != nil {
		panic(err) // a struct of strings always encodes.
	}
	return append(body, '\n')
}

func writeError(w http.ResponseWriter, status int, message, details string) {
	response := api.ErrorResponse{Message: message}
	if details != "" {
		response.Details = &details
	}
	writeJSON(w, status, response)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	body, err := json.Marshal(value)
	if err != nil {
		writeJSONBytes(w, http.StatusInternalServerError, internalErrorJSON)
		return
	}
	writeJSONBytes(w, status, append(body, '\n'))
}

func writeJSONBytes(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// a failed write means the client disconnected; a second response cannot be written.
	_, _ = w.Write(body)
}
