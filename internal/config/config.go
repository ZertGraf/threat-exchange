// Package config loads and validates process configuration without logging secrets.
package config

import (
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"
)

// defaults applied when the corresponding variable is unset or empty.
const (
	DefaultHTTPAddr  = "127.0.0.1:8080"
	DefaultRateRPS   = 100
	DefaultRateBurst = 200
)

// Config contains startup-only settings; a restart is required to rotate a key.
type Config struct {
	HTTPAddr    string
	DatabaseURL string
	APIKey      string
	TLSCertFile string
	TLSKeyFile  string
	RateRPS     float64
	RateBurst   int
}

// Load rejects partial tls settings and ambiguous secret sources.
func Load() (Config, error) {
	c := Config{HTTPAddr: DefaultHTTPAddr, RateRPS: DefaultRateRPS, RateBurst: DefaultRateBurst}
	if value := os.Getenv("HTTP_ADDR"); value != "" {
		c.HTTPAddr = value
	}
	_, port, err := net.SplitHostPort(c.HTTPAddr)
	if err != nil {
		return c, errors.New("HTTP_ADDR must be host:port")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return c, errors.New("HTTP_ADDR must have a port between 1 and 65535")
	}
	c.DatabaseURL, _, err = secret("DATABASE_URL")
	if err != nil {
		return c, err
	}
	if c.DatabaseURL == "" {
		return c, errors.New("DATABASE_URL or DATABASE_URL_FILE is required")
	}
	var keySource string
	c.APIKey, keySource, err = secret("API_KEY")
	if err != nil {
		return c, err
	}
	if c.APIKey != "" && len(c.APIKey) < 32 {
		return c, errors.New("API_KEY must contain at least 32 bytes")
	}
	if !headerSafe(c.APIKey) {
		// the value itself is never echoed: it may be a nearly correct secret.
		return c, fmt.Errorf("%s must contain only printable ASCII characters, spaces, or tabs", keySource)
	}
	c.TLSCertFile, c.TLSKeyFile = os.Getenv("TLS_CERT_FILE"), os.Getenv("TLS_KEY_FILE")
	if (c.TLSCertFile == "") != (c.TLSKeyFile == "") {
		return c, errors.New("TLS_CERT_FILE and TLS_KEY_FILE must be set together")
	}
	if value := os.Getenv("RATE_LIMIT_RPS"); value != "" {
		c.RateRPS, err = strconv.ParseFloat(value, 64)
		if err != nil || math.IsNaN(c.RateRPS) || math.IsInf(c.RateRPS, 0) || c.RateRPS <= 0 {
			return c, errors.New("RATE_LIMIT_RPS must be a finite positive number")
		}
	}
	if value := os.Getenv("RATE_LIMIT_BURST"); value != "" {
		c.RateBurst, err = strconv.Atoi(value)
		if err != nil || c.RateBurst <= 0 {
			return c, errors.New("RATE_LIMIT_BURST must be a positive integer")
		}
	}
	return c, nil
}

// secret also reports which variable supplied the value, for error messages.
func secret(name string) (value, source string, err error) {
	value, file := os.Getenv(name), os.Getenv(name+"_FILE")
	if value != "" && file != "" {
		return "", "", fmt.Errorf("set only one of %s and %s_FILE", name, name)
	}
	source = name
	if file != "" {
		data, err := os.ReadFile(file)
		if err != nil {
			return "", "", fmt.Errorf("cannot read %s_FILE", name)
		}
		value, source = string(data), name+"_FILE"
	} else if value == "" {
		return "", source, nil
	}
	if !utf8.ValidString(value) {
		return "", "", fmt.Errorf("%s must contain UTF-8", source)
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return "", "", fmt.Errorf("%s is empty", source)
	}
	return value, source, nil
}

// headerSafe accepts values every http client can send unchanged in a header field:
// visible US-ASCII with inner spaces or tabs (RFC 9110 field-content without obs-text).
func headerSafe(value string) bool {
	for i := 0; i < len(value); i++ {
		if c := value[i]; (c < ' ' && c != '\t') || c > '~' {
			return false
		}
	}
	return true
}
