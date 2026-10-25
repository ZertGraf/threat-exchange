// Package testdb provisions disposable PostgreSQL schemas for integration tests.
package testdb

import (
	"context"
	"crypto/rand"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// Isolated creates a random private schema and drops only that schema at cleanup.
// It returns a URL whose search_path selects the schema, and the admin connection
// that owns it; the test is skipped when TEST_DATABASE_URL is unset.
func Isolated(t testing.TB) (string, *pgx.Conn) {
	t.Helper()
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("set TEST_DATABASE_URL to run real PostgreSQL integration tests")
	}
	parsed, err := url.Parse(databaseURL)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") {
		t.Fatal("TEST_DATABASE_URL must be a PostgreSQL URI")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schemaName := "test_" + strings.ToLower(rand.Text())
	identifier := pgx.Identifier{schemaName}.Sanitize()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := admin.Exec(ctx, "DROP SCHEMA IF EXISTS "+identifier+" CASCADE"); err != nil {
			t.Error(err)
		}
		if err := admin.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	query.Set("search_path", schemaName)
	parsed.RawQuery = query.Encode()
	return parsed.String(), admin
}
