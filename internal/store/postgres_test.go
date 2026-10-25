package store

import (
	"context"
	"errors"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"threat-exchange/api"
	"threat-exchange/internal/testdb"
)

func TestDefaults(t *testing.T) {
	d, s, k, tags := defaults(nil, nil, nil, nil)
	if d != "" || s != api.SeverityUnknown || k != api.ThreatTypeUnknown || tags == nil || len(tags) != 0 {
		t.Fatal("incorrect omitted field defaults")
	}
	description, severity, kind, labels := "analysis", api.SeverityCritical, api.ThreatTypeRansomware, []string{"windows"}
	d, s, k, tags = defaults(&description, &severity, &kind, &labels)
	if d != description || s != severity || k != kind || !reflect.DeepEqual(tags, labels) {
		t.Fatal("explicit values were not preserved")
	}
}

type failedRow struct{ err error }

func (r failedRow) Scan(...any) error { return r.err }

func TestScanErrors(t *testing.T) {
	duplicate := &pgconn.PgError{Code: "23505"}
	for _, tt := range []struct {
		name        string
		input, want error
	}{
		{"missing", pgx.ErrNoRows, ErrNotFound},
		{"unrelated unique constraint", duplicate, duplicate},
		{"canceled", context.Canceled, context.Canceled},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := scan(failedRow{tt.input})
			if !errors.Is(err, tt.want) {
				t.Fatalf("got %v, want %v", err, tt.want)
			}
		})
	}
}

func TestInvalidDatabaseConfig(t *testing.T) {
	if _, err := Open(context.Background(), "postgres://%zz"); err == nil {
		t.Fatal("accepted malformed database URL")
	}
}

func TestConfiguredPoolAndCreationTime(t *testing.T) {
	isolatedURL, admin := testdb.Isolated(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	parsed, err := url.Parse(isolatedURL)
	if err != nil {
		t.Fatal(err)
	}
	params := parsed.Query()
	params.Set("pool_max_conns", "2")
	parsed.RawQuery = params.Encode()
	schemaID := pgx.Identifier{params.Get("search_path")}.Sanitize()
	repo, err := Open(ctx, parsed.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(repo.Close)
	if repo.pool.Config().MaxConns != 2 {
		t.Fatal("explicit pool size was overwritten")
	}
	// existing tables may retain their original defaults; inserts must use one new timestamp.
	if _, err := admin.Exec(ctx, "ALTER TABLE "+schemaID+".threats "+
		"ALTER COLUMN created_at SET DEFAULT '2000-01-01'::timestamptz, "+
		"ALTER COLUMN updated_at SET DEFAULT '2001-01-01'::timestamptz"); err != nil {
		t.Fatal(err)
	}
	created, err := repo.Create(ctx, api.ThreatCreateRequest{Md5: "d41d8cd98f00b204e9800998ecf8427e", Name: "creation time"})
	if err != nil {
		t.Fatal(err)
	}
	if !created.CreatedAt.Equal(created.UpdatedAt) || created.CreatedAt.IsZero() || created.CreatedAt.Year() == 2000 {
		t.Fatalf("creation timestamps diverged or used obsolete defaults: %+v", created)
	}
}
