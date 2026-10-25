// Package store persists threat records in postgres.
package store

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"threat-exchange/api"
)

// ErrNotFound distinguishes missing records from infrastructure failures.
var ErrNotFound = errors.New("threat not found")

// ErrConflict reports a duplicate canonical md5, including concurrent inserts.
var ErrConflict = errors.New("threat already exists")

//go:embed schema.sql
var schema string

// Postgres owns a concurrency-safe connection pool.
type Postgres struct {
	pool *pgxpool.Pool
}

// Open verifies connectivity and initializes the schema under a transaction lock.
func Open(ctx context.Context, url string) (*Postgres, error) {
	config, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, errors.New("invalid database configuration")
	}
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, errors.New("cannot create database pool")
	}
	if err := initialize(ctx, pool); err != nil {
		pool.Close()
		return nil, fmt.Errorf("initialize database: %w", err)
	}
	return &Postgres{pool: pool}, nil
}

func initialize(ctx context.Context, pool *pgxpool.Pool) error {
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(843741106)"); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, schema)
		return err
	})
}

// Close releases database connections after the http server has drained.
func (p *Postgres) Close() { p.pool.Close() }

// Ping is used by readiness checks and honors the request deadline.
func (p *Postgres) Ping(ctx context.Context) error { return p.pool.Ping(ctx) }

const columns = "md5, name, description, severity, type, tags, created_at, updated_at"

// Get accepts either md5 letter case and returns the canonical record.
func (p *Postgres) Get(ctx context.Context, md5 string) (api.ThreatResponse, error) {
	return scan(p.pool.QueryRow(ctx, "SELECT "+columns+" FROM threats WHERE md5 = $1", strings.ToLower(md5)))
}

// Create relies on the primary key for atomic uniqueness across service instances.
func (p *Postgres) Create(ctx context.Context, request api.ThreatCreateRequest) (api.ThreatResponse, error) {
	description, severity, kind, tags := defaults(request.Description, request.Severity, request.Type, request.Tags)
	result, err := scan(p.pool.QueryRow(ctx,
		"INSERT INTO threats ("+columns+") "+
			"VALUES ($1, $2, $3, $4, $5, $6, statement_timestamp(), statement_timestamp()) ON CONFLICT (md5) DO NOTHING RETURNING "+columns,
		strings.ToLower(request.Md5), strings.TrimSpace(request.Name), description, severity, kind, tags))
	if errors.Is(err, ErrNotFound) {
		return api.ThreatResponse{}, ErrConflict
	}
	return result, err
}

// Update replaces writable fields and preserves md5 and the original creation time.
func (p *Postgres) Update(ctx context.Context, md5 string, request api.ThreatUpdateRequest) (api.ThreatResponse, error) {
	description, severity, kind, tags := defaults(request.Description, request.Severity, request.Type, request.Tags)
	return scan(p.pool.QueryRow(ctx,
		"UPDATE threats SET name=$2, description=$3, severity=$4, type=$5, tags=$6, "+
			"updated_at=GREATEST(clock_timestamp(), updated_at) WHERE md5=$1 RETURNING "+columns,
		strings.ToLower(md5), strings.TrimSpace(request.Name), description, severity, kind, tags))
}

func scan(row pgx.Row) (api.ThreatResponse, error) {
	var result api.ThreatResponse
	err := row.Scan(&result.Md5, &result.Name, &result.Description, &result.Severity,
		&result.Type, &result.Tags, &result.CreatedAt, &result.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return api.ThreatResponse{}, ErrNotFound
	}
	if err != nil {
		return api.ThreatResponse{}, fmt.Errorf("query threat: %w", err)
	}
	result.CreatedAt = result.CreatedAt.UTC()
	result.UpdatedAt = result.UpdatedAt.UTC()
	return result, nil
}

func defaults(description *string, severity *api.Severity, kind *api.ThreatType, tags *[]string) (string, api.Severity, api.ThreatType, []string) {
	d, s, k, t := "", api.SeverityUnknown, api.ThreatTypeUnknown, []string{}
	if description != nil {
		d = *description
	}
	if severity != nil {
		s = *severity
	}
	if kind != nil {
		k = *kind
	}
	if tags != nil {
		t = *tags
	}
	return d, s, k, t
}
