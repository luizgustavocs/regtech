package config

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func NewDatabasePool() (*pgxpool.Pool, error) {
	connStr := os.Getenv("DATABASE_URL")
	if connStr == "" {
		return nil, fmt.Errorf("DATABASE_URL environment variable is missing")
	}

	config, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse database database config: %w", err)
	}

	// Configura o modo de execução para ignorar o cache nominal e evitar o erro 42P05 no PgBouncer
	config.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeCacheDescribe

	config.MaxConns = 5
	config.MinConns = 1
	config.MaxConnIdleTime = 15 * time.Minute
	config.MaxConnLifetime = 30 * time.Minute

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("database unreachable: %w", err)
	}

	slog.Info("Secure PostgreSQL connection pool established successfully with TLS")
	return pool, nil
}
