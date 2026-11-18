package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "github.com/tursodatabase/libsql-client-go/libsql"
	"handler/internal/security"
	_ "modernc.org/sqlite"
)

type Store struct {
	db      *sql.DB
	cipher  *security.Cipher
	dataDir string
}

func Open(dataDir string) (*Store, error) {
	driver, dsn, externalDSN := resolveDatabaseConfig(dataDir)
	if !externalDSN {
		if err := os.MkdirAll(dataDir, 0o750); err != nil {
			return nil, fmt.Errorf("create data directory: %w", err)
		}
	}
	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", driver, err)
	}
	if driver == "sqlite" {
		db.SetMaxOpenConns(1)
		db.SetMaxIdleConns(1)
		for _, pragma := range []string{
			"PRAGMA journal_mode=WAL",
			"PRAGMA synchronous=NORMAL",
			"PRAGMA busy_timeout=5000",
			"PRAGMA foreign_keys=ON",
		} {
			if _, err = db.Exec(pragma); err != nil {
				db.Close()
				return nil, fmt.Errorf("configure sqlite: %w", err)
			}
		}
	} else {
		installLibSQLRetryTransport()
		db.SetMaxOpenConns(4)
		db.SetMaxIdleConns(0)
	}

	var cipher *security.Cipher
	if !externalDSN || security.HasEnvMasterKey() {
		cipher, err = security.LoadOrCreateCipher(dataDir)
		if err != nil {
			db.Close()
			return nil, err
		}
	}

	s := &Store{db: db, cipher: cipher, dataDir: dataDir}
	ctx := context.Background()
	alreadyMigrated := s.isSchemaCurrent(ctx)
	if !alreadyMigrated {
		if err = s.Migrate(ctx); err != nil {
			db.Close()
			return nil, err
		}
	}
	if s.cipher == nil {
		cipher, err = s.loadOrCreateDBMasterKey(ctx)
		if err != nil {
			db.Close()
			return nil, err
		}
		s.cipher = cipher
	}
	if !alreadyMigrated {
		if err = s.migratePlaintextSecrets(ctx); err != nil {
			db.Close()
			return nil, err
		}
		_, _ = s.db.ExecContext(ctx, `INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES(2, unixepoch())`)
	}
	if err = s.recoverInterruptedWork(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) isSchemaCurrent(ctx context.Context) bool {
	var version int
	err := s.db.QueryRowContext(ctx, `SELECT version FROM schema_migrations WHERE version=2`).Scan(&version)
	return err == nil && version == 2
}

func (s *Store) loadOrCreateDBMasterKey(ctx context.Context) (*security.Cipher, error) {
	var stored string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key='system_master_key'`).Scan(&stored)
	if errors.Is(err, sql.ErrNoRows) || strings.TrimSpace(stored) == "" {
		generated, genErr := security.GenerateMasterKey()
		if genErr != nil {
			return nil, genErr
		}
		if _, execErr := s.db.ExecContext(ctx, `INSERT INTO settings(key,value) VALUES('system_master_key',?) ON CONFLICT(key) DO NOTHING`, generated); execErr != nil {
			return nil, fmt.Errorf("persist database master key: %w", execErr)
		}
		if err = s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key='system_master_key'`).Scan(&stored); err != nil {
			return nil, fmt.Errorf("load database master key: %w", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("query database master key: %w", err)
	}
	return security.NewCipherFromKey(stored)
}

func resolveDatabaseConfig(dataDir string) (driver string, dsn string, externalDSN bool) {
	rawURL := strings.TrimSpace(os.Getenv("CDT_DATABASE_URL"))
	if rawURL == "" {
		rawURL = strings.TrimSpace(os.Getenv("TURSO_DATABASE_URL"))
	}
	if rawURL == "" {
		return "sqlite", filepath.Join(dataDir, "data.sqlite"), false
	}
	token := strings.TrimSpace(os.Getenv("CDT_DATABASE_AUTH_TOKEN"))
	if token == "" {
		token = strings.TrimSpace(os.Getenv("TURSO_AUTH_TOKEN"))
	}
	if token != "" && !strings.Contains(rawURL, "authToken=") {
		sep := "?"
		if strings.Contains(rawURL, "?") {
			sep = "&"
		}
		rawURL = rawURL + sep + "authToken=" + url.QueryEscape(token)
	}
	lower := strings.ToLower(rawURL)
	for _, prefix := range []string{"libsql://", "https://", "http://", "wss://", "ws://"} {
		if strings.HasPrefix(lower, prefix) {
			return "libsql", rawURL, true
		}
	}
	return "sqlite", rawURL, true
}

var libsqlTransportOnce sync.Once

type libsqlRetryTransport struct {
	base http.RoundTripper
}

func (t *libsqlRetryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil && req.GetBody != nil && strings.HasSuffix(req.URL.Path, "/v2/pipeline") && isTransientEOF(err) {
		if body, bodyErr := req.GetBody(); bodyErr == nil {
			cloned := req.Clone(req.Context())
			cloned.Body = body
			cloned.Close = true
			return t.base.RoundTrip(cloned)
		}
	}
	return resp, err
}

func isTransientEOF(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "EOF") || strings.Contains(msg, "connection reset") || strings.Contains(msg, "broken pipe")
}

func installLibSQLRetryTransport() {
	libsqlTransportOnce.Do(func() {
		base := http.DefaultClient.Transport
		if base == nil {
			if dt, ok := http.DefaultTransport.(*http.Transport); ok {
				cloned := dt.Clone()
				cloned.IdleConnTimeout = 10 * time.Second
				base = cloned
			} else {
				base = http.DefaultTransport
			}
		}
		http.DefaultClient.Transport = &libsqlRetryTransport{base: base}
	})
}

func execStatements(ctx context.Context, db *sql.DB, script string) error {
	for _, stmt := range splitSQLStatements(script) {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

func splitSQLStatements(script string) []string {
	var stmts []string
	var current strings.Builder
	var inSingle, inDouble bool
	for i := 0; i < len(script); i++ {
		ch := script[i]
		switch {
		case ch == '\'' && !inDouble:
			if inSingle && i+1 < len(script) && script[i+1] == '\'' {
				current.WriteByte(ch)
				i++
			} else {
				inSingle = !inSingle
			}
			current.WriteByte(ch)
		case ch == '"' && !inSingle:
			inDouble = !inDouble
			current.WriteByte(ch)
		case ch == ';' && !inSingle && !inDouble:
			if trimmed := strings.TrimSpace(current.String()); trimmed != "" {
				stmts = append(stmts, trimmed)
			}
			current.Reset()
		default:
			current.WriteByte(ch)
		}
	}
	if trimmed := strings.TrimSpace(current.String()); trimmed != "" {
		stmts = append(stmts, trimmed)
	}
	return stmts
}

func (s *Store) recoverInterruptedWork(ctx context.Context) error {
	return execStatements(ctx, s.db, `
UPDATE jobs SET status='queued', locked_at=0, available_at=unixepoch(), updated_at=unixepoch()
WHERE status='running' AND locked_at < unixepoch()-120;
UPDATE notification_outbox SET status='queued', available_at=unixepoch(), updated_at=unixepoch()
WHERE status='sending' AND updated_at < unixepoch()-120;
`)
}

func (s *Store) Close() error { return s.db.Close() }
func (s *Store) DB() *sql.DB  { return s.db }

func (s *Store) Ready(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return s.db.PingContext(ctx)
}

func (s *Store) WithTx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err = fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func (s *Store) Encrypt(value string) (string, error) { return s.cipher.Encrypt(value) }
func (s *Store) Decrypt(value string) (string, error) { return s.cipher.Decrypt(value) }

func nullTime(unix sql.NullInt64) *time.Time {
	if !unix.Valid || unix.Int64 <= 0 {
		return nil
	}
	t := time.Unix(unix.Int64, 0).UTC()
	return &t
}

func isNotFound(err error) bool { return errors.Is(err, sql.ErrNoRows) }
