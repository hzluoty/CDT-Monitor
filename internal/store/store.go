package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/tursodatabase/libsql-client-go/libsql"
	"github.com/hzluoty/CDT-Monitor/internal/security"
	_ "modernc.org/sqlite"
)

type Store struct {
	db      *sql.DB
	cipher  *security.Cipher
	dataDir string
}

func Open(dataDir string) (*Store, error) {
	driver, dsn, externalDSN := resolveDatabaseConfig(dataDir)
	if !externalDSN || !security.HasEnvMasterKey() {
		if err := os.MkdirAll(dataDir, 0o750); err != nil {
			return nil, fmt.Errorf("create data directory: %w", err)
		}
	}
	cipher, err := security.LoadOrCreateCipher(dataDir)
	if err != nil {
		return nil, err
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
	}
	s := &Store{db: db, cipher: cipher, dataDir: dataDir}
	if err = s.Migrate(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	if err = s.migratePlaintextSecrets(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	if err = s.recoverInterruptedWork(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
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
