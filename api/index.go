package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	_ "time/tzdata"

	"handler/internal/aliyun"
	"handler/internal/engine"
	"handler/internal/httpapi"
	"handler/internal/notify"
	"handler/internal/store"
	"handler/internal/web"
)

var (
	mu          sync.Mutex
	server      *httpapi.Server
	activeStore *store.Store
)

func resetServer() {
	mu.Lock()
	defer mu.Unlock()
	if activeStore != nil {
		_ = activeStore.Close()
		activeStore = nil
	}
	server = nil
}

func getServer() (*httpapi.Server, error) {
	mu.Lock()
	defer mu.Unlock()
	if server != nil {
		return server, nil
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	dataDir := strings.TrimSpace(os.Getenv("CDT_DATA_DIR"))
	if dataDir == "" {
		dataDir = filepath.Join(os.TempDir(), "cdt-monitor")
	}
	workers := 4
	if raw := strings.TrimSpace(os.Getenv("CDT_WORKERS")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			workers = parsed
		}
	}
	st, err := store.Open(dataDir)
	if err != nil {
		return nil, err
	}
	eng := engine.New(st, aliyun.NewClient(), notify.New(), logger, workers)
	commit := strings.TrimSpace(os.Getenv("VERCEL_GIT_COMMIT_SHA"))
	if len(commit) > 7 {
		commit = commit[:7]
	}
	if commit == "" {
		commit = "vercel"
	}
	version := strings.TrimSpace(os.Getenv("CDT_VERSION"))
	if version == "" {
		version = "serverless"
	}
	srv := httpapi.New(st, eng, web.FS(), logger, httpapi.BuildInfo{
		Version: version,
		Commit:  commit,
		BuiltAt: "vercel",
	})
	srv.SetSyncDrain(true)
	activeStore = st
	server = srv
	return server, nil
}

func Handler(w http.ResponseWriter, r *http.Request) {
	srv, err := getServer()
	if err != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]string{
				"code":    "serverless_init_failed",
				"message": err.Error(),
			},
		})
		return
	}
	srv.Handler().ServeHTTP(w, r)
}
