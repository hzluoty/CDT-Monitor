package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestVercelHandlerServesHealthAndInitStatus(t *testing.T) {
	resetServer()
	dbPath := filepath.Join(t.TempDir(), "vercel-test.sqlite")
	t.Cleanup(resetServer)
	t.Setenv("CDT_MASTER_KEY", "0123456789abcdef0123456789abcdef")
	t.Setenv("CDT_DATABASE_URL", dbPath)
	t.Setenv("VERCEL_GIT_COMMIT_SHA", "abcdef1234567890")

	healthReq := httptest.NewRequest(http.MethodGet, "https://cdt.vercel.app/healthz", nil)
	healthResp := httptest.NewRecorder()
	Handler(healthResp, healthReq)
	if healthResp.Code != http.StatusOK {
		t.Fatalf("healthz status = %d, body = %s", healthResp.Code, healthResp.Body.String())
	}

	initReq := httptest.NewRequest(http.MethodGet, "https://cdt.vercel.app/api/v1/system/init-status", nil)
	initResp := httptest.NewRecorder()
	Handler(initResp, initReq)
	if initResp.Code != http.StatusOK {
		t.Fatalf("init-status status = %d, body = %s", initResp.Code, initResp.Body.String())
	}
	var payload struct {
		Initialized bool `json:"initialized"`
	}
	if err := json.Unmarshal(initResp.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Initialized {
		t.Fatal("expected uninitialized database on fresh startup")
	}
}
