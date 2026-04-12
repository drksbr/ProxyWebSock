package relay

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestDashboardAuthDisabledPassThrough(t *testing.T) {
	server := &relayServer{}
	handler := server.dashboardAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected pass-through status 204, got %d", rec.Code)
	}
}

func TestDashboardAuthRejectsInvalidCredentials(t *testing.T) {
	server := &relayServer{
		opts: &relayOptions{
			dashboardUser: "admin",
			dashboardPass: "secret",
		},
	}
	handler := server.dashboardAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth("admin", "wrong")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", rec.Code)
	}
	if header := rec.Header().Get("WWW-Authenticate"); header == "" {
		t.Fatal("expected WWW-Authenticate header")
	}
}

func TestDashboardAuthAcceptsValidCredentials(t *testing.T) {
	server := &relayServer{
		opts: &relayOptions{
			dashboardUser: "admin",
			dashboardPass: "secret",
		},
	}
	handler := server.dashboardAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth("admin", "secret")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected status 204, got %d", rec.Code)
	}
}

func TestAvailableDashboardDownloads(t *testing.T) {
	tempDir := t.TempDir()
	linuxArtifact := filepath.Join(tempDir, "intratun-linux-amd64")
	if err := os.WriteFile(linuxArtifact, []byte("linux-agent"), 0o755); err != nil {
		t.Fatalf("write linux artifact: %v", err)
	}
	windowsArtifact := filepath.Join(tempDir, "intratun-windows-amd64.exe")
	if err := os.WriteFile(windowsArtifact, []byte("windows-agent"), 0o755); err != nil {
		t.Fatalf("write windows artifact: %v", err)
	}

	server := &relayServer{
		logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		updatesDir:     tempDir,
		executablePath: filepath.Join(tempDir, "relay"),
	}
	updateManager, err := newUpdateManager(server.logger, tempDir)
	if err != nil {
		t.Fatalf("new update manager: %v", err)
	}
	server.updateManager = updateManager

	req := httptest.NewRequest(http.MethodGet, "https://relay.example.com/status.json", nil)
	downloads := server.availableDashboardDownloads(req)

	if len(downloads) != 2 {
		t.Fatalf("expected 2 downloads, got %d", len(downloads))
	}
	if downloads[0].URL != "https://relay.example.com/downloads/agent/linux/amd64.zip" {
		t.Fatalf("unexpected linux url: %s", downloads[0].URL)
	}
	if downloads[1].FileName != "intratun-windows-amd64.exe.zip" {
		t.Fatalf("unexpected windows filename: %s", downloads[1].FileName)
	}
}

func TestParseDashboardDownloadPath(t *testing.T) {
	goos, goarch, ok := parseDashboardDownloadPath("/agent/linux/amd64.zip")
	if !ok {
		t.Fatal("expected valid dashboard path")
	}
	if goos != "linux" || goarch != "amd64" {
		t.Fatalf("unexpected parse result: %s %s", goos, goarch)
	}
	if _, _, ok := parseDashboardDownloadPath("/agent/linux/amd64"); ok {
		t.Fatal("expected invalid dashboard path without zip suffix")
	}
}
