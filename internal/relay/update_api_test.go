package relay

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/drksbr/ProxyWebSock/internal/controlplane"
)

func TestAgentUpdateManifestUsesPinnedDeployment(t *testing.T) {
	tempDir := t.TempDir()
	oldVersion := "0.1.0+build.10.aaaa"
	newVersion := "0.2.0+build.20.bbbb"
	writeReleaseArtifact(t, tempDir, oldVersion, "windows", "amd64", []byte("old"))
	writeReleaseArtifact(t, tempDir, newVersion, "windows", "amd64", []byte("new"))

	server := newTestUpdateServer(t, tempDir)
	if err := server.updateManager.setPinnedTarget("agente01", "windows", "amd64", oldVersion); err != nil {
		t.Fatalf("set pinned target: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "https://relay.example.com/updates/agent/manifest", nil)
	req.SetBasicAuth("agente01", "secret")
	req.Header.Set("X-Intratun-GOOS", "windows")
	req.Header.Set("X-Intratun-GOARCH", "amd64")
	req.Header.Set("X-Intratun-Version", newVersion)
	rec := httptest.NewRecorder()

	server.handleUpdates(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var payload struct {
		Version string `json:"version"`
		URL     string `json:"url"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	if payload.Version != oldVersion {
		t.Fatalf("unexpected manifest version: %s", payload.Version)
	}
	if !strings.Contains(payload.URL, "/updates/bin/"+oldVersion+"/windows/amd64") {
		t.Fatalf("unexpected manifest url: %s", payload.URL)
	}
}

func TestAgentDeploymentAPIResetsToLatest(t *testing.T) {
	tempDir := t.TempDir()
	oldVersion := "0.1.0+build.10.aaaa"
	newVersion := "0.2.0+build.20.bbbb"
	writeReleaseArtifact(t, tempDir, oldVersion, "windows", "amd64", []byte("old"))
	writeReleaseArtifact(t, tempDir, newVersion, "windows", "amd64", []byte("new"))

	server := newTestUpdateServer(t, tempDir)
	if err := server.updateManager.setPinnedTarget("agente01", "windows", "amd64", oldVersion); err != nil {
		t.Fatalf("set pinned target: %v", err)
	}

	body := strings.NewReader(`{"version":"","goos":"windows","goarch":"amd64","forceCheck":false}`)
	req := httptest.NewRequest(http.MethodPost, "/api/agents/agente01/deployment", body)
	rec := httptest.NewRecorder()

	server.handleAgentDeploymentAPI(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var payload agentDeploymentResponse
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Track != "latest" {
		t.Fatalf("unexpected track: %s", payload.Track)
	}
	if payload.DesiredVersion != newVersion {
		t.Fatalf("unexpected desired version: %s", payload.DesiredVersion)
	}
	events, err := server.control.ListAuditEvents(req.Context(), 10)
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	if len(events) != 1 || events[0].Category != "deployment" {
		t.Fatalf("unexpected audit events: %+v", events)
	}
}

func newTestUpdateServer(t *testing.T, updatesDir string) *relayServer {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	updateManager, err := newUpdateManager(logger, updatesDir)
	if err != nil {
		t.Fatalf("new update manager: %v", err)
	}
	return &relayServer{
		logger: logger,
		agentDirectory: map[string]*agentRecord{
			"agente01": {
				Login:    "agente01",
				Password: "secret",
			},
		},
		control:       controlplane.NewMemoryStore(),
		updateManager: updateManager,
	}
}

func writeReleaseArtifact(t *testing.T, rootDir, versionText, goos, goarch string, contents []byte) {
	t.Helper()
	releaseDir := filepath.Join(rootDir, versionText)
	if err := os.MkdirAll(releaseDir, 0o755); err != nil {
		t.Fatalf("mkdir release dir: %v", err)
	}
	name := "intratun-" + goos + "-" + goarch
	if goos == "windows" {
		name += ".exe"
	}
	if err := os.WriteFile(filepath.Join(releaseDir, name), contents, 0o755); err != nil {
		t.Fatalf("write release artifact: %v", err)
	}
}
