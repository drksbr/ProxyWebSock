package relay

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
)

type updateArtifact struct {
	GOOS    string
	GOARCH  string
	Path    string
	Version string
	SHA256  string
}

type dashboardDownloadTarget struct {
	GOOS   string
	GOARCH string
	Label  string
}

var dashboardDownloadTargets = []dashboardDownloadTarget{
	{GOOS: "linux", GOARCH: "amd64", Label: "Linux x86_64"},
	{GOOS: "linux", GOARCH: "arm64", Label: "Linux ARM64"},
	{GOOS: "darwin", GOARCH: "arm64", Label: "macOS Apple Silicon"},
	{GOOS: "windows", GOARCH: "amd64", Label: "Windows x86_64"},
}

func (s *relayServer) handleUpdates(w http.ResponseWriter, r *http.Request) {
	cleanPath := path.Clean("/" + strings.TrimPrefix(r.URL.Path, "/updates/"))
	switch {
	case cleanPath == "/agent/manifest":
		s.handleAgentUpdateManifest(w, r)
	case strings.HasPrefix(cleanPath, "/manifest-") && strings.HasSuffix(cleanPath, ".json"):
		s.handlePublicUpdateManifest(w, r, path.Base(cleanPath))
	case strings.HasPrefix(cleanPath, "/bin/"):
		s.handleUpdateBinary(w, r, cleanPath)
	default:
		http.NotFound(w, r)
	}
}

func (s *relayServer) handleDashboardDownloads(w http.ResponseWriter, r *http.Request) {
	cleanPath := path.Clean("/" + strings.TrimPrefix(r.URL.Path, "/downloads/"))
	goos, goarch, ok := parseDashboardDownloadPath(cleanPath)
	if !ok {
		http.NotFound(w, r)
		return
	}
	artifact, err := s.resolveUpdateArtifact("", goos, goarch)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			http.NotFound(w, r)
			return
		}
		s.logger.Warn("dashboard download resolve failed", "goos", goos, "goarch", goarch, "error", err)
		http.Error(w, "dashboard download error", http.StatusInternalServerError)
		return
	}
	if err := serveZippedArtifact(w, artifact); err != nil {
		s.logger.Warn("dashboard zip failed", "goos", goos, "goarch", goarch, "error", err)
	}
}

func (s *relayServer) handlePublicUpdateManifest(w http.ResponseWriter, r *http.Request, name string) {
	goos, goarch, ok := parseManifestName(name)
	if !ok {
		http.NotFound(w, r)
		return
	}
	artifact, err := s.resolveUpdateArtifact("", goos, goarch)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			http.NotFound(w, r)
			return
		}
		s.logger.Warn("update manifest resolve failed", "goos", goos, "goarch", goarch, "error", err)
		http.Error(w, "update manifest error", http.StatusInternalServerError)
		return
	}
	s.writeUpdateManifest(w, r, artifact)
}

func (s *relayServer) handleAgentUpdateManifest(w http.ResponseWriter, r *http.Request) {
	agentID, token, ok := r.BasicAuth()
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="intratun-agent-update", charset="UTF-8"`)
		http.Error(w, "agent auth required", http.StatusUnauthorized)
		return
	}
	if _, valid := s.authenticateAgent(agentID, token); !valid {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	goos := strings.TrimSpace(r.Header.Get("X-Intratun-GOOS"))
	goarch := strings.TrimSpace(r.Header.Get("X-Intratun-GOARCH"))
	versionText := strings.TrimSpace(r.Header.Get("X-Intratun-Version"))
	if s.updateManager != nil {
		s.updateManager.observeRuntime(agentID, versionText, goos, goarch)
	}

	status := agentDeploymentStatus{}
	if s.updateManager != nil {
		status = s.updateManager.deploymentStatus(agentID, goos, goarch)
	}
	if status.GOOS != "" {
		goos = status.GOOS
	}
	if status.GOARCH != "" {
		goarch = status.GOARCH
	}
	if goos == "" || goarch == "" {
		http.Error(w, "missing agent platform headers", http.StatusBadRequest)
		return
	}

	artifact, err := s.resolveUpdateArtifact(status.DesiredVersion, goos, goarch)
	if err != nil {
		switch {
		case errors.Is(err, os.ErrNotExist):
			http.Error(w, "requested deployment artifact not found", http.StatusConflict)
		default:
			s.logger.Warn("agent manifest resolve failed", "agent", agentID, "goos", goos, "goarch", goarch, "target_version", status.DesiredVersion, "error", err)
			http.Error(w, "agent manifest error", http.StatusInternalServerError)
		}
		return
	}
	s.writeUpdateManifest(w, r, artifact)
}

func (s *relayServer) writeUpdateManifest(w http.ResponseWriter, r *http.Request, artifact *updateArtifact) {
	if artifact == nil {
		http.Error(w, "artifact not found", http.StatusNotFound)
		return
	}
	payload := struct {
		Version string `json:"version"`
		URL     string `json:"url"`
		SHA256  string `json:"sha256"`
	}{
		Version: artifact.Version,
		URL:     s.externalUpdateURL(r, fmt.Sprintf("/updates/bin/%s/%s/%s", artifact.Version, artifact.GOOS, artifact.GOARCH)),
		SHA256:  artifact.SHA256,
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		s.logger.Warn("update manifest encode failed", "error", err)
	}
}

func (s *relayServer) handleUpdateBinary(w http.ResponseWriter, r *http.Request, cleanPath string) {
	versionText, goos, goarch, ok := parseBinaryPath(cleanPath)
	if !ok {
		http.NotFound(w, r)
		return
	}
	artifact, err := s.resolveUpdateArtifact(versionText, goos, goarch)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			http.NotFound(w, r)
			return
		}
		s.logger.Warn("update binary resolve failed", "goos", goos, "goarch", goarch, "version", versionText, "error", err)
		http.Error(w, "update binary error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Intratun-Version", artifact.Version)
	w.Header().Set("X-Intratun-Sha256", artifact.SHA256)
	http.ServeFile(w, r, artifact.Path)
}

func (s *relayServer) resolveUpdateArtifact(versionText, goos, goarch string) (*updateArtifact, error) {
	if s.updateManager == nil {
		return nil, errors.New("update manager unavailable")
	}
	return s.updateManager.resolveArtifact(versionText, goos, goarch)
}

func (s *relayServer) availableDashboardDownloads(r *http.Request) []statusDownload {
	downloads := make([]statusDownload, 0, len(dashboardDownloadTargets))
	for _, target := range dashboardDownloadTargets {
		artifact, err := s.resolveUpdateArtifact("", target.GOOS, target.GOARCH)
		if err != nil {
			continue
		}
		downloads = append(downloads, statusDownload{
			Label:    target.Label,
			GOOS:     artifact.GOOS,
			GOARCH:   artifact.GOARCH,
			URL:      s.dashboardDownloadURL(r, artifact.GOOS, artifact.GOARCH),
			FileName: dashboardArchiveName(artifact),
			Version:  artifact.Version,
		})
	}
	return downloads
}

func parseManifestName(name string) (string, string, bool) {
	if !strings.HasPrefix(name, "manifest-") || !strings.HasSuffix(name, ".json") {
		return "", "", false
	}
	base := strings.TrimSuffix(strings.TrimPrefix(name, "manifest-"), ".json")
	parts := strings.Split(base, "-")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func parseBinaryPath(cleanPath string) (string, string, string, bool) {
	parts := strings.Split(strings.TrimPrefix(cleanPath, "/"), "/")
	switch {
	case len(parts) == 3 && parts[0] == "bin" && parts[1] != "" && parts[2] != "":
		return "", parts[1], parts[2], true
	case len(parts) == 4 && parts[0] == "bin" && parts[1] != "" && parts[2] != "" && parts[3] != "":
		return parts[1], parts[2], parts[3], true
	default:
		return "", "", "", false
	}
}

func parseDashboardDownloadPath(cleanPath string) (string, string, bool) {
	parts := strings.Split(strings.TrimPrefix(cleanPath, "/"), "/")
	if len(parts) != 3 || parts[0] != "agent" || parts[1] == "" || parts[2] == "" {
		return "", "", false
	}
	goarch := strings.TrimSuffix(parts[2], ".zip")
	if goarch == "" || !strings.HasSuffix(parts[2], ".zip") {
		return "", "", false
	}
	return parts[1], goarch, true
}

func (s *relayServer) externalUpdateURL(r *http.Request, pathValue string) string {
	if r == nil {
		return pathValue
	}
	scheme := "https"
	if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); forwarded != "" {
		scheme = strings.Split(forwarded, ",")[0]
	} else if r.TLS == nil {
		scheme = "http"
	}
	return (&url.URL{
		Scheme: scheme,
		Host:   r.Host,
		Path:   pathValue,
	}).String()
}

func (s *relayServer) dashboardDownloadURL(r *http.Request, goos, goarch string) string {
	return s.externalUpdateURL(r, fmt.Sprintf("/downloads/agent/%s/%s.zip", goos, goarch))
}

func dashboardArchiveName(artifact *updateArtifact) string {
	suffix := ""
	if artifact.GOOS == "windows" {
		suffix = ".exe"
	}
	return fmt.Sprintf("intratun-%s-%s%s.zip", artifact.GOOS, artifact.GOARCH, suffix)
}

func serveZippedArtifact(w http.ResponseWriter, artifact *updateArtifact) error {
	info, err := os.Stat(artifact.Path)
	if err != nil {
		return err
	}
	file, err := os.Open(artifact.Path)
	if err != nil {
		return err
	}
	defer file.Close()

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Intratun-Version", artifact.Version)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, dashboardArchiveName(artifact)))

	zipWriter := zip.NewWriter(w)
	defer zipWriter.Close()

	header, err := zip.FileInfoHeader(info)
	if err != nil {
		return err
	}
	header.Name = filepath.Base(artifact.Path)
	header.Method = zip.Deflate

	entry, err := zipWriter.CreateHeader(header)
	if err != nil {
		return err
	}
	_, err = io.Copy(entry, file)
	return err
}

func sha256File(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func dedupeStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}
