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
	"runtime"
	"strings"

	"github.com/drksbr/ProxyWebSock/internal/version"
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
	case strings.HasPrefix(cleanPath, "/manifest-") && strings.HasSuffix(cleanPath, ".json"):
		s.handleUpdateManifest(w, r, path.Base(cleanPath))
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
	artifact, err := s.findUpdateArtifact(goos, goarch)
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

func (s *relayServer) handleUpdateManifest(w http.ResponseWriter, r *http.Request, name string) {
	goos, goarch, ok := parseManifestName(name)
	if !ok {
		http.NotFound(w, r)
		return
	}
	artifact, err := s.resolveUpdateArtifact(goos, goarch)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			http.NotFound(w, r)
			return
		}
		s.logger.Warn("update manifest resolve failed", "goos", goos, "goarch", goarch, "error", err)
		http.Error(w, "update manifest error", http.StatusInternalServerError)
		return
	}

	payload := struct {
		Version string `json:"version"`
		URL     string `json:"url"`
		SHA256  string `json:"sha256"`
	}{
		Version: artifact.Version,
		URL:     s.externalUpdateURL(r, fmt.Sprintf("/updates/bin/%s/%s", goos, goarch)),
		SHA256:  artifact.SHA256,
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		s.logger.Warn("update manifest encode failed", "error", err)
	}
}

func (s *relayServer) handleUpdateBinary(w http.ResponseWriter, r *http.Request, cleanPath string) {
	goos, goarch, ok := parseBinaryPath(cleanPath)
	if !ok {
		http.NotFound(w, r)
		return
	}
	artifact, err := s.resolveUpdateArtifact(goos, goarch)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			http.NotFound(w, r)
			return
		}
		s.logger.Warn("update binary resolve failed", "goos", goos, "goarch", goarch, "error", err)
		http.Error(w, "update binary error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Intratun-Version", artifact.Version)
	w.Header().Set("X-Intratun-Sha256", artifact.SHA256)
	http.ServeFile(w, r, artifact.Path)
}

func (s *relayServer) resolveUpdateArtifact(goos, goarch string) (*updateArtifact, error) {
	artifact, err := s.findUpdateArtifact(goos, goarch)
	if err != nil {
		return nil, err
	}
	sum, err := sha256File(artifact.Path)
	if err != nil {
		return nil, err
	}
	artifact.SHA256 = sum
	return artifact, nil
}

func (s *relayServer) findUpdateArtifact(goos, goarch string) (*updateArtifact, error) {
	candidates := s.updateCandidates(goos, goarch)
	for _, candidate := range candidates {
		info, err := os.Stat(candidate)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, err
		}
		if info.IsDir() {
			continue
		}
		return &updateArtifact{
			GOOS:    goos,
			GOARCH:  goarch,
			Path:    candidate,
			Version: version.Version,
		}, nil
	}
	return nil, os.ErrNotExist
}

func (s *relayServer) availableDashboardDownloads(r *http.Request) []statusDownload {
	downloads := make([]statusDownload, 0, len(dashboardDownloadTargets))
	for _, target := range dashboardDownloadTargets {
		artifact, err := s.findUpdateArtifact(target.GOOS, target.GOARCH)
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

func (s *relayServer) updateCandidates(goos, goarch string) []string {
	suffix := ""
	if goos == "windows" {
		suffix = ".exe"
	}
	candidates := []string{
		filepath.Join(s.updatesDir, fmt.Sprintf("intratun-%s-%s%s", goos, goarch, suffix)),
		filepath.Join(s.updatesDir, fmt.Sprintf("intratun-agent-%s-%s%s", goos, goarch, suffix)),
	}
	if goos == runtime.GOOS && goarch == runtime.GOARCH && s.executablePath != "" {
		candidates = append(candidates, s.executablePath)
	}
	return dedupeStrings(candidates)
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

func parseBinaryPath(cleanPath string) (string, string, bool) {
	parts := strings.Split(strings.TrimPrefix(cleanPath, "/"), "/")
	if len(parts) != 3 || parts[0] != "bin" || parts[1] == "" || parts[2] == "" {
		return "", "", false
	}
	return parts[1], parts[2], true
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
