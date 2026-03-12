package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/drksbr/ProxyWebSock/internal/version"
)

type updateManifest struct {
	Version string `json:"version"`
	URL     string `json:"url"`
	SHA256  string `json:"sha256"`
}

type parsedVersion struct {
	major    int
	minor    int
	patch    int
	build    int
	hasBuild bool
}

func (a *agent) autoUpdateLoop(ctx context.Context) {
	if a.opts.updateParsedURL == nil {
		return
	}
	if !selfUpdateSupported() {
		a.logger.Warn("automatic agent updates are not supported on this platform", "goos", runtime.GOOS, "goarch", runtime.GOARCH)
		return
	}
	a.checkForUpdate(ctx)

	ticker := time.NewTicker(a.opts.updateInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.checkForUpdate(ctx)
		}
	}
}

func (a *agent) checkForUpdate(ctx context.Context) {
	a.update.Lock()
	defer a.update.Unlock()

	manifest, err := a.fetchUpdateManifest(ctx)
	if err != nil {
		a.logger.Debug("update check failed", "error", err)
		return
	}
	if !shouldUpdateVersion(version.Version, manifest.Version) {
		return
	}
	if err := a.applyUpdate(ctx, manifest); err != nil {
		a.logger.Warn("automatic update failed", "target_version", manifest.Version, "error", err)
	}
}

func (a *agent) fetchUpdateManifest(ctx context.Context) (*updateManifest, error) {
	manifestURL := a.opts.updateParsedURL
	if manifestURL == nil {
		return nil, errors.New("update manifest url not configured")
	}
	checkCtx, cancel := context.WithTimeout(ctx, a.opts.updateTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(checkCtx, http.MethodGet, manifestURL.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", fmt.Sprintf("intratun-agent/%s", version.Version))

	client := &http.Client{Timeout: a.opts.updateTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("manifest http status %d", resp.StatusCode)
	}

	var manifest updateManifest
	if err := json.NewDecoder(resp.Body).Decode(&manifest); err != nil {
		return nil, fmt.Errorf("decode manifest: %w", err)
	}
	manifest.Version = strings.TrimSpace(manifest.Version)
	manifest.URL = strings.TrimSpace(manifest.URL)
	manifest.SHA256 = strings.ToLower(strings.TrimSpace(manifest.SHA256))
	if manifest.Version == "" {
		return nil, errors.New("manifest missing version")
	}
	if manifest.URL == "" {
		return nil, errors.New("manifest missing url")
	}
	if manifest.SHA256 == "" {
		return nil, errors.New("manifest missing sha256")
	}
	return &manifest, nil
}

func (a *agent) applyUpdate(ctx context.Context, manifest *updateManifest) error {
	if manifest == nil {
		return errors.New("nil manifest")
	}
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable path: %w", err)
	}
	downloadURL, err := resolveDownloadURL(a.opts.updateParsedURL, manifest.URL)
	if err != nil {
		return err
	}

	checkCtx, cancel := context.WithTimeout(ctx, a.opts.updateTimeout)
	defer cancel()

	tempPath, err := a.downloadUpdatedBinary(checkCtx, downloadURL, exePath, manifest.SHA256)
	if err != nil {
		return err
	}
	defer func() {
		_ = os.Remove(tempPath)
	}()

	a.logger.Info("applying agent update", "from", version.Version, "to", manifest.Version, "url", downloadURL.String())
	if err := swapExecutable(exePath, tempPath); err != nil {
		return fmt.Errorf("replace executable: %w", err)
	}
	if err := restartExecutable(exePath); err != nil {
		return fmt.Errorf("restart updated executable: %w", err)
	}
	return nil
}

func (a *agent) downloadUpdatedBinary(ctx context.Context, downloadURL *url.URL, exePath, expectedSHA string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", fmt.Sprintf("intratun-agent/%s", version.Version))

	client := &http.Client{Timeout: a.opts.updateTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("binary http status %d", resp.StatusCode)
	}

	tempFile, err := os.CreateTemp(filepath.Dir(exePath), ".intratun-update-*")
	if err != nil {
		return "", err
	}
	tempPath := tempFile.Name()
	success := false
	defer func() {
		_ = tempFile.Close()
		if !success {
			_ = os.Remove(tempPath)
		}
	}()

	hasher := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tempFile, hasher), resp.Body); err != nil {
		return "", err
	}
	actualSHA := strings.ToLower(hex.EncodeToString(hasher.Sum(nil)))
	if !strings.EqualFold(actualSHA, expectedSHA) {
		return "", fmt.Errorf("sha256 mismatch: expected %s got %s", expectedSHA, actualSHA)
	}

	mode := os.FileMode(0o755)
	if info, err := os.Stat(exePath); err == nil {
		mode = info.Mode() & os.ModePerm
		if mode&0o111 == 0 {
			mode |= 0o755
		}
	}
	if err := tempFile.Chmod(mode); err != nil {
		return "", err
	}
	if err := tempFile.Close(); err != nil {
		return "", err
	}
	success = true
	return tempPath, nil
}

func resolveDownloadURL(base *url.URL, raw string) (*url.URL, error) {
	ref, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid download url: %w", err)
	}
	if base == nil {
		if ref.Scheme == "" || ref.Host == "" {
			return nil, errors.New("download url must be absolute when update manifest base is unavailable")
		}
		return ref, nil
	}
	return base.ResolveReference(ref), nil
}

func shouldUpdateVersion(current, target string) bool {
	current = strings.TrimSpace(current)
	target = strings.TrimSpace(target)
	if current == "" || target == "" || current == target {
		return false
	}
	cur, curOK := parseVersion(current)
	next, nextOK := parseVersion(target)
	if curOK && nextOK {
		return compareParsedVersions(cur, next) < 0
	}
	return target != current
}

func compareParsedVersions(a, b parsedVersion) int {
	switch {
	case a.major != b.major:
		return compareInt(a.major, b.major)
	case a.minor != b.minor:
		return compareInt(a.minor, b.minor)
	case a.patch != b.patch:
		return compareInt(a.patch, b.patch)
	case a.hasBuild && b.hasBuild && a.build != b.build:
		return compareInt(a.build, b.build)
	default:
		return 0
	}
}

func compareInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

func parseVersion(raw string) (parsedVersion, bool) {
	versionText := strings.TrimSpace(raw)
	if versionText == "" {
		return parsedVersion{}, false
	}
	mainPart := versionText
	buildPart := ""
	if idx := strings.IndexByte(versionText, '+'); idx >= 0 {
		mainPart = versionText[:idx]
		buildPart = versionText[idx+1:]
	}
	if dash := strings.IndexByte(mainPart, '-'); dash >= 0 {
		mainPart = mainPart[:dash]
	}
	parts := strings.Split(mainPart, ".")
	if len(parts) != 3 {
		return parsedVersion{}, false
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return parsedVersion{}, false
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return parsedVersion{}, false
	}
	patch, err := strconv.Atoi(parts[2])
	if err != nil {
		return parsedVersion{}, false
	}
	parsed := parsedVersion{
		major: major,
		minor: minor,
		patch: patch,
	}
	if strings.HasPrefix(buildPart, "build.") {
		buildTokens := strings.Split(buildPart, ".")
		if len(buildTokens) >= 2 {
			build, err := strconv.Atoi(buildTokens[1])
			if err == nil {
				parsed.build = build
				parsed.hasBuild = true
			}
		}
	}
	return parsed, true
}
