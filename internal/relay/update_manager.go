package relay

import (
	"bufio"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/drksbr/ProxyWebSock/internal/version"
)

const updateCatalogTTL = 5 * time.Second

type updateManager struct {
	logger           *slog.Logger
	updatesDir       string
	deploymentsPath  string
	mu               sync.RWMutex
	pinnedTargets    map[string]deploymentTarget
	observedRuntimes map[string]agentRuntimeObservation
	cachedCatalog    *updateCatalog
	cachedAt         time.Time
}

type deploymentTarget struct {
	Version   string    `json:"version"`
	GOOS      string    `json:"goos,omitempty"`
	GOARCH    string    `json:"goarch,omitempty"`
	UpdatedAt time.Time `json:"updatedAt,omitempty"`
}

type agentRuntimeObservation struct {
	Version     string    `json:"version,omitempty"`
	GOOS        string    `json:"goos,omitempty"`
	GOARCH      string    `json:"goarch,omitempty"`
	LastCheckAt time.Time `json:"lastCheckAt,omitempty"`
}

type updateCatalog struct {
	artifacts          map[string]*updateArtifact
	versionsByPlatform map[string][]string
	latestByPlatform   map[string]string
}

type agentDeploymentStatus struct {
	CurrentVersion string
	DesiredVersion string
	PinnedVersion  string
	Track          string
	GOOS           string
	GOARCH         string
	LastCheckAt    time.Time
}

type statusUpdateCatalogEntry struct {
	GOOS          string   `json:"goos"`
	GOARCH        string   `json:"goarch"`
	LatestVersion string   `json:"latestVersion,omitempty"`
	Versions      []string `json:"versions"`
}

func newUpdateManager(logger *slog.Logger, updatesDir string) (*updateManager, error) {
	manager := &updateManager{
		logger:           logger,
		updatesDir:       updatesDir,
		deploymentsPath:  filepath.Join(updatesDir, ".intratun-deployments.json"),
		pinnedTargets:    make(map[string]deploymentTarget),
		observedRuntimes: make(map[string]agentRuntimeObservation),
	}
	if err := manager.loadPinnedTargets(); err != nil {
		return nil, err
	}
	return manager, nil
}

func (m *updateManager) resolveArtifact(versionText, goos, goarch string) (*updateArtifact, error) {
	catalog, err := m.catalog(false)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(goos) == "" || strings.TrimSpace(goarch) == "" {
		return nil, os.ErrNotExist
	}
	versionText = strings.TrimSpace(versionText)
	if versionText == "" {
		versionText = catalog.latestByPlatform[platformKey(goos, goarch)]
	}
	if versionText == "" {
		return nil, os.ErrNotExist
	}
	artifact, ok := catalog.artifacts[artifactKey(versionText, goos, goarch)]
	if !ok {
		return nil, os.ErrNotExist
	}
	copyArtifact := *artifact
	return &copyArtifact, nil
}

func (m *updateManager) availableVersions(goos, goarch string) []string {
	catalog, err := m.catalog(false)
	if err != nil {
		return nil
	}
	return append([]string(nil), catalog.versionsByPlatform[platformKey(goos, goarch)]...)
}

func (m *updateManager) catalogEntries() []statusUpdateCatalogEntry {
	catalog, err := m.catalog(false)
	if err != nil {
		return nil
	}
	entries := make([]statusUpdateCatalogEntry, 0, len(catalog.versionsByPlatform))
	for platform, versions := range catalog.versionsByPlatform {
		goos, goarch, ok := strings.Cut(platform, "/")
		if !ok {
			continue
		}
		entries = append(entries, statusUpdateCatalogEntry{
			GOOS:          goos,
			GOARCH:        goarch,
			LatestVersion: catalog.latestByPlatform[platform],
			Versions:      append([]string(nil), versions...),
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].GOOS == entries[j].GOOS {
			return entries[i].GOARCH < entries[j].GOARCH
		}
		return entries[i].GOOS < entries[j].GOOS
	})
	return entries
}

func (m *updateManager) deploymentStatus(agentID, goos, goarch string) agentDeploymentStatus {
	m.mu.RLock()
	target, targetOK := m.pinnedTargets[agentID]
	observed := m.observedRuntimes[agentID]
	m.mu.RUnlock()

	if strings.TrimSpace(goos) == "" {
		goos = observed.GOOS
	}
	if strings.TrimSpace(goarch) == "" {
		goarch = observed.GOARCH
	}
	status := agentDeploymentStatus{
		CurrentVersion: observed.Version,
		PinnedVersion:  target.Version,
		Track:          "latest",
		GOOS:           goos,
		GOARCH:         goarch,
		LastCheckAt:    observed.LastCheckAt,
	}
	if targetOK && strings.TrimSpace(target.Version) != "" {
		status.DesiredVersion = target.Version
		status.Track = "pinned"
		return status
	}
	if artifact, err := m.resolveArtifact("", goos, goarch); err == nil && artifact != nil {
		status.DesiredVersion = artifact.Version
	}
	return status
}

func (m *updateManager) setPinnedTarget(agentID, goos, goarch, versionText string) error {
	if strings.TrimSpace(agentID) == "" {
		return errors.New("agent id is required")
	}
	versionText = strings.TrimSpace(versionText)

	m.mu.Lock()
	defer m.mu.Unlock()

	if versionText == "" {
		delete(m.pinnedTargets, agentID)
		return m.persistPinnedTargetsLocked()
	}

	if strings.TrimSpace(goos) != "" && strings.TrimSpace(goarch) != "" {
		catalog, err := m.catalogLocked(false)
		if err != nil {
			return err
		}
		if _, ok := catalog.artifacts[artifactKey(versionText, goos, goarch)]; !ok {
			return os.ErrNotExist
		}
	}

	m.pinnedTargets[agentID] = deploymentTarget{
		Version:   versionText,
		GOOS:      strings.TrimSpace(goos),
		GOARCH:    strings.TrimSpace(goarch),
		UpdatedAt: time.Now(),
	}
	return m.persistPinnedTargetsLocked()
}

func (m *updateManager) observeRuntime(agentID, versionText, goos, goarch string) {
	agentID = strings.TrimSpace(agentID)
	if agentID == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	current := m.observedRuntimes[agentID]
	if trimmed := strings.TrimSpace(versionText); trimmed != "" {
		current.Version = trimmed
	}
	if trimmed := strings.TrimSpace(goos); trimmed != "" {
		current.GOOS = trimmed
	}
	if trimmed := strings.TrimSpace(goarch); trimmed != "" {
		current.GOARCH = trimmed
	}
	current.LastCheckAt = time.Now()
	m.observedRuntimes[agentID] = current
}

func (m *updateManager) catalog(force bool) (*updateCatalog, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.catalogLocked(force)
}

func (m *updateManager) catalogLocked(force bool) (*updateCatalog, error) {
	if !force && m.cachedCatalog != nil && time.Since(m.cachedAt) < updateCatalogTTL {
		return m.cachedCatalog, nil
	}
	catalog, err := m.scanCatalog()
	if err != nil {
		return nil, err
	}
	m.cachedCatalog = catalog
	m.cachedAt = time.Now()
	return catalog, nil
}

func (m *updateManager) scanCatalog() (*updateCatalog, error) {
	rootChecksums, _ := loadSHA256Sums(m.updatesDir)
	catalog := &updateCatalog{
		artifacts:          make(map[string]*updateArtifact),
		versionsByPlatform: make(map[string][]string),
		latestByPlatform:   make(map[string]string),
	}

	entries, err := os.ReadDir(m.updatesDir)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		fullPath := filepath.Join(m.updatesDir, entry.Name())
		switch {
		case entry.IsDir():
			versionText := strings.TrimSpace(entry.Name())
			if versionText == "" {
				continue
			}
			checksums, _ := loadSHA256Sums(fullPath)
			if err := scanCatalogDir(catalog, fullPath, versionText, checksums); err != nil {
				return nil, err
			}
		case entry.Type().IsRegular():
			if err := addArtifactFromFile(catalog, fullPath, version.Version, rootChecksums); err != nil {
				return nil, err
			}
		}
	}

	for platform, versions := range catalog.versionsByPlatform {
		sort.Slice(versions, func(i, j int) bool {
			return compareUpdateVersions(versions[i], versions[j]) > 0
		})
		catalog.versionsByPlatform[platform] = dedupeSortedStrings(versions)
		if len(catalog.versionsByPlatform[platform]) > 0 {
			catalog.latestByPlatform[platform] = catalog.versionsByPlatform[platform][0]
		}
	}

	return catalog, nil
}

func scanCatalogDir(catalog *updateCatalog, dirPath, versionText string, checksums map[string]string) error {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			continue
		}
		if err := addArtifactFromFile(catalog, filepath.Join(dirPath, entry.Name()), versionText, checksums); err != nil {
			return err
		}
	}
	return nil
}

func addArtifactFromFile(catalog *updateCatalog, filePath, versionText string, checksums map[string]string) error {
	if catalog == nil {
		return nil
	}
	base := filepath.Base(filePath)
	goos, goarch, ok := parseArtifactFilename(base)
	if !ok {
		return nil
	}
	sum := checksums[base]
	if sum == "" {
		hash, err := sha256File(filePath)
		if err != nil {
			return err
		}
		sum = hash
	}
	key := artifactKey(versionText, goos, goarch)
	if _, exists := catalog.artifacts[key]; exists {
		return nil
	}
	catalog.artifacts[key] = &updateArtifact{
		GOOS:    goos,
		GOARCH:  goarch,
		Path:    filePath,
		Version: versionText,
		SHA256:  strings.ToLower(sum),
	}
	platform := platformKey(goos, goarch)
	catalog.versionsByPlatform[platform] = append(catalog.versionsByPlatform[platform], versionText)
	return nil
}

func loadSHA256Sums(dirPath string) (map[string]string, error) {
	sumsPath := filepath.Join(dirPath, "SHA256SUMS")
	file, err := os.Open(sumsPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer file.Close()

	sums := make(map[string]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		fileName := strings.TrimPrefix(fields[len(fields)-1], "*")
		sums[fileName] = strings.ToLower(fields[0])
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return sums, nil
}

func parseArtifactFilename(name string) (string, string, bool) {
	trimmed := strings.TrimSpace(name)
	switch {
	case strings.HasPrefix(trimmed, "intratun-agent-"):
		trimmed = strings.TrimPrefix(trimmed, "intratun-agent-")
	case strings.HasPrefix(trimmed, "intratun-"):
		trimmed = strings.TrimPrefix(trimmed, "intratun-")
	default:
		return "", "", false
	}
	trimmed = strings.TrimSuffix(trimmed, ".exe")
	parts := strings.Split(trimmed, "-")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func (m *updateManager) loadPinnedTargets() error {
	file, err := os.Open(m.deploymentsPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer file.Close()

	var payload struct {
		Agents map[string]deploymentTarget `json:"agents"`
	}
	if err := json.NewDecoder(file).Decode(&payload); err != nil {
		return err
	}
	for agentID, target := range payload.Agents {
		if strings.TrimSpace(agentID) == "" || strings.TrimSpace(target.Version) == "" {
			continue
		}
		m.pinnedTargets[agentID] = target
	}
	return nil
}

func (m *updateManager) persistPinnedTargetsLocked() error {
	payload := struct {
		Agents map[string]deploymentTarget `json:"agents"`
	}{
		Agents: make(map[string]deploymentTarget, len(m.pinnedTargets)),
	}
	for agentID, target := range m.pinnedTargets {
		if strings.TrimSpace(target.Version) == "" {
			continue
		}
		payload.Agents[agentID] = target
	}

	tempPath := m.deploymentsPath + ".tmp"
	file, err := os.Create(tempPath)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(file).Encode(payload); err != nil {
		_ = file.Close()
		_ = os.Remove(tempPath)
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(tempPath)
		return err
	}
	return os.Rename(tempPath, m.deploymentsPath)
}

func artifactKey(versionText, goos, goarch string) string {
	return strings.TrimSpace(versionText) + "\x00" + platformKey(goos, goarch)
}

func platformKey(goos, goarch string) string {
	return strings.TrimSpace(goos) + "/" + strings.TrimSpace(goarch)
}

func dedupeSortedStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	result := values[:0]
	var last string
	for i, value := range values {
		if i == 0 || value != last {
			result = append(result, value)
			last = value
		}
	}
	return result
}

type updateVersion struct {
	major    int
	minor    int
	patch    int
	build    int
	hasBuild bool
}

func compareUpdateVersions(a, b string) int {
	parsedA, okA := parseUpdateVersion(a)
	parsedB, okB := parseUpdateVersion(b)
	switch {
	case okA && okB:
		switch {
		case parsedA.major != parsedB.major:
			return compareInts(parsedA.major, parsedB.major)
		case parsedA.minor != parsedB.minor:
			return compareInts(parsedA.minor, parsedB.minor)
		case parsedA.patch != parsedB.patch:
			return compareInts(parsedA.patch, parsedB.patch)
		case parsedA.hasBuild && parsedB.hasBuild && parsedA.build != parsedB.build:
			return compareInts(parsedA.build, parsedB.build)
		default:
			return compareInts(strings.Compare(a, b), 0)
		}
	case okA:
		return 1
	case okB:
		return -1
	default:
		return compareInts(strings.Compare(a, b), 0)
	}
}

func parseUpdateVersion(raw string) (updateVersion, bool) {
	versionText := strings.TrimSpace(raw)
	if versionText == "" {
		return updateVersion{}, false
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
		return updateVersion{}, false
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return updateVersion{}, false
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return updateVersion{}, false
	}
	patch, err := strconv.Atoi(parts[2])
	if err != nil {
		return updateVersion{}, false
	}
	parsed := updateVersion{major: major, minor: minor, patch: patch}
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

func compareInts(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}
