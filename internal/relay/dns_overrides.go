package relay

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/drksbr/ProxyWebSock/internal/protocol"
	"gopkg.in/yaml.v3"
)

type dnsOverrideEntry struct {
	Host      string    `yaml:"host" json:"host"`
	Address   string    `yaml:"address" json:"address"`
	UpdatedAt time.Time `yaml:"updated_at,omitempty" json:"updatedAt,omitempty"`
}

type dnsOverrideStore struct {
	path string

	mu      sync.RWMutex
	entries map[string]dnsOverrideEntry
}

type dnsOverrideFile struct {
	Overrides []dnsOverrideEntry `yaml:"overrides"`
}

func newDNSOverrideStore(path string) (*dnsOverrideStore, error) {
	store := &dnsOverrideStore{
		path:    path,
		entries: make(map[string]dnsOverrideEntry),
	}
	if strings.TrimSpace(path) == "" {
		return store, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("create dns override dir: %w", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return store, nil
		}
		return nil, fmt.Errorf("read dns overrides: %w", err)
	}
	var payload dnsOverrideFile
	if err := yaml.Unmarshal(data, &payload); err != nil {
		return nil, fmt.Errorf("parse dns overrides: %w", err)
	}
	for _, entry := range payload.Overrides {
		host, address, err := normalizeDNSOverride(entry.Host, entry.Address)
		if err != nil {
			return nil, err
		}
		entry.Host = host
		entry.Address = address
		store.entries[host] = entry
	}
	return store, nil
}

func (s *dnsOverrideStore) List() []dnsOverrideEntry {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]dnsOverrideEntry, 0, len(s.entries))
	for _, entry := range s.entries {
		result = append(result, entry)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Host < result[j].Host
	})
	return result
}

func (s *dnsOverrideStore) Resolve(host string) (dnsOverrideEntry, bool) {
	if s == nil {
		return dnsOverrideEntry{}, false
	}
	key := normalizeOverrideHost(host)
	if key == "" {
		return dnsOverrideEntry{}, false
	}
	s.mu.RLock()
	entry, ok := s.entries[key]
	s.mu.RUnlock()
	return entry, ok
}

func (s *dnsOverrideStore) Set(host, address string) (dnsOverrideEntry, error) {
	if s == nil {
		return dnsOverrideEntry{}, fmt.Errorf("dns override store unavailable")
	}
	host, address, err := normalizeDNSOverride(host, address)
	if err != nil {
		return dnsOverrideEntry{}, err
	}
	entry := dnsOverrideEntry{
		Host:      host,
		Address:   address,
		UpdatedAt: time.Now().UTC(),
	}
	s.mu.Lock()
	s.entries[host] = entry
	err = s.persistLocked()
	s.mu.Unlock()
	if err != nil {
		return dnsOverrideEntry{}, err
	}
	return entry, nil
}

func (s *dnsOverrideStore) Delete(host string) error {
	if s == nil {
		return fmt.Errorf("dns override store unavailable")
	}
	key := normalizeOverrideHost(host)
	if key == "" {
		return fmt.Errorf("host is required")
	}
	s.mu.Lock()
	delete(s.entries, key)
	err := s.persistLocked()
	s.mu.Unlock()
	return err
}

func (s *dnsOverrideStore) persistLocked() error {
	if strings.TrimSpace(s.path) == "" {
		return nil
	}
	entries := make([]dnsOverrideEntry, 0, len(s.entries))
	for _, entry := range s.entries {
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Host < entries[j].Host
	})
	payload := dnsOverrideFile{Overrides: entries}
	data, err := yaml.Marshal(&payload)
	if err != nil {
		return fmt.Errorf("encode dns overrides: %w", err)
	}
	tempPath := s.path + ".tmp"
	if err := os.WriteFile(tempPath, data, 0o640); err != nil {
		return fmt.Errorf("write dns overrides: %w", err)
	}
	if err := os.Rename(tempPath, s.path); err != nil {
		return fmt.Errorf("replace dns overrides: %w", err)
	}
	return nil
}

func normalizeDNSOverride(host, address string) (string, string, error) {
	host = normalizeOverrideHost(host)
	if host == "" {
		return "", "", fmt.Errorf("host is required")
	}
	ip := net.ParseIP(strings.TrimSpace(address))
	if ip == nil {
		return "", "", fmt.Errorf("invalid ip address %q", address)
	}
	return host, ip.String(), nil
}

func normalizeOverrideHost(host string) string {
	host = strings.TrimSpace(host)
	host = strings.TrimSuffix(host, ".")
	return strings.ToLower(host)
}

func (s *relayServer) buildDialRequest(streamID uint64, host string, port int) protocol.DialRequest {
	req := protocol.DialRequest{
		StreamID: streamID,
		Host:     host,
		Port:     uint16(port),
	}
	if override, ok := s.lookupDNSOverride(host); ok {
		req.OverrideAddress = override.Address
	}
	return req
}

func (s *relayServer) lookupDNSOverride(host string) (dnsOverrideEntry, bool) {
	if s == nil || s.dnsOverrides == nil {
		return dnsOverrideEntry{}, false
	}
	return s.dnsOverrides.Resolve(host)
}

func formatStreamID(id uint64) string {
	return strconv.FormatUint(id, 10)
}
