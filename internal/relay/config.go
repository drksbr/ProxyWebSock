package relay

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

type agentConfigEntry struct {
	Identification string   `yaml:"identification"`
	Location       string   `yaml:"location"`
	Login          string   `yaml:"login"`
	Password       string   `yaml:"password"`
	ACLAllow       []string `yaml:"acl_allow"`
}

func loadAgentConfig(path string) (map[string]*agentRecord, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read agent config %q: %w", path, err)
	}

	var wrapper struct {
		Agents []agentConfigEntry `yaml:"agents"`
	}
	if err := yaml.Unmarshal(data, &wrapper); err != nil {
		return nil, fmt.Errorf("parse agent config %q: %w", path, err)
	}

	entries := wrapper.Agents
	if len(entries) == 0 {
		if err := yaml.Unmarshal(data, &entries); err != nil {
			return nil, fmt.Errorf("parse agent config %q: %w", path, err)
		}
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("agent config %q must define at least one agent", path)
	}

	result := make(map[string]*agentRecord, len(entries))
	for idx, entry := range entries {
		login := strings.TrimSpace(entry.Login)
		password := entry.Password
		if login == "" {
			return nil, fmt.Errorf("agent entry %d missing login", idx+1)
		}
		if password == "" {
			return nil, fmt.Errorf("agent %q missing password", login)
		}
		if _, exists := result[login]; exists {
			return nil, fmt.Errorf("duplicate agent login %q", login)
		}

		patterns := make([]string, 0, len(entry.ACLAllow))
		compiled := make([]*regexp.Regexp, 0, len(entry.ACLAllow))
		for idxPattern, pattern := range entry.ACLAllow {
			pattern = strings.TrimSpace(pattern)
			if pattern == "" {
				continue
			}
			re, err := regexp.Compile(pattern)
			if err != nil {
				return nil, fmt.Errorf("agent %q acl_allow[%d]: %w", login, idxPattern, err)
			}
			patterns = append(patterns, pattern)
			compiled = append(compiled, re)
		}

		result[login] = &agentRecord{
			Login:          login,
			Password:       password,
			Identification: strings.TrimSpace(entry.Identification),
			Location:       strings.TrimSpace(entry.Location),
			ACL:            compiled,
			ACLPatterns:    patterns,
		}
	}

	return result, nil
}
