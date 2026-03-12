package agent

import (
	"net/url"
	"runtime"
	"testing"
)

func TestShouldUpdateVersion(t *testing.T) {
	tests := []struct {
		name    string
		current string
		target  string
		want    bool
	}{
		{
			name:    "same version",
			current: "0.1.0+build.62.725155e",
			target:  "0.1.0+build.62.725155e",
			want:    false,
		},
		{
			name:    "same base higher build",
			current: "0.1.0+build.62.725155e",
			target:  "0.1.0+build.63.abcd123",
			want:    true,
		},
		{
			name:    "higher semver",
			current: "0.1.0+build.99.ffff",
			target:  "0.2.0+build.1.aaaa",
			want:    true,
		},
		{
			name:    "older target skipped",
			current: "0.2.0+build.1.aaaa",
			target:  "0.1.9+build.99.zzzz",
			want:    false,
		},
		{
			name:    "unparseable target different still updates",
			current: "dev",
			target:  "custom-release",
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shouldUpdateVersion(tt.current, tt.target)
			if got != tt.want {
				t.Fatalf("shouldUpdateVersion(%q, %q) = %v, want %v", tt.current, tt.target, got, tt.want)
			}
		})
	}
}

func TestParseVersion(t *testing.T) {
	got, ok := parseVersion("1.2.3-beta.1+build.42.abcdef")
	if !ok {
		t.Fatal("expected version to parse")
	}
	if got.major != 1 || got.minor != 2 || got.patch != 3 {
		t.Fatalf("unexpected semver parts: %+v", got)
	}
	if !got.hasBuild || got.build != 42 {
		t.Fatalf("unexpected build number: %+v", got)
	}
}

func TestDeriveDefaultUpdateManifestURL(t *testing.T) {
	relayURL, err := url.Parse("wss://relay.example.com/tunnel")
	if err != nil {
		t.Fatalf("parse relay url: %v", err)
	}
	got := deriveDefaultUpdateManifestURL(relayURL)
	want := "https://relay.example.com/updates/manifest-" + runtime.GOOS + "-" + runtime.GOARCH + ".json"
	if got == "" {
		t.Fatal("expected non-empty update manifest url")
	}
	if got != want {
		t.Fatalf("unexpected derived url: got %q want %q", got, want)
	}
}
