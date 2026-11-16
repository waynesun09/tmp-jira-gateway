// Package config loads and validates the gateway's single config file:
// settings plus the grant table.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"regexp"

	"github.com/nonflux/tmp-jira-gateway/internal/strictjson"
)

// Defaults for unset settings.
const (
	DefaultIssuer           = "https://token.actions.githubusercontent.com"
	DefaultUpstreamBaseURL  = "https://api.atlassian.com"
	DefaultTokenURL         = "https://auth.atlassian.com/oauth/token"
	DefaultClockSkewSeconds = 30
	DefaultMaxRequestBytes  = 1 << 20
	DefaultMaxResponseBytes = 3 << 20
	DefaultPreflightCache   = 60
	maxClockSkewSeconds     = 120
	maxPreflightCache       = 300
	DefaultFilterSlots      = 2
	maxFilterSlots          = 16
)

// Grant levels.
const (
	LevelRead  = "read"
	LevelWrite = "write"
)

// Grant is one repository's access: its identity (all three values must
// match the caller's token), the Jira site and the projects it may reach.
type Grant struct {
	Repository        string   `json:"repository"`
	RepositoryID      string   `json:"repository_id"`
	RepositoryOwnerID string   `json:"repository_owner_id"`
	CloudID           string   `json:"cloudId"`
	Level             string   `json:"level"`
	Projects          []string `json:"projects"`

	projectSet map[string]bool
}

// HasProject reports whether key is one of the grant's projects.
func (g *Grant) HasProject(key string) bool { return g.projectSet[key] }

// ProjectSet returns the grant's projects as a set. Callers must not
// modify it.
func (g *Grant) ProjectSet() map[string]bool { return g.projectSet }

// CanWrite reports whether the grant allows write calls.
func (g *Grant) CanWrite() bool { return g.Level == LevelWrite }

// Config is the gateway's configuration. The OAuth client values are read
// from the four files named here (Secret Manager mounts), never from the
// config itself, flags or the environment.
type Config struct {
	// Listen is the listen address; empty means ":$PORT", or ":8080".
	Listen string `json:"listen"`

	Issuer           string `json:"issuer"`
	Audience         string `json:"audience"`
	ClockSkewSeconds int    `json:"clock_skew_seconds"`

	UpstreamBaseURL string `json:"upstream_base_url"`
	TokenURL        string `json:"token_url"`

	ReadClientIDFile      string `json:"read_client_id_file"`
	ReadClientSecretFile  string `json:"read_client_secret_file"`
	WriteClientIDFile     string `json:"write_client_id_file"`
	WriteClientSecretFile string `json:"write_client_secret_file"`

	MaxRequestBytes  int64 `json:"max_request_bytes"`
	MaxResponseBytes int64 `json:"max_response_bytes"`

	// PreflightCacheSeconds is how long a successful issue pre-flight
	// ("KEY-n is issue N in project P") is reused; 0 disables the cache.
	// Unset means DefaultPreflightCache.
	PreflightCacheSeconds *int `json:"preflight_cache_seconds"`

	// FilterSlots bounds how many responses are filtered (decoded and
	// re-encoded) at once; excess callers wait up to 5 s, then get 503.
	FilterSlots int `json:"filter_slots"`

	Grants []*Grant `json:"grants"`

	byRepo map[string]*Grant
}

// Lookup returns the grant for a repository name, or nil.
func (c *Config) Lookup(repository string) *Grant { return c.byRepo[repository] }

var (
	repoRe       = regexp.MustCompile(`^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$`)
	digitsRe     = regexp.MustCompile(`^[0-9]{1,20}$`)
	cloudIDRe    = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
	projectKeyRe = regexp.MustCompile(`^[A-Z][A-Z0-9_]+$`)
)

// Load reads and validates the config file at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	return Parse(data)
}

// Parse validates config data: strict JSON, no unknown fields.
func Parse(data []byte) (*Config, error) {
	if _, err := strictjson.ParseObject(data); err != nil {
		return nil, fmt.Errorf("config: not a strict JSON object (duplicate keys, trailing data or bad syntax)")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var c Config
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if err := c.applyDefaultsAndValidate(); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return &c, nil
}

func (c *Config) applyDefaultsAndValidate() error {
	if c.Issuer == "" {
		c.Issuer = DefaultIssuer
	}
	if c.UpstreamBaseURL == "" {
		c.UpstreamBaseURL = DefaultUpstreamBaseURL
	}
	if c.TokenURL == "" {
		c.TokenURL = DefaultTokenURL
	}
	if c.ClockSkewSeconds == 0 {
		c.ClockSkewSeconds = DefaultClockSkewSeconds
	}
	if c.MaxRequestBytes == 0 {
		c.MaxRequestBytes = DefaultMaxRequestBytes
	}
	if c.MaxResponseBytes == 0 {
		c.MaxResponseBytes = DefaultMaxResponseBytes
	}
	if c.PreflightCacheSeconds == nil {
		d := DefaultPreflightCache
		c.PreflightCacheSeconds = &d
	}
	if *c.PreflightCacheSeconds < 0 || *c.PreflightCacheSeconds > maxPreflightCache {
		return fmt.Errorf("preflight_cache_seconds must be between 0 and %d", maxPreflightCache)
	}
	if c.FilterSlots == 0 {
		c.FilterSlots = DefaultFilterSlots
	}
	if c.FilterSlots < 1 || c.FilterSlots > maxFilterSlots {
		return fmt.Errorf("filter_slots must be between 1 and %d", maxFilterSlots)
	}
	if c.Audience == "" {
		return fmt.Errorf("audience is required")
	}
	if c.ClockSkewSeconds < 0 || c.ClockSkewSeconds > maxClockSkewSeconds {
		return fmt.Errorf("clock_skew_seconds must be between 0 and %d", maxClockSkewSeconds)
	}
	if c.MaxRequestBytes < 0 || c.MaxResponseBytes < 0 {
		return fmt.Errorf("size limits must be positive")
	}
	for name, u := range map[string]string{"issuer": c.Issuer, "upstream_base_url": c.UpstreamBaseURL, "token_url": c.TokenURL} {
		if err := checkURL(u); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	if len(c.Grants) == 0 {
		return fmt.Errorf("grants: at least one grant is required")
	}
	c.byRepo = map[string]*Grant{}
	ids := map[string]bool{}
	var needRead, needWrite bool
	for i, g := range c.Grants {
		if g == nil {
			return fmt.Errorf("grants[%d]: null", i)
		}
		if !repoRe.MatchString(g.Repository) {
			return fmt.Errorf("grants[%d]: repository must be owner/name", i)
		}
		if !digitsRe.MatchString(g.RepositoryID) || !digitsRe.MatchString(g.RepositoryOwnerID) {
			return fmt.Errorf("grants[%d] (%s): repository_id and repository_owner_id must be digit strings", i, g.Repository)
		}
		if !cloudIDRe.MatchString(g.CloudID) {
			return fmt.Errorf("grants[%d] (%s): cloudId is not a cloud id", i, g.Repository)
		}
		switch g.Level {
		case LevelRead:
			needRead = true
		case LevelWrite:
			needWrite = true
		default:
			return fmt.Errorf("grants[%d] (%s): level must be read or write", i, g.Repository)
		}
		if len(g.Projects) == 0 {
			return fmt.Errorf("grants[%d] (%s): at least one project is required", i, g.Repository)
		}
		g.projectSet = map[string]bool{}
		for _, p := range g.Projects {
			if !projectKeyRe.MatchString(p) {
				return fmt.Errorf("grants[%d] (%s): %q is not a project key", i, g.Repository, p)
			}
			g.projectSet[p] = true
		}
		if c.byRepo[g.Repository] != nil || ids[g.RepositoryID] {
			return fmt.Errorf("grants[%d] (%s): duplicate repository or repository_id", i, g.Repository)
		}
		c.byRepo[g.Repository] = g
		ids[g.RepositoryID] = true
	}
	if needRead && (c.ReadClientIDFile == "" || c.ReadClientSecretFile == "") {
		return fmt.Errorf("read_client_id_file and read_client_secret_file are required with a read grant")
	}
	if needWrite && (c.WriteClientIDFile == "" || c.WriteClientSecretFile == "") {
		return fmt.Errorf("write_client_id_file and write_client_secret_file are required with a write grant")
	}
	return nil
}

// checkURL requires https, or http on a loopback host (tests only).
func checkURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("not a plain absolute URL")
	}
	if u.Scheme == "https" {
		return nil
	}
	h := u.Hostname()
	if u.Scheme == "http" && (h == "127.0.0.1" || h == "localhost" || h == "::1") {
		return nil
	}
	return fmt.Errorf("must use https")
}
