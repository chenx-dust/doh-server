package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen  string `yaml:"listen"`   // e.g. ":8053"
	Path    string `yaml:"path"`     // e.g. "/dns-query"
	TLSCert string `yaml:"tls_cert"` // optional; serve HTTPS when both are set
	TLSKey  string `yaml:"tls_key"`

	Timeout time.Duration `yaml:"timeout"` // per upstream query

	// Named upstreams. Value forms:
	//   https://host/dns-query  (DoH)
	//   tls://host:853          (DNS over TLS)
	//   udp://host:53, tcp://host:53, or bare host[:port] (plain DNS, UDP)
	Upstreams map[string]string `yaml:"upstreams"`

	// Upstream used when no rule matches (name from Upstreams, or a literal address).
	Default string `yaml:"default"`

	Rules []Rule `yaml:"rules"`
}

type Rule struct {
	// "example.com" matches exactly; "*.example.com" matches any subdomain
	// (any depth) but not example.com itself; "*" matches everything.
	Domain string `yaml:"domain"`
	// Optional. Query this domain instead. If both Domain and Remap start
	// with "*.", the matched prefix is kept: a.b.foo.com -> a.b.bar.com.
	Remap string `yaml:"remap"`
	// Optional. Upstream name or literal address; falls back to Default.
	Upstream string `yaml:"upstream"`
}

func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := &Config{Listen: ":8053", Path: "/dns-query", Timeout: 5 * time.Second}
	if err := yaml.Unmarshal(b, cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if cfg.Default == "" {
		return nil, fmt.Errorf("config: 'default' upstream is required")
	}
	for i := range cfg.Rules {
		r := &cfg.Rules[i]
		if r.Domain == "" {
			return nil, fmt.Errorf("config: rule %d has empty domain", i)
		}
		r.Domain = normalize(r.Domain)
		if r.Remap != "" {
			r.Remap = normalize(r.Remap)
			if strings.HasPrefix(r.Remap, "*.") && !strings.HasPrefix(r.Domain, "*.") {
				return nil, fmt.Errorf("config: rule %q: wildcard remap requires wildcard domain", r.Domain)
			}
		}
	}
	return cfg, nil
}

// normalize lowercases and makes a name fully qualified ("example.com.").
func normalize(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "*" {
		return s
	}
	return dns.Fqdn(s)
}

// Match reports whether name (lowercase FQDN) matches the rule, and returns
// the name that should actually be queried.
func (r *Rule) Match(name string) (bool, string) {
	switch {
	case r.Domain == "*":
		if r.Remap != "" {
			return true, r.Remap
		}
		return true, name
	case strings.HasPrefix(r.Domain, "*."):
		suffix := r.Domain[1:] // ".example.com."
		if !strings.HasSuffix(name, suffix) || len(name) == len(suffix) {
			return false, ""
		}
		if r.Remap == "" {
			return true, name
		}
		if strings.HasPrefix(r.Remap, "*.") {
			prefix := name[:len(name)-len(suffix)]
			return true, prefix + r.Remap[1:]
		}
		return true, r.Remap
	default:
		if name != r.Domain {
			return false, ""
		}
		if r.Remap == "" {
			return true, name
		}
		return true, r.Remap
	}
}
