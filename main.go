package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/miekg/dns"
)

type Server struct {
	cfg       *Config
	upstreams map[string]Upstream // keyed by name or literal address
}


func NewServer(cfg *Config) (*Server, error) {
	s := &Server{cfg: cfg, upstreams: map[string]Upstream{}}
	for name, addr := range cfg.Upstreams {
		u, err := NewUpstream(addr, cfg.Timeout)
		if err != nil {
			return nil, fmt.Errorf("upstream %q: %w", name, err)
		}
		s.upstreams[name] = u
	}
	// Resolve the default and per-rule upstreams; unknown names are treated as literal addresses.
	refs := []string{cfg.Default}
	for _, r := range cfg.Rules {
		if r.Upstream != "" {
			refs = append(refs, r.Upstream)
		}
	}
	for _, ref := range refs {
		if _, ok := s.upstreams[ref]; ok {
			continue
		}
		u, err := NewUpstream(ref, cfg.Timeout)
		if err != nil {
			return nil, err
		}
		s.upstreams[ref] = u
	}
	return s, nil
}

// route picks the first matching rule (config order) and returns the upstream
// and the name to query.
func (s *Server) route(name string) (Upstream, string) {
	for _, r := range s.cfg.Rules {
		if ok, target := r.Match(name); ok {
			up := r.Upstream
			if up == "" {
				up = s.cfg.Default
			}
			return s.upstreams[up], target
		}
	}
	return s.upstreams[s.cfg.Default], name
}

func (s *Server) Resolve(ctx context.Context, req *dns.Msg) *dns.Msg {
	if len(req.Question) != 1 {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeFormatError)
		return m
	}
	orig := req.Question[0]
	name := strings.ToLower(orig.Name)
	up, target := s.route(name)

	q := req.Copy()
	q.Question[0].Name = target

	resp, err := up.Exchange(ctx, q)
	if err != nil {
		log.Printf("%s %s -> %s via %s: %v", dns.TypeToString[orig.Qtype], name, target, up, err)
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeServerFailure)
		return m
	}
	log.Printf("%s %s -> %s via %s: %s, %d answers",
		dns.TypeToString[orig.Qtype], name, target, up, dns.RcodeToString[resp.Rcode], len(resp.Answer))

	resp.Id = req.Id
	if target != name {
		rewriteBack(resp, target, orig.Name)
	}
	resp.Question = req.Question
	return resp
}

// rewriteBack renames records owned by the remapped name back to the name the
// client asked for, so the client sees answers for its original question.
func rewriteBack(m *dns.Msg, target, orig string) {
	for _, sec := range [][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range sec {
			if strings.EqualFold(rr.Header().Name, target) {
				rr.Header().Name = orig
			}
		}
	}
}

// ServeHTTP implements RFC 8484 (GET ?dns=<base64url> and POST application/dns-message).
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var wire []byte
	var err error
	switch r.Method {
	case http.MethodGet:
		wire, err = base64.RawURLEncoding.DecodeString(strings.TrimRight(r.URL.Query().Get("dns"), "="))
	case http.MethodPost:
		if ct := r.Header.Get("Content-Type"); ct != "application/dns-message" {
			http.Error(w, "unsupported content type", http.StatusUnsupportedMediaType)
			return
		}
		wire, err = io.ReadAll(io.LimitReader(r.Body, 65535))
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err != nil || len(wire) == 0 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	req := new(dns.Msg)
	if err := req.Unpack(wire); err != nil {
		http.Error(w, "invalid dns message", http.StatusBadRequest)
		return
	}

	resp := s.Resolve(r.Context(), req)
	out, err := resp.Pack()
	if err != nil {
		http.Error(w, "pack error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d", minTTL(resp)))
	w.Write(out)
}

func minTTL(m *dns.Msg) uint32 {
	var ttl uint32
	first := true
	for _, rr := range append(m.Answer, m.Ns...) {
		if t := rr.Header().Ttl; first || t < ttl {
			ttl, first = t, false
		}
	}
	return ttl
}

func main() {
	cfgPath := flag.String("c", "config.yaml", "path to config file")
	flag.Parse()

	cfg, err := LoadConfig(*cfgPath)
	if err != nil {
		log.Fatal(err)
	}
	srv, err := NewServer(cfg)
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.Handle(cfg.Path, srv)

	if cfg.TLSCert != "" && cfg.TLSKey != "" {
		log.Printf("DoH listening on https://%s%s", cfg.Listen, cfg.Path)
		log.Fatal(http.ListenAndServeTLS(cfg.Listen, cfg.TLSCert, cfg.TLSKey, mux))
	}
	log.Printf("DoH listening on http://%s%s (no TLS; put behind a TLS proxy)", cfg.Listen, cfg.Path)
	log.Fatal(http.ListenAndServe(cfg.Listen, mux))
}
