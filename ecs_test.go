package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/miekg/dns"
)

// fakeUpstream records the query and echoes its OPT record, as an ECS-aware resolver would.
type fakeUpstream struct{ got *dns.Msg }

func (f *fakeUpstream) String() string { return "fake" }
func (f *fakeUpstream) Exchange(_ context.Context, m *dns.Msg) (*dns.Msg, error) {
	f.got = m.Copy()
	resp := new(dns.Msg)
	resp.SetReply(m)
	if opt := m.IsEdns0(); opt != nil {
		resp.Extra = append(resp.Extra, dns.Copy(opt))
	}
	return resp, nil
}

func subnetOf(m *dns.Msg) *dns.EDNS0_SUBNET {
	if opt := m.IsEdns0(); opt != nil {
		for _, o := range opt.Option {
			if s, ok := o.(*dns.EDNS0_SUBNET); ok {
				return s
			}
		}
	}
	return nil
}

func TestClientIP(t *testing.T) {
	c := ECSConfig{IPv4Prefix: 24, IPv6Prefix: 56, TrustedProxies: []string{"10.0.0.0/8", "::1"}}
	if err := c.validate(); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, remote string
		xff          []string
		want         string
	}{
		{"direct", "203.0.113.7:1234", nil, "203.0.113.7"},
		{"direct v6", "[2001:db8::1]:1234", nil, "2001:db8::1"},
		{"v4-mapped", "[::ffff:203.0.113.7]:1234", nil, "203.0.113.7"},
		{"untrusted peer cannot spoof", "203.0.113.7:1234", []string{"198.51.100.1"}, "203.0.113.7"},
		{"trusted proxy", "10.0.0.1:1234", []string{"198.51.100.1"}, "198.51.100.1"},
		{"trusted v6 proxy", "[::1]:1234", []string{"198.51.100.1"}, "198.51.100.1"},
		{"spoofed left entry ignored", "10.0.0.1:1234", []string{"192.0.2.9, 198.51.100.1"}, "198.51.100.1"},
		{"proxy chain", "10.0.0.1:1234", []string{"198.51.100.1, 10.0.0.2"}, "198.51.100.1"},
		{"split header lines", "10.0.0.1:1234", []string{"192.0.2.9", "198.51.100.1"}, "198.51.100.1"},
		{"trusted proxy without header", "10.0.0.1:1234", nil, ""},
		{"only proxies", "10.0.0.1:1234", []string{"10.0.0.2"}, ""},
		{"malformed hop", "10.0.0.1:1234", []string{"nonsense"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tc.remote
			for _, v := range tc.xff {
				r.Header.Add("X-Forwarded-For", v)
			}
			var want netip.Addr
			if tc.want != "" {
				want = netip.MustParseAddr(tc.want)
			}
			if got := c.clientIP(r); got != want {
				t.Errorf("got %v want %v", got, want)
			}
		})
	}
}

func TestECSValidate(t *testing.T) {
	for _, c := range []ECSConfig{
		{IPv4Prefix: 0, IPv6Prefix: 56},
		{IPv4Prefix: 33, IPv6Prefix: 56},
		{IPv4Prefix: 24, IPv6Prefix: 129},
		{IPv4Prefix: 24, IPv6Prefix: 56, TrustedProxies: []string{"not-an-ip"}},
	} {
		if err := c.validate(); err == nil {
			t.Errorf("%+v: expected error", c)
		}
	}
}

// serve sends q through the full HTTP handler and returns the upstream's view,
// the client's view, and the Cache-Control header.
func serve(t *testing.T, enabled bool, remote string, q *dns.Msg) (*dns.Msg, *dns.Msg, string) {
	t.Helper()
	up := &fakeUpstream{}
	s := &Server{
		cfg: &Config{
			Default: "fake",
			ECS:     ECSConfig{Enabled: enabled, IPv4Prefix: 24, IPv6Prefix: 56},
		},
		upstreams: map[string]Upstream{"fake": up},
	}
	wire, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(wire))
	r.Header.Set("Content-Type", "application/dns-message")
	r.RemoteAddr = remote
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("HTTP %d: %s", w.Code, w.Body)
	}
	resp := new(dns.Msg)
	if err := resp.Unpack(w.Body.Bytes()); err != nil {
		t.Fatal(err)
	}
	return up.got, resp, w.Header().Get("Cache-Control")
}

func query() *dns.Msg {
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	return q
}

func TestECSAddedForIPv4WithoutClientEDNS(t *testing.T) {
	sent, resp, cc := serve(t, true, "203.0.113.7:1234", query())
	s := subnetOf(sent)
	if s == nil {
		t.Fatal("upstream got no ECS")
	}
	if s.Family != 1 || s.SourceNetmask != 24 || s.SourceScope != 0 || s.Address.String() != "203.0.113.0" {
		t.Errorf("bad ECS: %+v", s)
	}
	if resp.IsEdns0() != nil {
		t.Error("client that didn't use EDNS got an OPT record")
	}
	if cc != "private, max-age=0" {
		t.Errorf("Cache-Control = %q", cc)
	}
}

func TestECSAddedForIPv6(t *testing.T) {
	sent, _, _ := serve(t, true, "[2001:db8:1:2ff:3::4]:1234", query())
	s := subnetOf(sent)
	if s == nil || s.Family != 2 || s.SourceNetmask != 56 || s.Address.String() != "2001:db8:1:200::" {
		t.Errorf("bad ECS: %+v", s)
	}
}

func TestECSKeepsClientEDNS(t *testing.T) {
	q := query()
	q.SetEdns0(4096, true)
	sent, resp, _ := serve(t, true, "203.0.113.7:1234", q)
	if subnetOf(sent) == nil {
		t.Fatal("upstream got no ECS")
	}
	if opt := sent.IsEdns0(); opt.UDPSize() != 4096 || !opt.Do() {
		t.Errorf("client's EDNS settings changed: %v", opt)
	}
	if resp.IsEdns0() == nil {
		t.Error("client's OPT missing from response")
	}
	if subnetOf(resp) != nil {
		t.Error("client that didn't ask for ECS got it back")
	}
}

func TestECSClientSuppliedIsForwarded(t *testing.T) {
	for _, bits := range []uint8{0, 24} { // 0 is the RFC 7871 opt-out
		q := query()
		q.SetEdns0(4096, false)
		opt := q.IsEdns0()
		opt.Option = append(opt.Option, &dns.EDNS0_SUBNET{
			Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: bits,
			Address: netip.MustParseAddr("198.51.100.0").AsSlice(),
		})
		sent, resp, cc := serve(t, true, "203.0.113.7:1234", q)
		if s := subnetOf(sent); s == nil || s.SourceNetmask != bits {
			t.Errorf("bits %d: upstream got %+v", bits, s)
		}
		if subnetOf(resp) == nil {
			t.Errorf("bits %d: ECS reply not returned to the client that asked", bits)
		}
		if cc != "max-age=0" {
			t.Errorf("bits %d: Cache-Control = %q", bits, cc)
		}
	}
}

func TestECSNotSent(t *testing.T) {
	cases := []struct {
		name, remote string
		enabled      bool
	}{
		{"disabled", "203.0.113.7:1234", false},
		{"private", "192.168.1.5:1234", true},
		{"loopback", "127.0.0.1:1234", true},
		{"cgnat", "100.64.0.1:1234", true},
		{"ula", "[fd00::1]:1234", true},
		{"link-local", "[fe80::1%en0]:1234", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sent, _, cc := serve(t, tc.enabled, tc.remote, query())
			if sent.IsEdns0() != nil {
				t.Errorf("upstream got OPT: %v", sent.IsEdns0())
			}
			if cc != "max-age=0" {
				t.Errorf("Cache-Control = %q", cc)
			}
		})
	}
}
