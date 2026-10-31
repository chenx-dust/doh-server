package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type Upstream interface {
	Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error)
	String() string
}

func NewUpstream(addr string, timeout time.Duration) (Upstream, error) {
	switch {
	case strings.HasPrefix(addr, "https://"):
		return &dohUpstream{url: addr, client: &http.Client{Timeout: timeout}}, nil
	case strings.HasPrefix(addr, "tls://"):
		return newDNSUpstream("tcp-tls", strings.TrimPrefix(addr, "tls://"), "853", timeout)
	case strings.HasPrefix(addr, "tcp://"):
		return newDNSUpstream("tcp", strings.TrimPrefix(addr, "tcp://"), "53", timeout)
	case strings.HasPrefix(addr, "udp://"):
		return newDNSUpstream("udp", strings.TrimPrefix(addr, "udp://"), "53", timeout)
	case strings.Contains(addr, "://"):
		return nil, fmt.Errorf("unsupported upstream scheme: %s", addr)
	default:
		return newDNSUpstream("udp", addr, "53", timeout)
	}
}

// ---- plain DNS / DoT ----

type dnsUpstream struct {
	addr   string
	client *dns.Client
}

func newDNSUpstream(netw, hostport, defPort string, timeout time.Duration) (*dnsUpstream, error) {
	if _, _, err := net.SplitHostPort(hostport); err != nil {
		hostport = net.JoinHostPort(strings.Trim(hostport, "[]"), defPort)
	}
	c := &dns.Client{Net: netw, Timeout: timeout}
	if netw == "tcp-tls" {
		host, _, _ := net.SplitHostPort(hostport)
		c.TLSConfig = &tls.Config{ServerName: host}
	}
	return &dnsUpstream{addr: hostport, client: c}, nil
}

func (u *dnsUpstream) Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	resp, _, err := u.client.ExchangeContext(ctx, m, u.addr)
	// Retry over TCP if a UDP answer was truncated.
	if err == nil && resp.Truncated && u.client.Net == "udp" {
		tcp := *u.client
		tcp.Net = "tcp"
		resp, _, err = tcp.ExchangeContext(ctx, m, u.addr)
	}
	return resp, err
}

func (u *dnsUpstream) String() string { return u.client.Net + "://" + u.addr }

// ---- DoH (RFC 8484, POST) ----

type dohUpstream struct {
	url    string
	client *http.Client
}

func (u *dohUpstream) Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	q := m.Copy()
	q.Id = 0 // recommended by RFC 8484 for cache friendliness
	wire, err := q.Pack()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.url, bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := u.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", u.url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
	if err != nil {
		return nil, err
	}
	out := new(dns.Msg)
	if err := out.Unpack(body); err != nil {
		return nil, err
	}
	out.Id = m.Id
	return out, nil
}

func (u *dohUpstream) String() string { return u.url }
