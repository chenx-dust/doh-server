package main

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"

	"github.com/miekg/dns"
)

// ECSConfig controls EDNS Client Subnet (RFC 7871): telling upstreams which
// network the DoH client is in, so they can return geographically close answers.
type ECSConfig struct {
	Enabled bool `yaml:"enabled"`
	// How many leading address bits to reveal to upstreams.
	IPv4Prefix int `yaml:"ipv4_prefix"`
	IPv6Prefix int `yaml:"ipv6_prefix"`
	// Proxies (IP or CIDR) whose X-Forwarded-For header is believed. Connections
	// from anyone else are identified by their peer address alone.
	TrustedProxies []string `yaml:"trusted_proxies"`

	trusted []netip.Prefix
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

func (c *ECSConfig) validate() error {
	if c.IPv4Prefix < 1 || c.IPv4Prefix > 32 {
		return fmt.Errorf("ipv4_prefix %d out of range 1-32", c.IPv4Prefix)
	}
	if c.IPv6Prefix < 1 || c.IPv6Prefix > 128 {
		return fmt.Errorf("ipv6_prefix %d out of range 1-128", c.IPv6Prefix)
	}
	for _, s := range c.TrustedProxies {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			a, aerr := netip.ParseAddr(s)
			if aerr != nil {
				return fmt.Errorf("trusted_proxies: invalid IP or CIDR %q", s)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		c.trusted = append(c.trusted, p)
	}
	return nil
}

func (c *ECSConfig) isTrusted(ip netip.Addr) bool {
	return slices.ContainsFunc(c.trusted, func(p netip.Prefix) bool { return p.Contains(ip) })
}

// clientIP returns the address of the DoH client, or the zero Addr if unknown.
// X-Forwarded-For is walked from the nearest hop outwards and stops at the first
// untrusted address, because anything further left is client-controlled.
func (c *ECSConfig) clientIP(r *http.Request) netip.Addr {
	peer, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	ip := peer.Addr().Unmap().WithZone("")
	if !c.isTrusted(ip) {
		return ip
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		hop, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			return netip.Addr{}
		}
		ip = hop.Unmap().WithZone("")
		if !c.isTrusted(ip) {
			return ip
		}
	}
	// Only proxies in the chain: the real client is unknown.
	return netip.Addr{}
}

// addClientSubnet adds an ECS option for ip to req and reports whether it did.
// A query that already carries ECS is left alone, which also honours a client's
// opt-out (source prefix 0). Addresses with no meaning on the public internet
// are not sent, as RFC 7871 advises.
func (c *ECSConfig) addClientSubnet(req *dns.Msg, ip netip.Addr) bool {
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || cgnat.Contains(ip) {
		return false
	}
	opt := req.IsEdns0()
	if opt != nil && slices.ContainsFunc(opt.Option, isSubnet) {
		return false
	}
	if opt == nil {
		req.SetEdns0(1232, false)
		opt = req.IsEdns0()
	}
	family, bits := uint16(1), c.IPv4Prefix
	if ip.Is6() {
		family, bits = 2, c.IPv6Prefix
	}
	masked := netip.PrefixFrom(ip, bits).Masked().Addr()
	opt.Option = append(opt.Option, &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        family,
		SourceNetmask: uint8(bits),
		Address:       net.IP(masked.AsSlice()),
	})
	return true
}

// stripClientSubnet removes what the client didn't ask for from a response to a
// query that addClientSubnet modified: the ECS option, and the whole OPT record
// if the client's query had none (RFC 6891 forbids sending one back).
func stripClientSubnet(resp *dns.Msg, keepOPT bool) {
	resp.Extra = slices.DeleteFunc(resp.Extra, func(rr dns.RR) bool {
		opt, ok := rr.(*dns.OPT)
		if !ok {
			return false
		}
		opt.Option = slices.DeleteFunc(opt.Option, isSubnet)
		return !keepOPT
	})
}

func isSubnet(o dns.EDNS0) bool { return o.Option() == dns.EDNS0SUBNET }
