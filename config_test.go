package main

import "testing"

func TestRuleMatch(t *testing.T) {
	cases := []struct {
		domain, remap, name string
		ok                  bool
		want                string
	}{
		{"example.com.", "", "example.com.", true, "example.com."},
		{"example.com.", "", "www.example.com.", false, ""},
		{"*.example.com.", "", "a.b.example.com.", true, "a.b.example.com."},
		{"*.example.com.", "", "example.com.", false, ""},
		{"*.example.com.", "", "badexample.com.", false, ""},
		{"old.net.", "new.org.", "old.net.", true, "new.org."},
		{"*.foo.test.", "*.example.com.", "a.b.foo.test.", true, "a.b.example.com."},
		{"*.bar.test.", "example.com.", "x.bar.test.", true, "example.com."},
		{"*", "", "anything.", true, "anything."},
	}
	for _, c := range cases {
		r := Rule{Domain: c.domain, Remap: c.remap}
		ok, got := r.Match(c.name)
		if ok != c.ok || got != c.want {
			t.Errorf("%s/%s on %s: got (%v,%q) want (%v,%q)", c.domain, c.remap, c.name, ok, got, c.ok, c.want)
		}
	}
}
