package config

import "testing"

func TestNormalizeAddr(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ":8080"},
		{":9999", ":9999"},
		{"0.0.0.0:443", "0.0.0.0:443"},
		{"127.0.0.1:7070", "127.0.0.1:7070"},
		{"127.0.0.2:7070", ":127.0.0.2:7070"},
		{"8080", ":8080"},
	}
	for _, c := range cases {
		if got := NormalizeAddr(c.in); got != c.want {
			t.Fatalf("NormalizeAddr(%q)=%q want %q", c.in, got, c.want)
		}
	}
}
