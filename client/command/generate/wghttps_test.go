package generate

import (
	"net/url"
	"strings"
	"testing"
)

func parseURLForTest(raw string) (*url.URL, error) {
	return url.Parse(raw)
}

func TestParseWGHTTPSc2KeepsSchemeAndPort(t *testing.T) {
	c2s, err := ParseWGHTTPSc2("wg+https://c2.example:8443")
	if err != nil {
		t.Fatalf("ParseWGHTTPSc2(\"wg+https://c2.example:8443\"): %v", err)
	}
	if len(c2s) != 1 {
		t.Fatalf("expected exactly one C2, got %d", len(c2s))
	}
	uri, err := parseURLForTest(c2s[0].URL)
	if err != nil {
		t.Fatalf("parse %s: %v", c2s[0].URL, err)
	}
	if uri.Scheme != "wg+https" {
		t.Fatalf("scheme not preserved: got %q", uri.Scheme)
	}
	if uri.Port() != "8443" {
		t.Fatalf("port not preserved: got %q", uri.Port())
	}
}

func TestParseWGHTTPSc2DefaultsPort(t *testing.T) {
	c2s, err := ParseWGHTTPSc2("wg+https://c2.example")
	if err != nil {
		t.Fatalf("ParseWGHTTPSc2(\"wg+https://c2.example\"): %v", err)
	}
	uri, err := parseURLForTest(c2s[0].URL)
	if err != nil {
		t.Fatalf("parse %s: %v", c2s[0].URL, err)
	}
	if uri.Port() != "443" {
		t.Fatalf("default port not applied: got %q", uri.Port())
	}
}

func TestParseWGHTTPSc2RejectsBareHost(t *testing.T) {
	if _, err := ParseWGHTTPSc2("c2.example:443"); err == nil {
		t.Fatal("expected rejection of bare host without wg+https:// prefix")
	}
}

func TestParseWGHTTPSc2RejectsOtherSchemes(t *testing.T) {
	for _, arg := range []string{"wg://c2.example:53", "https://c2.example:443", "mtls://c2.example:8888"} {
		if _, err := ParseWGHTTPSc2(arg); err == nil {
			t.Fatalf("expected rejection of %q", arg)
		}
	}
}

func TestParseWGHTTPSc2RejectsBadPollInterval(t *testing.T) {
	for _, arg := range []string{
		"wg+https://c2.example:443?wg-poll-interval=500ms",
		"wg+https://c2.example:443?wg-poll-interval=999",
		"wg+https://c2.example:443?wg-poll-interval=11m",
		"wg+https://c2.example:443?wg-poll-interval=0s",
	} {
		if _, err := ParseWGHTTPSc2(arg); err == nil {
			t.Fatalf("expected rejection of %q", arg)
		}
	}
}

func TestParseWGHTTPSc2AcceptsAllowedOptions(t *testing.T) {
	c2s, err := ParseWGHTTPSc2("wg+https://c2.example:443?net-timeout=60s&tls-timeout=15s&proxy=http://proxy.example:8080&wg-poll-interval=30s")
	if err != nil {
		t.Fatalf("expected allowed options to parse: %v", err)
	}
	if len(c2s) != 1 {
		t.Fatalf("expected exactly one C2, got %d", len(c2s))
	}
}

func TestParseWGHTTPSc2PreservesProxyCredentialCase(t *testing.T) {
	c2s, err := ParseWGHTTPSc2("wg+https://c2.example:443?proxy=http://User:Secret@proxy.example:8080")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !strings.Contains(c2s[0].URL, "User:Secret") {
		t.Fatalf("proxy credentials were rewritten: %s", c2s[0].URL)
	}
}

func TestParseWGHTTPSc2RejectsUnknownOptions(t *testing.T) {
	for _, arg := range []string{
		"wg+https://c2.example:443?host-header=evil.example",
		"wg+https://c2.example:443?poll-timeout=30s",
	} {
		if _, err := ParseWGHTTPSc2(arg); err == nil {
			t.Fatalf("expected rejection of %q", arg)
		}
	}
}
