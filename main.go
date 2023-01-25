/*
Currently only supports the following frameworks:
	1. Cobalt Strike
*/

package caddy_c2

import (
	"fmt"
	"net/http"
	"os"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

// Interface guards
var (
	_ caddy.Module             = (*C2Profile)(nil)
	_ caddyhttp.RequestMatcher = (*C2Profile)(nil)
	_ caddy.Provisioner        = (*C2Profile)(nil)
	_ caddy.CleanerUpper       = (*C2Profile)(nil)
	_ caddyfile.Unmarshaler    = (*C2Profile)(nil)
)

func init() {
	caddy.RegisterModule(C2Profile{})
}

type C2Profile struct {
	// The path of the C2 profile file
	Profile string `json:"profile"`

	// The C2 framework
	Framework string `json:"framework"`

	// Profile data
	Data []byte

	// A list of attributes to get from the profiles
	Useragent    string
	AllowedGets  []string
	AllowedPosts []string

	logger *zap.Logger
}

func (m *C2Profile) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			switch d.Val() {
			case "profile":
				m.Profile = d.Val()
			case "framework":
				m.Framework = d.Val()
			default:
				return fmt.Errorf("unexpected config parameter %s", d.Val())
			}
		}
	}
	return nil
}

func (C2Profile) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.c2_profile",
		New: func() caddy.Module { return new(C2Profile) },
	}
}

func (m *C2Profile) Provision(ctx caddy.Context) error {
	var err error
	m.logger = ctx.Logger(m)

	// Read in profile
	m.Data, err = os.ReadFile(m.Profile)
	if err != nil {
		return fmt.Errorf("cannot open profile %s: %v", m.Profile, err)
	}

	// Parse profile and confirm it's a valid profile
	if m.Framework == "cobaltstrike" {
		err = m.parseCobaltStrike()
		if err != nil {
			return fmt.Errorf("parsing error for Cobalt Strike profile: %v", err)
		}
	} else {
		return fmt.Errorf("framework not supported %s: %v", m.Framework, err)
	}

	return err
}

// No cleanup necessary
func (m *C2Profile) Cleanup() error {
	return nil
}

// Match based on the profile
func (m *C2Profile) Match(r *http.Request) bool {
	// Check User-Agent
	if r.Header.Get("User-Agent") != m.Useragent {
		return false
	}

	// Check URIs
	if r.Method == "GET" {
		if !contains(m.AllowedGets, r.RequestURI) {
			return false
		}
	} else if r.Method == "POST" {
		if !contains(m.AllowedPosts, r.RequestURI) {
			return false
		}

	} else { // Only GET and POST accepted
		return false
	}

	return true
}
