/*
Currently only supports the following frameworks:
	1. Cobalt Strike
	2. Empire
	3. Nimhawk
	4. NimPlant
*/

package caddy_c2

import (
	"fmt"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

// Interface guards
var (
	_ caddy.Module                      = (*C2Profile)(nil)
	_ caddyhttp.RequestMatcherWithError = (*C2Profile)(nil)
	_ caddy.Provisioner                 = (*C2Profile)(nil)
	_ caddy.CleanerUpper                = (*C2Profile)(nil)
	_ caddyfile.Unmarshaler             = (*C2Profile)(nil)
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
	Useragent              string
	AllowedGets            []string
	AllowedGetsStartsWith  []string
	AllowedPosts           []string
	AllowedPostsStartsWith []string
	AllowedOptions         []string

	logger *zap.Logger
}

func (m *C2Profile) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			switch d.Val() {
			case "profile":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.Profile = d.Val()
			case "framework":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.Framework = d.Val()
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
		err = m.ParseCobaltStrike()
		if err != nil {
			return fmt.Errorf("parsing error for Cobalt Strike profile: %v", err)
		}
	} else if m.Framework == "empire" {
		err = m.ParseEmpire()
		if err != nil {
			return fmt.Errorf("parsing error for Empire profile: %v", err)
		}
	} else if m.Framework == "nimhawk" {
		err = m.ParseNimhawk()
		if err != nil {
			return fmt.Errorf("parsing error for Nimhawk config: %v", err)
		}
	} else if m.Framework == "nimplant" {
		err = m.ParseNimPlant()
		if err != nil {
			return fmt.Errorf("parsing error for NimPlant config: %v", err)
		}
	} else {
		return fmt.Errorf("framework not supported %s: %v", m.Framework, err)
	}

	m.logger.Info("profile parsed", zap.String("framework", m.Framework), zap.String("profile", m.Profile), zap.String("user_agent", m.Useragent), zap.String("get_requests", strconv.Itoa(len(m.AllowedGets))), zap.String("post_requests", strconv.Itoa(len(m.AllowedPosts))))

	return err
}

// No cleanup necessary
func (m *C2Profile) Cleanup() error {
	return nil
}

// Match based on the profile
func (m *C2Profile) Match(r *http.Request) bool {
	matched, _ := m.MatchWithError(r)
	return matched
}

// MatchWithError implements the newer interface
func (m *C2Profile) MatchWithError(r *http.Request) (bool, error) {
	// Check User-Agent
	if r.Header.Get("User-Agent") != m.Useragent {
		m.logger.Debug("failed User-Agent check", zap.String("ip", r.RemoteAddr), zap.String("method", r.Method), zap.String("uri", r.RequestURI))
		return false, fmt.Errorf("user agent mismatch")
	}

	// Check URLs (disregard the query parameters)
	if r.Method == "GET" {
		// Check if the path starts with any of the allowed GET paths
		for _, path := range m.AllowedGetsStartsWith {
			if strings.HasPrefix(r.URL.Path, path) {
				m.logger.Debug("passed GET starts with check", zap.String("ip", r.RemoteAddr), zap.String("method", r.Method), zap.String("uri", r.RequestURI))
				return true, nil
			}
		}

		// Check specific GET paths
		if !slices.Contains(m.AllowedGets, r.URL.Path) {
			m.logger.Debug("failed GET check", zap.String("ip", r.RemoteAddr), zap.String("method", r.Method), zap.String("uri", r.RequestURI))
			return false, fmt.Errorf("GET path not allowed")
		}
	} else if r.Method == "POST" {
		// Check if the path starts with any of the allowed POST paths
		for _, path := range m.AllowedPostsStartsWith {
			if strings.HasPrefix(r.URL.Path, path) {
				m.logger.Debug("passed POST starts with check", zap.String("ip", r.RemoteAddr), zap.String("method", r.Method), zap.String("uri", r.RequestURI))
				return true, nil
			}
		}

		// Check specific POST paths
		if !slices.Contains(m.AllowedPosts, r.URL.Path) {
			m.logger.Debug("failed POST check", zap.String("ip", r.RemoteAddr), zap.String("method", r.Method), zap.String("uri", r.RequestURI))
			return false, fmt.Errorf("POST path not allowed")
		}
	} else if r.Method == "OPTIONS" {
		if !slices.Contains(m.AllowedOptions, r.URL.Path) {
			m.logger.Debug("failed OPTIONS check", zap.String("ip", r.RemoteAddr), zap.String("method", r.Method), zap.String("uri", r.RequestURI))
			return false, fmt.Errorf("OPTIONS path not allowed")
		}
	} else { // Only GET, POST, and OPTIONS accepted
		m.logger.Debug("method not supported", zap.String("ip", r.RemoteAddr), zap.String("method", r.Method), zap.String("uri", r.RequestURI))
		return false, fmt.Errorf("method not supported")
	}

	m.logger.Debug("passed all checks", zap.String("ip", r.RemoteAddr), zap.String("method", r.Method), zap.String("uri", r.RequestURI))
	return true, nil
}
