/*
There are a few things the parser/module does not account for with the profile:

 1. The parser/module does not check the header details of the profile.

 2. The parser/module does not validate the Verb set in the profile. It defaults
    to GET requests as valid for http-get block and POST request as valid for
    http-post block.
    Example:
    This module will block all traffic if http-get block is set with `set verb "POST"`

 3. The http-stage `set uri_x86` and `set uri_x86` options are added to the
    AllowedGets array.
*/
package caddy_c2

import (
	"strings"

	parser "github.com/D00Movenok/goMalleable"
)

// Parse Cobalt Strike profile to get User-Agent, URIs, and Headers
func (m *C2Profile) parseCobaltStrike() error {
	var err error

	// Parse data
	parsed, err := parser.Parse(string(m.Data))
	if err != nil {
		return err
	}

	// Get useragent
	m.Useragent = parsed.Globals["useragent"]

	// GET details
	for _, x := range parsed.HttpGet {
		// URIs
		y := strings.Split(x.Params["uri"], " ")
		m.AllowedGets = append(m.AllowedGets, y...)
	}

	// POST details
	for _, x := range parsed.HttpPost {
		// URIs
		y := strings.Split(x.Params["uri"], " ")
		m.AllowedPosts = append(m.AllowedPosts, y...)
	}

	// HTTP Stager
	for _, x := range parsed.HttpStager {
		// URIs
		x64 := x.Params["uri_x64"]
		if x64 != "" {
			m.AllowedGets = append(m.AllowedGets, x64)
		}

		x86 := x.Params["uri_x86"]
		if x86 != "" {
			m.AllowedGets = append(m.AllowedGets, x86)
		}
	}

	return err
}
