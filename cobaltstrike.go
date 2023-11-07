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
func (m *C2Profile) ParseCobaltStrike() error {
	var err error

	// Parse data
	myReader := strings.NewReader(string(m.Data))
	parsed, err := parser.Parse(myReader)
	if err != nil {
		return err
	}

	// Get useragent
	m.Useragent = parsed.UserAgent

	// GET details
	for _, x := range parsed.HTTPGet {
		// URIs
		uris := strings.Split(x.URI.String(), " ")
		m.AllowedGets = append(m.AllowedGets, uris...)
	}

	// POST details
	for _, x := range parsed.HTTPPost {
		// URIs
		uris := strings.Split(x.URI.String(), " ")
		m.AllowedPosts = append(m.AllowedPosts, uris...)
	}

	// HTTP Stager
	for _, x := range parsed.HTTPStager {
		// URIs
		x64 := x.URIx64.String()
		if x64 != "" {
			m.AllowedGets = append(m.AllowedGets, x64)
		}

		x86 := x.URIx86.String()
		if x86 != "" {
			m.AllowedGets = append(m.AllowedGets, x86)
		}
	}

	return err
}
