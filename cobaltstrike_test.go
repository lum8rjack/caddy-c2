package caddy_c2

import (
	"os"
	"testing"
)

var (
	CS_PROFILES []string = []string{
		"tests/profiles/cobaltstrike.profile",
	}

	CS_USERAGENTS []string = []string{
		"Mozilla/5.0 (Windows NT 6.1) AppleWebKit/587.38 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36",
	}

	CS_GETURI [][]string = [][]string{
		{"/login", "/config", "/admin", "/Console", "/console"},
	}

	CS_POSTURI [][]string = [][]string{
		{"/Login", "/Config", "/Admin"},
	}
)

// TestParseCobaltStrike
// Validates the function correctly parses Cobalt Strike
// profiles and has the correct User-Agent, GET URIs and
// POST URIs.
func TestParseCobaltStrike(t *testing.T) {
	// Setup the caddy module
	module := &C2Profile{
		Profile:   "",
		Framework: "cobaltstrike",
	}
	var err error

	// Loop through each example profile
	for n, p := range CS_PROFILES {
		module.Profile = p
		// Read the file
		module.Data, err = os.ReadFile(p)
		if err != nil {
			t.Fatalf("error reading profile %s: %s\n", p, err)
		}

		// Parse the data
		err = module.ParseCobaltStrike()
		if err != nil {
			t.Fatalf("error parsing profile %s: %s\n", p, err)
		}

		// Confirm User-Agent
		if CS_USERAGENTS[n] != module.Useragent {
			t.Fatalf("invalid User-Agent: Got %s but should have got %s\n", module.Useragent, CS_USERAGENTS[n])
		}

		// Confirm GET URIs
		for _, g := range module.AllowedGets {
			if !Contains(CS_GETURI[n], g) {
				t.Fatalf("GET URI %s not in the list\n", g)
			}
		}
		if len(CS_GETURI[n]) != len(module.AllowedGets) {
			t.Fatalf("Number of GET URIs in the profile %d does not equal %d\n", len(module.AllowedGets), len(CS_GETURI[n]))
		}

		// Confirm POST URIs
		for _, g := range module.AllowedPosts {
			if !Contains(CS_POSTURI[n], g) {
				t.Fatalf("POST URI %s not in the list\n", g)
			}
		}
		if len(CS_POSTURI[n]) != len(module.AllowedPosts) {
			t.Fatalf("Number of POST URIs in the profile %d does not equal %d\n", len(module.AllowedPosts), len(CS_POSTURI[n]))
		}
	}
}
