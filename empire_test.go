package caddy_c2

import (
	"net/url"
	"os"
	"slices"
	"testing"
)

var (
	EMPIRE_PROFILES []string = []string{
		"tests/profiles/empire.profile",
	}

	EMPIRE_USERAGENTS []string = []string{
		"Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko)",
	}

	EMPIRE_GETURI [][]string = [][]string{
		{"/messages/C0527B0NM", "/messages/DALBNSf25", "/messages/DALBNSF25"},
	}

	EMPIRE_POSTURI [][]string = [][]string{
		{"/api/api.test"},
	}

	EMPIRE_GETURI_PARAMS [][]string = [][]string{
		{"/messages/C0527B0NM?d=testing"},
	}
)

// TestParseEmpire
// Validates the function correctly parses Empire
// profiles and has the correct User-Agent, GET URIs and
// POST URIs.
func TestParseEmpire(t *testing.T) {
	// Setup the empire module
	module := &C2Profile{
		Profile:   "",
		Framework: "empire",
	}
	var err error

	// Loop through each example profile
	for n, p := range EMPIRE_PROFILES {
		module.Profile = p
		// Read the file
		module.Data, err = os.ReadFile(p)
		if err != nil {
			t.Fatalf("error reading profile %s: %s\n", p, err)
		}

		// Parse the data
		err = module.ParseEmpire()
		if err != nil {
			t.Fatalf("error parsing profile %s: %s\n", p, err)
		}

		// Confirm User-Agent
		if EMPIRE_USERAGENTS[n] != module.Useragent {
			t.Fatalf("invalid User-Agent: Got %s but should have got %s\n", module.Useragent, EMPIRE_USERAGENTS[n])
		}

		// Confirm GET URIs
		for _, g := range module.AllowedGets {
			if !slices.Contains(EMPIRE_GETURI[n], g) {
				t.Fatalf("GET URI %s not in the list\n", g)
			}
		}
		if len(EMPIRE_GETURI[n]) != len(module.AllowedGets) {
			t.Fatalf("Number of GET URIs in the profile %d does not equal %d\n", len(module.AllowedGets), len(EMPIRE_GETURI[n]))
		}

		// Confirm POST URIs
		for _, g := range module.AllowedPosts {
			if !slices.Contains(EMPIRE_POSTURI[n], g) {
				t.Fatalf("POST URI %s not in the list\n", g)
			}
		}
		if len(EMPIRE_POSTURI[n]) != len(module.AllowedPosts) {
			t.Fatalf("Number of POST URIs in the profile %d does not equal %d\n", len(module.AllowedPosts), len(EMPIRE_POSTURI[n]))
		}

		// Check the added query parameters
		for _, g := range EMPIRE_GETURI_PARAMS[n] {
			path, err := url.Parse("https://127.0.0.1" + g)
			if err != nil {
				t.Fatalf("error parsing url http://127.0.0.1%s n", g)
			}
			if !slices.Contains(module.AllowedGets, path.Path) {
				t.Fatalf("GET URI_PARAMS %s not in the list\n", g)
			}
		}

	}
}
