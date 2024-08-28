package caddy_c2

import (
	"os"
	"slices"
	"testing"
)

var (
	NIM_PROFILES []string = []string{
		"tests/profiles/nimplant.toml",
	}

	NIM_USERAGENTS []string = []string{
		"NimPlant C2 Client",
	}

	NIM_GETURI [][]string = [][]string{
		{"/register", "/task"},
	}

	NIM_POSTURI [][]string = [][]string{
		{"/register", "/result"},
	}
)

// TestParseNimPlant
// Validates the function correctly parses NimPlant
// profiles and has the correct User-Agent, GET and POST URIs.
func TestParseNimPlant(t *testing.T) {
	// Setup the caddy module
	module := &C2Profile{
		Profile:   "",
		Framework: "nimplant",
	}
	var err error

	// Loop through each example profile
	for n, p := range NIM_PROFILES {
		module.Profile = p
		// Read the file
		module.Data, err = os.ReadFile(p)
		if err != nil {
			t.Fatalf("error reading profile %s: %s\n", p, err)
		}

		// Parse the data
		err = module.ParseNimPlant()
		if err != nil {
			t.Fatalf("error parsing profile %s: %s\n", p, err)
		}

		// Confirm User-Agent
		if NIM_USERAGENTS[n] != module.Useragent {
			t.Fatalf("invalid User-Agent: Got %s but should have got %s\n", module.Useragent, NIM_USERAGENTS[n])
		}

		// Confirm GET URIs
		for _, g := range module.AllowedGets {
			if !slices.Contains(NIM_GETURI[n], g) {
				t.Fatalf("GET URI %s not in the list\n", g)
			}
		}
		if len(NIM_GETURI[n]) != len(module.AllowedGets) {
			t.Fatalf("Number of GET URIs in the profile %d does not equal %d\n", len(module.AllowedGets), len(NIM_GETURI[n]))
		}

		// Confirm POST URIs
		for _, g := range module.AllowedPosts {
			if !slices.Contains(NIM_POSTURI[n], g) {
				t.Fatalf("POST URI %s not in the list\n", g)
			}
		}
		if len(NIM_POSTURI[n]) != len(module.AllowedPosts) {
			t.Fatalf("Number of POST URIs in the profile %d does not equal %d\n", len(module.AllowedPosts), len(NIM_POSTURI[n]))
		}
	}
}
