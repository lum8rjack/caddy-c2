package caddy_c2

import (
	"os"
	"slices"
	"testing"
)

var (
	NIMHAWK_PROFILES []string = []string{
		"tests/profiles/nimhawk.toml",
	}

	NIMHAWK_USERAGENTS []string = []string{
		"Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko",
	}

	NIMHAWK_GETURI [][]string = [][]string{
		{"/register", "/task"},
	}

	NIMHAWK_GETSTARTWITH [][]string = [][]string{
		{"/task"},
	}

	NIMHAWK_POSTURI [][]string = [][]string{
		{"/register", "/task", "/task/u", "/result"},
	}

	NIMHAWK_POSTSTARTWITH [][]string = [][]string{
		{"/task"},
	}

	NIMHAWK_OPTIONSURI [][]string = [][]string{
		{"/reconnect"},
	}
)

// TestParseNimhawk
// Validates the function correctly parses Nimhawk
// profiles and has the correct User-Agent, GET and POST URIs.
func TestParseNimhawk(t *testing.T) {
	// Setup the caddy module
	module := &C2Profile{
		Profile:   "",
		Framework: "nimhawk",
	}
	var err error

	// Loop through each example profile
	for n, p := range NIMHAWK_PROFILES {
		module.Profile = p
		// Read the file
		module.Data, err = os.ReadFile(p)
		if err != nil {
			t.Fatalf("error reading profile %s: %s\n", p, err)
		}

		// Parse the data
		err = module.ParseNimhawk()
		if err != nil {
			t.Fatalf("error parsing profile %s: %s\n", p, err)
		}

		// Confirm User-Agent
		if NIMHAWK_USERAGENTS[n] != module.Useragent {
			t.Fatalf("invalid User-Agent: Got %s but should have got %s\n", module.Useragent, NIMHAWK_USERAGENTS[n])
		}

		// Confirm GET URIs
		for _, g := range module.AllowedGets {
			if !slices.Contains(NIMHAWK_GETURI[n], g) {
				t.Fatalf("GET URI %s not in the list\n", g)
			}
		}
		if len(NIMHAWK_GETURI[n]) != len(module.AllowedGets) {
			t.Fatalf("Number of GET URIs in the profile %d does not equal %d\n", len(module.AllowedGets), len(NIMHAWK_GETURI[n]))
		}

		// Confirm GET starts with
		for _, g := range module.AllowedGetsStartsWith {
			if !slices.Contains(NIMHAWK_GETSTARTWITH[n], g) {
				t.Fatalf("GET starts with URI %s not in the list\n", g)
			}
		}
		if len(NIMHAWK_GETSTARTWITH[n]) != len(module.AllowedGetsStartsWith) {
			t.Fatalf("Number of GET starts with URIs in the profile %d does not equal %d\n", len(module.AllowedGetsStartsWith), len(NIMHAWK_GETSTARTWITH[n]))
		}

		// Confirm POST URIs
		for _, g := range module.AllowedPosts {
			if !slices.Contains(NIMHAWK_POSTURI[n], g) {
				t.Fatalf("POST URI %s not in the list\n", g)
			}
		}
		if len(NIMHAWK_POSTURI[n]) != len(module.AllowedPosts) {
			t.Fatalf("Number of POST URIs in the profile %d does not equal %d\n", len(module.AllowedPosts), len(NIMHAWK_POSTURI[n]))
		}

		// Confirm OPTIONS URI
		for _, g := range module.AllowedOptions {
			if !slices.Contains(NIMHAWK_OPTIONSURI[n], g) {
				t.Fatalf("OPTIONS URI %s not in the list\n", g)
			}
		}
		if len(NIMHAWK_OPTIONSURI[n]) != len(module.AllowedOptions) {
			t.Fatalf("Number of OPTIONS URIs in the profile %d does not equal %d\n", len(module.AllowedOptions), len(NIMHAWK_OPTIONSURI[n]))
		}
	}
}
