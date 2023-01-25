package caddy_c2

// Check if array contains a value
func Contains(s []string, v string) bool {
	for _, a := range s {
		if a == v {
			return true
		}
	}
	return false
}
