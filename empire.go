/*
The PowerShell Empire framework uses the same profile structure as Cobalt Strike
*/
package caddy_c2

// Parse Empire profile to get User-Agent, URIs, and Headers
func (m *C2Profile) ParseEmpire() error {
	return m.ParseCobaltStrike()
}
