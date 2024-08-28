package caddy_c2

import (
	"github.com/pelletier/go-toml/v2"
)

type NimPlantConfig struct {
	Server struct {
		IP   string `toml:"ip"`
		Port int    `toml:"port"`
	} `toml:"server"`
	Listener struct {
		Type         string `toml:"type"`
		SslCertPath  string `toml:"sslCertPath"`
		SslKeyPath   string `toml:"sslKeyPath"`
		Hostname     string `toml:"hostname"`
		IP           string `toml:"ip"`
		Port         int    `toml:"port"`
		RegisterPath string `toml:"registerPath"`
		TaskPath     string `toml:"taskPath"`
		ResultPath   string `toml:"resultPath"`
	} `toml:"listener"`
	Nimplant struct {
		RiskyMode   bool   `toml:"riskyMode"`
		SleepMask   bool   `toml:"sleepMask"`
		SleepTime   int    `toml:"sleepTime"`
		SleepJitter int    `toml:"sleepJitter"`
		KillDate    string `toml:"killDate"`
		UserAgent   string `toml:"userAgent"`
	} `toml:"nimplant"`
}

// Parse NimPlant profile to get User-Agent and URIs
func (m *C2Profile) ParseNimPlant() error {
	var parsed NimPlantConfig

	// Parse data
	err := toml.Unmarshal(m.Data, &parsed)
	if err != nil {
		return err
	}

	// Get useragent
	m.Useragent = parsed.Nimplant.UserAgent

	// GET details
	m.AllowedGets = append(m.AllowedGets, parsed.Listener.RegisterPath)
	m.AllowedGets = append(m.AllowedGets, parsed.Listener.TaskPath)

	// POST details
	m.AllowedPosts = append(m.AllowedPosts, parsed.Listener.RegisterPath)
	m.AllowedPosts = append(m.AllowedPosts, parsed.Listener.ResultPath)

	return err
}
