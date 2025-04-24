package caddy_c2

import (
	"github.com/pelletier/go-toml/v2"
)

type NimhawkConfig struct {
	AdminAPI struct {
		IP   string `toml:"ip"`
		Port int    `toml:"port"`
	} `toml:"admin_api"`
	ImplantsServer struct {
		Type          string `toml:"type"`
		SslCertPath   string `toml:"sslCertPath"`
		SslKeyPath    string `toml:"sslKeyPath"`
		Hostname      string `toml:"hostname"`
		Port          int    `toml:"port"`
		RegisterPath  string `toml:"registerPath"`
		TaskPath      string `toml:"taskPath"`
		ResultPath    string `toml:"resultPath"`
		ReconnectPath string `toml:"reconnectPath"`
	} `toml:"implants_server"`
	Implant struct {
		ImplantCallbackIP         string `toml:"implantCallbackIp"`
		RiskyMode                 bool   `toml:"riskyMode"`
		SleepMask                 bool   `toml:"sleepMask"`
		SleepTime                 int    `toml:"sleepTime"`
		SleepJitter               int    `toml:"sleepJitter"`
		KillDate                  string `toml:"killDate"`
		UserAgent                 string `toml:"userAgent"`
		HTTPAllowCommunicationKey string `toml:"httpAllowCommunicationKey"`
		MaxReconnectionAttemps    int    `toml:"maxReconnectionAttemps"`
	} `toml:"implant"`
	Auth struct {
		Enabled         bool `toml:"enabled"`
		SessionDuration int  `toml:"session_duration"`
		Users           []struct {
			Email    string `toml:"email"`
			Password string `toml:"password"`
			Admin    bool   `toml:"admin"`
		} `toml:"users"`
	} `toml:"auth"`
}

// Parse Nimhawk profile to get User-Agent and URIs
func (m *C2Profile) ParseNimhawk() error {
	var parsed NimhawkConfig

	// Parse data
	err := toml.Unmarshal(m.Data, &parsed)
	if err != nil {
		return err
	}

	// Get useragent
	m.Useragent = parsed.Implant.UserAgent

	// GET starts with details
	m.AllowedGetsStartsWith = append(m.AllowedGetsStartsWith, parsed.ImplantsServer.TaskPath)

	// GET details
	m.AllowedGets = append(m.AllowedGets, parsed.ImplantsServer.RegisterPath)
	m.AllowedGets = append(m.AllowedGets, parsed.ImplantsServer.TaskPath)

	// POST details
	m.AllowedPosts = append(m.AllowedPosts, parsed.ImplantsServer.RegisterPath)
	m.AllowedPosts = append(m.AllowedPosts, parsed.ImplantsServer.TaskPath)
	m.AllowedPosts = append(m.AllowedPosts, parsed.ImplantsServer.TaskPath+"/u")
	m.AllowedPosts = append(m.AllowedPosts, parsed.ImplantsServer.ResultPath)

	// OPTIONS details
	m.AllowedOptions = append(m.AllowedOptions, parsed.ImplantsServer.ReconnectPath)

	return err
}
