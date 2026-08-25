package wireproxy

import (
	"errors"
	"strings"

	ini "github.com/go-ini/ini"
)

// TailscaleConfig holds the settings for an embedded Tailscale node
// (tsnet). Connections of this kind are mutually exclusive with WireGuard
// [Interface] connections.
//
// Building a binary that can start Tailscale connections requires the
// "tsnet" build tag (`make wireproxy-tsnet`); without it, configuration
// validation still works but starting such a connection fails.
type TailscaleConfig struct {
	// Hostname is the node name this connection registers as in the tailnet.
	Hostname string
	// AuthKey is an optional pre-auth key (supports $ENV interpolation).
	AuthKey string
	// ControlURL optionally points at an alternate control server
	// (e.g. Headscale). Empty means the official Tailscale coordination
	// server.
	ControlURL string
	// Ephemeral registers the node as ephemeral (auto-removed after
	// disconnect).
	Ephemeral bool
	// StateDir persists node identity/state. Each connection must have a
	// distinct directory when multiple nodes run in one process.
	StateDir string
	// AdvertiseTags requests ACL tags for the node (comma separated).
	AdvertiseTags []string
}

func parseTailscaleConfig(section *ini.Section) (*TailscaleConfig, error) {
	config := &TailscaleConfig{}

	hostname, err := parseString(section, "Hostname")
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(hostname) == "" {
		return nil, errors.New("Hostname should not be empty")
	}
	config.Hostname = hostname

	authKey, _ := parseString(section, "AuthKey")
	config.AuthKey = authKey

	controlURL, _ := parseString(section, "ControlURL")
	config.ControlURL = controlURL

	stateDir, _ := parseString(section, "StateDir")
	config.StateDir = stateDir

	ephemeral, err := parseBoolKey(section, "Ephemeral")
	if err != nil {
		return nil, err
	}
	config.Ephemeral = ephemeral

	if sectionKey, err := section.GetKey("AdvertiseTags"); err == nil {
		for _, tag := range strings.Split(sectionKey.String(), ",") {
			tag = strings.TrimSpace(tag)
			if tag != "" {
				config.AdvertiseTags = append(config.AdvertiseTags, tag)
			}
		}
	}

	return config, nil
}

func (c *TailscaleConfig) start(name string, logLevel int) (*VirtualTun, error) {
	return startTsnet(name, c, logLevel)
}
