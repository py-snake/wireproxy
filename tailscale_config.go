package wireproxy

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	ini "github.com/go-ini/ini"
)

// defaultStateDirBase is the parent directory used when StateDir is unset.
const defaultStateDirBase = "tsnet"

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
		return nil, errors.New("hostname must not be empty")
	}
	config.Hostname = hostname

	authKey, err := parseString(section, "AuthKey")
	if err != nil {
		return nil, err
	}
	config.AuthKey = authKey

	controlURL, err := parseString(section, "ControlURL")
	if err != nil {
		return nil, err
	}
	config.ControlURL = controlURL

	stateDir, err := parseString(section, "StateDir")
	if err != nil {
		return nil, err
	}
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

// EffectiveStateDir returns the directory where this node persists its
// state. An explicit StateDir wins; otherwise a deterministic per-connection
// path under the user's config/cache dir is derived, so multiple nodes never
// collide and sandboxing rules can be computed up front.
func (c *TailscaleConfig) EffectiveStateDir(connName string) string {
	if c.StateDir != "" {
		return c.StateDir
	}
	base, err := os.UserCacheDir()
	if err != nil || base == "" {
		base = os.TempDir()
	}
	return filepath.Join(base, "wireproxy", defaultStateDirBase, connName)
}

func (c *TailscaleConfig) start(name string, logLevel int) (*VirtualTun, error) {
	return startTsnet(name, c, logLevel)
}
