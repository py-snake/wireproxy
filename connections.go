package wireproxy

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ConnectionSpec couples a parsed configuration with its identity.
type ConnectionSpec struct {
	// Name uniquely identifies the connection; it prefixes log lines and
	// keys the aggregated health endpoint.
	Name string
	// Conf is the parsed configuration of the connection.
	Conf *Configuration
}

// StartConnection starts the backend described by the spec (WireGuard
// device or embedded Tailscale node) and returns its virtual tunnel.
func StartConnection(spec *ConnectionSpec, logLevel int) (*VirtualTun, error) {
	conf := spec.Conf
	switch {
	case conf.Tailscale != nil:
		return conf.Tailscale.start(spec.Name, logLevel)
	default:
		return StartWireguard(conf, logLevel)
	}
}

var connectionNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)

// sanitizeConnectionName normalizes a derived connection name: lowercase,
// non-alphanumeric characters replaced with dashes.
func sanitizeConnectionName(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(name)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	return b.String()
}

// defaultNameFromFile derives a connection name from a configuration file
// path by taking its sanitized basename without extension.
func defaultNameFromFile(path string) string {
	return sanitizeConnectionName(strings.TrimSuffix(filepath.Base(path), filepath.Ext(path)))
}

// LoadConfigSources expands configuration paths into ordered connection
// specifications. A path may be a file or a directory, in which case all
// *.conf files inside are loaded in lexicographic order. Each file may
// define multiple connections via prefixed sections.
//
// infoAddr is the optional health endpoint bind address; when set it takes
// part in cross-connection port conflict validation.
func LoadConfigSources(paths []string, infoAddr string) ([]*ConnectionSpec, error) {
	var files []string
	for _, p := range paths {
		fi, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		if fi.IsDir() {
			entries, err := os.ReadDir(p)
			if err != nil {
				return nil, err
			}
			for _, e := range entries {
				if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".conf") {
					continue
				}
				files = append(files, filepath.Join(p, e.Name()))
			}
			continue
		}
		files = append(files, p)
	}

	if len(files) == 0 {
		return nil, fmt.Errorf("no configuration files found")
	}

	var specs []*ConnectionSpec
	for _, f := range files {
		fileSpecs, err := ParseConfigFile(f)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		specs = append(specs, fileSpecs...)
	}

	if err := ValidateConnections(specs, infoAddr); err != nil {
		return nil, err
	}
	return specs, nil
}

// ValidateConnections enforces cross-connection constraints:
//   - names are valid and unique
//   - host-bound listeners do not conflict across connections
//   - TCPServerTunnel ports are unique within one connection
//   - Tailscale connections do not carry unsupported routines
func ValidateConnections(specs []*ConnectionSpec, infoAddr string) error {
	names := make(map[string]bool)

	type bind struct {
		kind  string
		host  string
		port  string
		owner string
	}
	var binds []bind

	addBind := func(kind, addr, owner string) error {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return fmt.Errorf("invalid address %q: %w", addr, err)
		}
		binds = append(binds, bind{kind: kind, host: host, port: port, owner: owner})
		return nil
	}

	if infoAddr != "" {
		if err := addBind("tcp", infoAddr, "<health endpoint>"); err != nil {
			return err
		}
	}

	for _, spec := range specs {
		if !connectionNamePattern.MatchString(spec.Name) {
			return fmt.Errorf("connection %q: name must match %s", spec.Name, connectionNamePattern.String())
		}
		if names[spec.Name] {
			return fmt.Errorf("duplicate connection name %q", spec.Name)
		}
		names[spec.Name] = true

		listenPorts := map[int]bool{}
		for _, r := range spec.Conf.Routines {
			switch rt := r.(type) {
			case *TCPClientTunnelConfig:
				addBind("tcp", rt.BindAddress.String(), spec.Name)
			case *Socks5Config:
				addBind("tcp", rt.BindAddress, spec.Name)
			case *HTTPConfig:
				addBind("tcp", rt.BindAddress, spec.Name)
			case *SNIConfig:
				addBind("tcp", rt.BindAddress, spec.Name)
			case *UDPProxyTunnelConfig:
				if spec.Conf.Tailscale != nil {
					return fmt.Errorf("connection %q: UDPProxyTunnel is not supported for Tailscale connections", spec.Name)
				}
				addBind("udp", rt.BindAddress, spec.Name)
			case *TCPServerTunnelConfig:
				if listenPorts[rt.ListenPort] {
					return fmt.Errorf("connection %q: TCPServerTunnel ListenPort %d used twice", spec.Name, rt.ListenPort)
				}
				listenPorts[rt.ListenPort] = true
			}
		}
	}

	for i := 0; i < len(binds); i++ {
		for j := i + 1; j < len(binds); j++ {
			a, b := binds[i], binds[j]
			if a.kind != b.kind || a.port != b.port {
				continue
			}
			if a.host == b.host || isWildcardHost(a.host) || isWildcardHost(b.host) {
				return fmt.Errorf("%s listeners %s (%s) and %s (%s) share port %s",
					a.kind, a.owner, net.JoinHostPort(a.host, a.port),
					b.owner, net.JoinHostPort(b.host, b.port), a.port)
			}
		}
	}
	return nil
}

func isWildcardHost(host string) bool {
	return host == "" || host == "0.0.0.0" || host == "::"
}
