package wireproxy

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/go-ini/ini"

	"net/netip"
)

type PeerConfig struct {
	PublicKey    string
	PreSharedKey string
	Endpoint     *string
	KeepAlive    int
	AllowedIPs   []netip.Prefix
}

// DeviceConfig contains the information to initiate a wireguard connection
type DeviceConfig struct {
	SecretKey          string
	Endpoint           []netip.Addr
	Peers              []PeerConfig
	DNS                []netip.Addr
	MTU                int
	ListenPort         *int
	CheckAlive         []netip.Addr
	CheckAliveInterval int
}

type UDPProxyTunnelConfig struct {
	BindAddress       string
	Target            string
	InactivityTimeout int
}

type TCPClientTunnelConfig struct {
	BindAddress *net.TCPAddr
	Target      string
}

type STDIOTunnelConfig struct {
	Target string
	Input  *os.File
	Output *os.File
}

type TCPServerTunnelConfig struct {
	ListenPort int
	Target     string
}

type Socks5Config struct {
	BindAddress   string
	Username      string
	Password      string
	TunnelDomains []*regexp.Regexp
	LogDomains    bool
}

type SNIConfig struct {
	BindAddress   string
	TunnelDomains []*regexp.Regexp
	LogDomains    bool
}

type HTTPConfig struct {
	BindAddress   string
	Username      string
	Password      string
	CertFile      string
	KeyFile       string
	TunnelDomains []*regexp.Regexp
	LogDomains    bool
}

type ResolveConfig struct {
	ResolveStrategy string
}

type Configuration struct {
	// Name is the unique identifier of this connection (used in logs and
	// the aggregated health endpoint).
	Name string
	// Device holds the WireGuard device configuration. Mutually exclusive
	// with Tailscale.
	Device *DeviceConfig
	// Tailscale holds an embedded tsnet node configuration. Mutually
	// exclusive with Device.
	Tailscale *TailscaleConfig
	Routines  []RoutineSpawner
	Resolve   *ResolveConfig
}

func parseString(section *ini.Section, keyName string) (string, error) {
	key := section.Key(strings.ToLower(keyName))
	if key == nil {
		return "", errors.New(keyName + " should not be empty")
	}
	value := key.String()
	if strings.HasPrefix(value, "$") {
		if strings.HasPrefix(value, "$$") {
			return strings.Replace(value, "$$", "$", 1), nil
		}
		var ok bool
		value, ok = os.LookupEnv(strings.TrimPrefix(value, "$"))
		if !ok {
			return "", errors.New(keyName + " references unset environment variable " + key.String())
		}
		return value, nil
	}
	return key.String(), nil
}

func parsePort(section *ini.Section, keyName string) (int, error) {
	key := section.Key(keyName)
	if key == nil {
		return 0, errors.New(keyName + " should not be empty")
	}

	port, err := key.Int()
	if err != nil {
		return 0, err
	}

	if port < 0 || port >= 65536 {
		return 0, errors.New("port should be >= 0 and < 65536")
	}

	return port, nil
}

func parseTCPAddr(section *ini.Section, keyName string) (*net.TCPAddr, error) {
	addrStr, err := parseString(section, keyName)
	if err != nil {
		return nil, err
	}
	return net.ResolveTCPAddr("tcp", addrStr)
}

func parseBase64KeyToHex(section *ini.Section, keyName string) (string, error) {
	key, err := parseString(section, keyName)
	if err != nil {
		return "", err
	}
	result, err := encodeBase64ToHex(key)
	if err != nil {
		return result, err
	}

	return result, nil
}
func encodeBase64ToHex(key string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		// Do not echo the value: it may be a mistyped private key.
		return "", errors.New("invalid base64 key material")
	}
	if len(decoded) != 32 {
		return "", errors.New("key should be 32 bytes")
	}

	return hex.EncodeToString(decoded), nil
}

func parseNetIP(section *ini.Section, keyName string) ([]netip.Addr, error) {
	key, err := parseString(section, keyName)
	if err != nil {
		if strings.Contains(err.Error(), "should not be empty") {
			return []netip.Addr{}, nil
		}
		return nil, err
	}

	keys := strings.Split(key, ",")
	var ips = make([]netip.Addr, 0, len(keys))
	for _, str := range keys {
		str = strings.TrimSpace(str)
		if len(str) == 0 {
			continue
		}
		ip, err := netip.ParseAddr(str)
		if err != nil {
			return nil, err
		}
		ips = append(ips, ip)
	}
	return ips, nil
}

func parseCIDRNetIP(section *ini.Section, keyName string) ([]netip.Addr, error) {
	key, err := parseString(section, keyName)
	if err != nil {
		if strings.Contains(err.Error(), "should not be empty") {
			return []netip.Addr{}, nil
		}
		return nil, err
	}

	keys := strings.Split(key, ",")
	var ips = make([]netip.Addr, 0, len(keys))
	for _, str := range keys {
		str = strings.TrimSpace(str)
		if len(str) == 0 {
			continue
		}

		if addr, err := netip.ParseAddr(str); err == nil {
			ips = append(ips, addr)
		} else {
			prefix, err := netip.ParsePrefix(str)
			if err != nil {
				return nil, err
			}

			addr := prefix.Addr()
			ips = append(ips, addr)
		}
	}
	return ips, nil
}

func parseAllowedIPs(section *ini.Section) ([]netip.Prefix, error) {
	key, err := parseString(section, "AllowedIPs")
	if err != nil {
		if strings.Contains(err.Error(), "should not be empty") {
			return []netip.Prefix{}, nil
		}
		return nil, err
	}

	keys := strings.Split(key, ",")
	var ips = make([]netip.Prefix, 0, len(keys))
	for _, str := range keys {
		str = strings.TrimSpace(str)
		if len(str) == 0 {
			continue
		}
		prefix, err := netip.ParsePrefix(str)
		if err != nil {
			return nil, err
		}

		ips = append(ips, prefix)
	}
	return ips, nil
}

func resolveIP(ip string) (*net.IPAddr, error) {
	return net.ResolveIPAddr("ip", ip)
}

func resolveIPPAndPort(addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}

	ip, err := resolveIP(host)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(ip.String(), port), nil
}

// ParseInterface parses the [Interface] section and extracts the
// information into `device`
func ParseInterface(cfg *ini.File, device *DeviceConfig) error {
	sections, err := cfg.SectionsByName("Interface")
	if len(sections) != 1 || err != nil {
		return errors.New("one and only one [Interface] is expected")
	}
	return parseInterfaceSection(sections[0], device)
}

// ParsePeers parses the [Peer] sections and extracts the information into `peers`
func ParsePeers(cfg *ini.File, peers *[]PeerConfig) error {
	sections, err := cfg.SectionsByName("Peer")
	if len(sections) < 1 || err != nil {
		return errors.New("at least one [Peer] is expected")
	}
	return parsePeerSections(sections, peers)
}

func parseTCPClientTunnelConfig(section *ini.Section) (RoutineSpawner, error) {
	config := &TCPClientTunnelConfig{}
	tcpAddr, err := parseTCPAddr(section, "BindAddress")
	if err != nil {
		return nil, err
	}
	config.BindAddress = tcpAddr

	targetSection, err := parseString(section, "Target")
	if err != nil {
		return nil, err
	}
	config.Target = targetSection

	return config, nil
}

func parseSTDIOTunnelConfig(section *ini.Section) (RoutineSpawner, error) {
	config := &STDIOTunnelConfig{}
	targetSection, err := parseString(section, "Target")
	if err != nil {
		return nil, err
	}
	config.Target = targetSection
	config.Input = os.Stdin
	config.Output = os.Stdout

	return config, nil
}

func parseTCPServerTunnelConfig(section *ini.Section) (RoutineSpawner, error) {
	config := &TCPServerTunnelConfig{}

	listenPort, err := parsePort(section, "ListenPort")
	if err != nil {
		return nil, err
	}
	config.ListenPort = listenPort

	target, err := parseString(section, "Target")
	if err != nil {
		return nil, err
	}
	config.Target = target

	return config, nil
}

// parseRegexList reads a whitelist of regular expressions from a section key.
// Each occurrence of the key (one per line; AllowShadows is enabled) is treated
// as a single, complete regex — the value is NOT split on commas, so quantifiers
// like `a{2,4}` work. An absent key yields no patterns. An invalid pattern is a
// configuration error, so --configtest rejects it before any traffic flows.
func parseRegexList(section *ini.Section, keyName string) ([]*regexp.Regexp, error) {
	key, err := section.GetKey(keyName)
	if err != nil {
		return nil, nil
	}

	var patterns []*regexp.Regexp
	for _, raw := range key.ValueWithShadows() {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		re, cerr := regexp.Compile(raw)
		if cerr != nil {
			return nil, errors.New("invalid " + keyName + " regex `" + raw + "`: " + cerr.Error())
		}
		patterns = append(patterns, re)
	}
	return patterns, nil
}

// parseBoolKey reads an optional boolean key, defaulting to false when absent.
func parseBoolKey(section *ini.Section, keyName string) (bool, error) {
	key, err := section.GetKey(keyName)
	if err != nil {
		return false, nil
	}
	return key.Bool()
}

func parseSocks5Config(section *ini.Section) (RoutineSpawner, error) {
	config := &Socks5Config{}

	bindAddress, err := parseString(section, "BindAddress")
	if err != nil {
		return nil, err
	}
	config.BindAddress = bindAddress

	username, err := parseString(section, "Username")
	if err != nil {
		return nil, err
	}
	config.Username = username

	password, err := parseString(section, "Password")
	if err != nil {
		return nil, err
	}
	config.Password = password

	tunnelDomains, err := parseRegexList(section, "TunnelDomains")
	if err != nil {
		return nil, err
	}
	config.TunnelDomains = tunnelDomains

	logDomains, err := parseBoolKey(section, "LogDomains")
	if err != nil {
		return nil, err
	}
	config.LogDomains = logDomains

	return config, nil
}

func parseSNIConfig(section *ini.Section) (RoutineSpawner, error) {
	config := &SNIConfig{}

	bindAddress, err := parseString(section, "BindAddress")
	if err != nil {
		return nil, err
	}
	config.BindAddress = bindAddress

	tunnelDomains, err := parseRegexList(section, "TunnelDomains")
	if err != nil {
		return nil, err
	}
	config.TunnelDomains = tunnelDomains

	logDomains, err := parseBoolKey(section, "LogDomains")
	if err != nil {
		return nil, err
	}
	config.LogDomains = logDomains

	return config, nil
}

func parseHTTPConfig(section *ini.Section) (RoutineSpawner, error) {
	config := &HTTPConfig{}

	bindAddress, err := parseString(section, "BindAddress")
	if err != nil {
		return nil, err
	}
	config.BindAddress = bindAddress

	username, err := parseString(section, "Username")
	if err != nil {
		return nil, err
	}
	config.Username = username

	password, err := parseString(section, "Password")
	if err != nil {
		return nil, err
	}
	config.Password = password

	certFile, err := parseString(section, "CertFile")
	if err != nil {
		return nil, err
	}
	config.CertFile = certFile

	keyFile, err := parseString(section, "KeyFile")
	if err != nil {
		return nil, err
	}
	config.KeyFile = keyFile

	tunnelDomains, err := parseRegexList(section, "TunnelDomains")
	if err != nil {
		return nil, err
	}
	config.TunnelDomains = tunnelDomains

	logDomains, err := parseBoolKey(section, "LogDomains")
	if err != nil {
		return nil, err
	}
	config.LogDomains = logDomains

	return config, nil
}

func parseResolveConfig(section *ini.Section) (*ResolveConfig, error) {
	config := &ResolveConfig{}

	resolvStrategy, _ := parseString(section, "ResolveStrategy")
	switch strings.ToLower(strings.TrimSpace(resolvStrategy)) {
	case "ipv4", "ipv6":
		config.ResolveStrategy = strings.ToLower(resolvStrategy)
	case "":
		// Absent or empty strategy behaves like a missing [Resolve]
		// section: automatic selection.
		config.ResolveStrategy = "auto"
	default:
		return nil, errors.New("ResolveStrategy must be one of: auto, ipv4, ipv6")
	}

	return config, nil
}

func parseUDPProxyTunnelConfig(section *ini.Section) (RoutineSpawner, error) {
	config := &UDPProxyTunnelConfig{}

	bindAddress, err := parseString(section, "BindAddress")
	if err != nil {
		return nil, err
	}
	config.BindAddress = bindAddress

	target, err := parseString(section, "Target")
	if err != nil {
		return nil, err
	}
	config.Target = target

	inactivityTimeout := 0
	if sectionKey, err := section.GetKey("InactivityTimeout"); err == nil {
		timeoutVal, err := sectionKey.Int()
		if err != nil {
			return nil, err
		}
		inactivityTimeout = timeoutVal
	}
	config.InactivityTimeout = inactivityTimeout

	return config, nil
}

// routineParsers maps a section type onto its parser. The order determines
// the spawn order of routines inside one connection.
var routineParsers = []struct {
	sectionType string
	parse       func(*ini.Section) (RoutineSpawner, error)
}{
	{"tcpclienttunnel", parseTCPClientTunnelConfig},
	{"stdiotunnel", parseSTDIOTunnelConfig},
	{"tcpservertunnel", parseTCPServerTunnelConfig},
	{"socks5", parseSocks5Config},
	{"http", parseHTTPConfig},
	{"sni", parseSNIConfig},
	{"udpproxytunnel", parseUDPProxyTunnelConfig},
}

// connGroup collects the sections belonging to one connection while
// preserving their file order. The unnamed group is the implicit default
// connection used by classic single-connection configurations.
type connGroup struct {
	name string

	iface     []*ini.Section
	peers     []*ini.Section
	tailscale []*ini.Section
	resolve   []*ini.Section
	routines  map[string][]*ini.Section
}

func newConnGroup(name string) *connGroup {
	return &connGroup{name: name, routines: make(map[string][]*ini.Section)}
}

// splitIntoGroups partitions all named sections into connections. Sections
// named "<group>.<Type>" belong to connection <group>; everything else
// belongs to the default connection. The returned ini.Section is the
// DEFAULT section holding root keys (e.g. WGConfig, Name).
func splitIntoGroups(cfg *ini.File) (*ini.Section, []*connGroup, error) {
	root := cfg.Section(ini.DefaultSection)
	groups := make([]*connGroup, 0, 1)
	byName := make(map[string]*connGroup)

	for _, section := range cfg.Sections() {
		name := section.Name()
		// The DEFAULT section holds root keys; under Insensitive its name
		// is lowercased, so compare case-insensitively.
		if name == "" || strings.EqualFold(name, ini.DefaultSection) {
			continue
		}

		groupName := ""
		sectionType := name
		if idx := strings.IndexByte(name, '.'); idx >= 0 {
			groupName, sectionType = name[:idx], name[idx+1:]
			// Group names feed logs, health keys and file-derived names:
			// normalize them up front so different spellings cannot alias.
			groupName = sanitizeConnectionName(groupName)
			if groupName == "" {
				return nil, nil, errors.New("invalid connection group name in section " + name)
			}
		}

		g, ok := byName[groupName]
		if !ok {
			g = newConnGroup(groupName)
			byName[groupName] = g
			groups = append(groups, g)
		}

		switch sectionType {
		case "interface":
			g.iface = append(g.iface, section)
		case "peer":
			g.peers = append(g.peers, section)
		case "tailscale":
			g.tailscale = append(g.tailscale, section)
		case "resolve":
			g.resolve = append(g.resolve, section)
		default:
			g.routines[sectionType] = append(g.routines[sectionType], section)
		}
	}
	return root, groups, nil
}

// parseInterfaceSection fills device from a single [Interface] section.
func parseInterfaceSection(section *ini.Section, device *DeviceConfig) error {
	address, err := parseCIDRNetIP(section, "Address")
	if err != nil {
		return err
	}
	device.Endpoint = address

	privKey, err := parseBase64KeyToHex(section, "PrivateKey")
	if err != nil {
		return err
	}
	device.SecretKey = privKey

	dns, err := parseNetIP(section, "DNS")
	if err != nil {
		return err
	}
	device.DNS = dns

	if sectionKey, err := section.GetKey("MTU"); err == nil {
		value, err := sectionKey.Int()
		if err != nil {
			return err
		}
		device.MTU = value
	}

	if sectionKey, err := section.GetKey("ListenPort"); err == nil {
		value, err := sectionKey.Int()
		if err != nil {
			return err
		}
		device.ListenPort = &value
	}

	checkAlive, err := parseNetIP(section, "CheckAlive")
	if err != nil {
		return err
	}
	device.CheckAlive = checkAlive

	device.CheckAliveInterval = 5
	if sectionKey, err := section.GetKey("CheckAliveInterval"); err == nil {
		value, err := sectionKey.Int()
		if err != nil {
			return err
		}
		if len(checkAlive) == 0 {
			return errors.New("CheckAliveInterval is only valid when CheckAlive is set")
		}
		if value < 1 || value > 86400 {
			return errors.New("CheckAliveInterval must be between 1 and 86400 seconds")
		}

		device.CheckAliveInterval = value
	}

	return nil
}

// parsePeerSections fills peers from [Peer] sections.
func parsePeerSections(sections []*ini.Section, peers *[]PeerConfig) error {
	for _, section := range sections {
		peer := PeerConfig{
			PreSharedKey: "0000000000000000000000000000000000000000000000000000000000000000",
			KeepAlive:    0,
		}

		decoded, err := parseBase64KeyToHex(section, "PublicKey")
		if err != nil {
			return err
		}
		peer.PublicKey = decoded

		if sectionKey, err := section.GetKey("PreSharedKey"); err == nil {
			value, err := encodeBase64ToHex(sectionKey.String())
			if err != nil {
				return err
			}
			peer.PreSharedKey = value
		}

		if sectionKey, err := section.GetKey("Endpoint"); err == nil {
			value := sectionKey.String()
			decoded, err = resolveIPPAndPort(strings.ToLower(value))
			if err != nil {
				return err
			}
			peer.Endpoint = &decoded
		}

		if sectionKey, err := section.GetKey("PersistentKeepalive"); err == nil {
			value, err := sectionKey.Int()
			if err != nil {
				return err
			}
			peer.KeepAlive = value
		}

		peer.AllowedIPs, err = parseAllowedIPs(section)
		if err != nil {
			return err
		}

		*peers = append(*peers, peer)
	}
	return nil
}

// wgIniOptions are the options used for loading wireproxy and plain
// WireGuard configuration files alike.
var wgIniOptions = ini.LoadOptions{
	Insensitive:            true,
	AllowShadows:           true,
	AllowNonUniqueSections: true,
}

// resolveWGConfigPath resolves a WGConfig value relative to the directory of
// the referencing wireproxy configuration unless it is absolute. This covers
// bare filenames as well as subdirectory-relative paths, so launches from any
// working directory behave identically.
func resolveWGConfigPath(wgPath, parentDir string) string {
	if !filepath.IsAbs(wgPath) {
		wgPath = filepath.Join(parentDir, wgPath)
	}
	return wgPath
}

// parse turns one group of sections into a Configuration. sourcePath is the
// path of the wireproxy config file (used to resolve relative WGConfig
// paths); root holds the file's root keys (e.g. WGConfig for the default
// connection).
func (g *connGroup) parse(sourcePath string, root *ini.Section) (*Configuration, error) {
	resolve := &ResolveConfig{ResolveStrategy: "auto"}
	if len(g.resolve) > 0 {
		r, err := parseResolveConfig(g.resolve[0])
		if err != nil {
			return nil, err
		}
		resolve = r
	}

	conf := &Configuration{Name: g.name, Resolve: resolve}

	// A [Tailscale] section makes this a Tailscale connection; WireGuard
	// sections must not be mixed in.
	if len(g.tailscale) > 0 {
		if len(g.iface) > 0 || len(g.peers) > 0 {
			return nil, errors.New("[Tailscale] cannot be combined with [Interface] or [Peer] sections in the same connection")
		}
		if len(g.tailscale) > 1 {
			return nil, errors.New("at most one [Tailscale] section is expected per connection")
		}
		tsConf, err := parseTailscaleConfig(g.tailscale[0])
		if err != nil {
			return nil, err
		}
		conf.Tailscale = tsConf
		return g.appendRoutines(conf)
	}

	device := &DeviceConfig{MTU: 1420}
	parentDir := filepath.Dir(sourcePath)

	// Determine where the WireGuard device configuration comes from:
	//   - an external file referenced by a WGConfig key inside this
	//     group's [Interface] section (any connection), or by the root
	//     WGConfig key (default connection only)
	//   - or inline [Interface]/[Peer] sections
	externalPath := ""
	switch len(g.iface) {
	case 0:
		if g.name != "" {
			return nil, errors.New("one and only one [Interface] is expected")
		}
		if key, err := root.GetKey("WGConfig"); err == nil {
			externalPath = resolveWGConfigPath(key.String(), parentDir)
		} else {
			return nil, errors.New("one and only one [Interface] is expected")
		}
	case 1:
		if key, err := g.iface[0].GetKey("WGConfig"); err == nil {
			// Allow specific override fields alongside WGConfig
			for _, forbidden := range []string{"PrivateKey", "Address"} {
				if _, err := g.iface[0].GetKey(forbidden); err == nil {
					return nil, errors.New("[Interface] must not combine WGConfig with inline " + forbidden)
				}
			}
			externalPath = resolveWGConfigPath(key.String(), parentDir)
		}
	default:
		return nil, errors.New("one and only one [Interface] is expected")
	}

	if externalPath != "" {
		wgCfg, err := ini.LoadSources(wgIniOptions, externalPath)
		if err != nil {
			return nil, err
		}
		if err := ParseInterface(wgCfg, device); err != nil {
			return nil, err
		}
		if err := ParsePeers(wgCfg, &device.Peers); err != nil {
			return nil, err
		}
		// Apply overrides from the wrapper's [Interface] section (if present)
		if len(g.iface) == 1 {
			if err := applyInterfaceOverrides(g.iface[0], device); err != nil {
				return nil, err
			}
		}
	} else {
		if err := parseInterfaceSection(g.iface[0], device); err != nil {
			return nil, err
		}
		if len(g.peers) == 0 {
			return nil, errors.New("at least one [Peer] is expected")
		}
		if err := parsePeerSections(g.peers, &device.Peers); err != nil {
			return nil, err
		}
	}
	conf.Device = device

	return g.appendRoutines(conf)
}

// applyInterfaceOverrides applies specific fields from a wrapper's [Interface]
// section to override values imported via WGConfig. Only specific fields
// are allowed to be overridden: MTU, DNS, ListenPort, CheckAlive, CheckAliveInterval.
func applyInterfaceOverrides(section *ini.Section, device *DeviceConfig) error {
	// MTU override
	if sectionKey, err := section.GetKey("MTU"); err == nil {
		value, err := sectionKey.Int()
		if err != nil {
			return err
		}
		device.MTU = value
	}

	// DNS override
	if _, err := section.GetKey("DNS"); err == nil {
		dns, err := parseNetIP(section, "DNS")
		if err != nil {
			return err
		}
		device.DNS = dns
	}

	// ListenPort override
	if sectionKey, err := section.GetKey("ListenPort"); err == nil {
		value, err := sectionKey.Int()
		if err != nil {
			return err
		}
		device.ListenPort = &value
	}

	// CheckAlive override
	if _, err := section.GetKey("CheckAlive"); err == nil {
		checkAlive, err := parseNetIP(section, "CheckAlive")
		if err != nil {
			return err
		}
		device.CheckAlive = checkAlive
	}

	// CheckAliveInterval override
	if sectionKey, err := section.GetKey("CheckAliveInterval"); err == nil {
		value, err := sectionKey.Int()
		if err != nil {
			return err
		}
		device.CheckAliveInterval = value
	}

	return nil
}

// appendRoutines parses all routine sections of the group in canonical order.
// Unknown section types are an error: a typo like [Sokcs5] must never
// silently drop a proxy from the configuration.
func (g *connGroup) appendRoutines(conf *Configuration) (*Configuration, error) {
	parsed := make(map[string]bool, len(routineParsers))
	for _, rp := range routineParsers {
		parsed[rp.sectionType] = true
		for _, section := range g.routines[rp.sectionType] {
			routine, err := rp.parse(section)
			if err != nil {
				return nil, err
			}
			conf.Routines = append(conf.Routines, routine)
		}
	}
	for sectionType := range g.routines {
		if !parsed[sectionType] {
			conn := conf.Name
			if conn == "" {
				conn = "<default>"
			}
			return nil, errors.New("unknown section type [" + sectionType + "] in connection " + conn)
		}
	}
	return conf, nil
}

// ParseConfig takes the path of a configuration file and parses it into
// Configuration. The connection name defaults to the sanitized file stem;
// it can be overridden with a root-level "Name" key.
func ParseConfig(path string) (*Configuration, error) {
	specs, err := ParseConfigFile(path)
	if err != nil {
		return nil, err
	}
	return specs[0].Conf, nil
}

// ParseConfigFile parses a configuration file into one or more connection
// specifications, ordered by their appearance in the file. Sections named
// "<group>.<Type>" (e.g. [vpn2.Socks5]) form their own connections;
// unprefixed sections form the implicit default connection, so classic
// single-connection files keep working unchanged.
func ParseConfigFile(path string) ([]*ConnectionSpec, error) {
	source, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseConfigSource(source, path)
}

// parseConfigSource parses a wireproxy configuration given as bytes.
// sourcePath is used to resolve relative WGConfig imports and to derive
// the default connection name.
func parseConfigSource(source []byte, sourcePath string) ([]*ConnectionSpec, error) {
	cfg, err := ini.LoadSources(wgIniOptions, source)
	if err != nil {
		return nil, err
	}

	root, groups, err := splitIntoGroups(cfg)
	if err != nil {
		return nil, err
	}

	explicitName := ""
	if key, err := root.GetKey("Name"); err == nil {
		explicitName = sanitizeConnectionName(key.String())
		if explicitName == "" {
			return nil, errors.New("Name should not be empty")
		}
	}

	specs := make([]*ConnectionSpec, 0, len(groups))
	for _, g := range groups {
		conf, err := g.parse(sourcePath, root)
		if err != nil {
			return nil, err
		}

		name := g.name
		if name == "" {
			if explicitName != "" {
				name = explicitName
			} else {
				name = defaultNameFromFile(sourcePath)
			}
		}
		conf.Name = name
		specs = append(specs, &ConnectionSpec{Name: name, Conf: conf})
	}

	if len(specs) == 0 {
		return nil, errors.New("no connections defined")
	}
	return specs, nil
}
