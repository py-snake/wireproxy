package wireproxy

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const (
	mcPrivKey = "LAr1aNSNF9d0MjwUgAVC4020T0N/E5NUtqVv5EnsSz0="
	mcPubKey  = "e8LKAc+f9xEzq9Ar7+MfKRrs+gZ/4yzvpRJLRJ/VJ1w="
)

const mcIfaceBody = `
PrivateKey = ` + mcPrivKey + `
Address = 10.5.0.2/32
`

const mcPeerBody = `
PublicKey = ` + mcPubKey + `
AllowedIPs = 0.0.0.0/0
Endpoint = 94.140.11.15:51820
`

const mcExternalWGConf = `
[Interface]
PrivateKey = ` + mcPrivKey + `
Address = 10.5.0.2/32
ListenPort = 51820

[Peer]
PublicKey = ` + mcPubKey + `
AllowedIPs = 0.0.0.0/0
Endpoint = 94.140.11.15:51820
`

func mcWGFileBody(socksBind string) string {
	return `
[Interface]` + mcIfaceBody + `
[Peer]` + mcPeerBody + `
[Socks5]
BindAddress = ` + socksBind + `
`
}

func mcWriteFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func mcWg(name string, listenPort *int, routines ...RoutineSpawner) *ConnectionSpec {
	return &ConnectionSpec{
		Name: name,
		Conf: &Configuration{Device: &DeviceConfig{ListenPort: listenPort}, Routines: routines},
	}
}

func mcTs(name string, ts *TailscaleConfig, routines ...RoutineSpawner) *ConnectionSpec {
	return &ConnectionSpec{
		Name: name,
		Conf: &Configuration{Tailscale: ts, Routines: routines},
	}
}

func TestLoadConfigSourcesSingleFile(t *testing.T) {
	dir := t.TempDir()
	f := mcWriteFile(t, dir, "alpha.conf", mcWGFileBody("127.0.0.1:14101"))

	specs, err := LoadConfigSources([]string{f}, "")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(specs) != 1 || specs[0].Name != "alpha" {
		t.Fatalf("unexpected specs: %+v", specs)
	}
	if specs[0].Conf.Device == nil {
		t.Fatal("wireguard connection should carry a Device config")
	}
}

func TestLoadConfigSourcesRepeatedFilePath(t *testing.T) {
	dir := t.TempDir()
	f := mcWriteFile(t, dir, "dup.conf", mcWGFileBody("127.0.0.1:14102"))

	_, err := LoadConfigSources([]string{f, f}, "")
	if err == nil || !strings.Contains(err.Error(), "duplicate connection name") {
		t.Fatalf("expected duplicate connection name error, got %v", err)
	}
}

func TestLoadConfigSourcesDirectory(t *testing.T) {
	dir := t.TempDir()
	mcWriteFile(t, dir, "b.conf", mcWGFileBody("127.0.0.1:14103"))
	mcWriteFile(t, dir, "a.conf", mcWGFileBody("127.0.0.1:14104"))
	mcWriteFile(t, dir, "notes.txt", "not a config")
	if err := os.Mkdir(filepath.Join(dir, "sub.conf"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "subdir"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "a.conf"), filepath.Join(dir, "zz-link.conf")); err != nil {
		t.Logf("symlinks unsupported on this filesystem, skipping symlink case: %v", err)
	}

	specs, err := LoadConfigSources([]string{dir}, "")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	var names []string
	for _, s := range specs {
		names = append(names, s.Name)
	}
	if len(names) != 2 || names[0] != "a" || names[1] != "b" {
		t.Fatalf("expected exactly [a b] in lexicographic order, got %v", names)
	}
}

func TestLoadConfigSourcesMissingPath(t *testing.T) {
	dir := t.TempDir()
	_, err := LoadConfigSources([]string{filepath.Join(dir, "missing.conf")}, "")
	if err == nil {
		t.Fatal("expected error for missing path")
	}
}

func TestLoadConfigSourcesEmptyDirectory(t *testing.T) {
	dir := t.TempDir()
	_, err := LoadConfigSources([]string{dir}, "")
	if err == nil || !strings.Contains(err.Error(), "no configuration files found") {
		t.Fatalf("expected empty-directory error, got %v", err)
	}
}

func TestLoadConfigSourcesInfoAddrValidation(t *testing.T) {
	dir := t.TempDir()
	f := mcWriteFile(t, dir, "svc.conf", mcWGFileBody("127.0.0.1:15001"))

	if _, err := LoadConfigSources([]string{f}, ":15001"); err == nil || !strings.Contains(err.Error(), "share port") {
		t.Fatalf("expected health-endpoint port conflict, got %v", err)
	}
	if _, err := LoadConfigSources([]string{f}, "127.0.0.1:015001"); err == nil || !strings.Contains(err.Error(), "share port") {
		t.Fatalf("expected normalized health-endpoint port conflict, got %v", err)
	}
	specs, err := LoadConfigSources([]string{f}, "127.0.0.1:19999")
	if err != nil {
		t.Fatalf("non-conflicting health endpoint should load: %v", err)
	}
	if len(specs) != 1 {
		t.Fatalf("unexpected spec count %d", len(specs))
	}
	if _, err := LoadConfigSources([]string{f}, "127.0.0.1"); err == nil || !strings.Contains(err.Error(), "invalid address") {
		t.Fatalf("expected malformed health endpoint rejection, got %v", err)
	}
}

func TestSanitizeConnectionName(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"My VPN", "my-vpn"},
		{"--x", "x"},
		{"_x", "x"},
		{"VPN_1-ok", "vpn_1-ok"},
		{"  spaces  ", "spaces"},
		{"\u00dcn\u00efcode", "n-code"},
		{"\u65e5\u672c\u8a9e", ""},
		{"---", ""},
		{"!!!", ""},
		{"", ""},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			if got := sanitizeConnectionName(c.in); got != c.want {
				t.Fatalf("sanitizeConnectionName(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestSanitizeConnectionNameTrailingPunctuation(t *testing.T) {
	got := sanitizeConnectionName("My VPN!")
	if got != "my-vpn" {
		t.Fatalf("sanitizeConnectionName(%q) = %q, want %q", "My VPN!", got, "my-vpn")
	}
}

func TestDefaultNameFromFile(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"/tmp/vpn.conf", "vpn"},
		{"/etc/wireproxy/My File.conf", "my-file"},
		{"/tmp/x.WG.conf", "x-wg"},
	}
	for _, c := range cases {
		if got := defaultNameFromFile(c.path); got != c.want {
			t.Fatalf("defaultNameFromFile(%q) = %q, want %q", c.path, got, c.want)
		}
	}
}

func TestValidateConnectionsMatrix(t *testing.T) {
	intPtr := func(p int) *int { return &p }

	tests := []struct {
		name     string
		specs    []*ConnectionSpec
		infoAddr string
		wantErr  string
	}{
		{
			name: "valid mixed wg and tsnet",
			specs: []*ConnectionSpec{
				mcWg("wga", nil, &Socks5Config{BindAddress: "127.0.0.1:16001"}),
				mcTs("tsa", &TailscaleConfig{Hostname: "node-a"}, &Socks5Config{BindAddress: "127.0.0.1:16002"}),
			},
		},
		{
			name:    "duplicate names rejected",
			specs:   []*ConnectionSpec{mcWg("same", nil), mcTs("same", &TailscaleConfig{Hostname: "n1"})},
			wantErr: "duplicate connection name",
		},
		{
			name: "duplicate hostnames rejected case insensitively",
			specs: []*ConnectionSpec{
				mcTs("a", &TailscaleConfig{Hostname: "Node-A"}),
				mcTs("b", &TailscaleConfig{Hostname: "node-a"}),
			},
			wantErr: "use the same Tailscale Hostname",
		},
		{
			name: "duplicate explicit statedirs rejected",
			specs: []*ConnectionSpec{
				mcTs("a", &TailscaleConfig{Hostname: "ha", StateDir: "/tmp/shared-ts"}),
				mcTs("b", &TailscaleConfig{Hostname: "hb", StateDir: "/tmp/shared-ts"}),
			},
			wantErr: "share the Tailscale StateDir",
		},
		{
			name: "distinct statedirs accepted",
			specs: []*ConnectionSpec{
				mcTs("a", &TailscaleConfig{Hostname: "hc", StateDir: "/tmp/ts-a"}),
				mcTs("b", &TailscaleConfig{Hostname: "hd", StateDir: "/tmp/ts-b"}),
			},
		},
		{
			name: "derived statedirs never collide",
			specs: []*ConnectionSpec{
				mcTs("a", &TailscaleConfig{Hostname: "he"}),
				mcTs("b", &TailscaleConfig{Hostname: "hf"}),
			},
		},
		{
			name:    "cross connection wireguard listenport duplicate rejected",
			specs:   []*ConnectionSpec{mcWg("a", intPtr(51820)), mcWg("b", intPtr(51820))},
			wantErr: "same WireGuard ListenPort",
		},
		{
			name:    "distinct wireguard listenports accepted",
			specs:   []*ConnectionSpec{mcWg("a", intPtr(51820)), mcWg("b", intPtr(51821))},
			wantErr: "",
		},
		{
			name: "numeric port normalization conflict",
			specs: []*ConnectionSpec{
				mcWg("a", nil, &Socks5Config{BindAddress: "127.0.0.1:08080"}),
				mcWg("b", nil, &Socks5Config{BindAddress: ":8080"}),
			},
			wantErr: "share port",
		},
		{
			name: "wildcard host conflicts with specific host",
			specs: []*ConnectionSpec{
				mcWg("a", nil, &Socks5Config{BindAddress: ":8080"}),
				mcWg("b", nil, &Socks5Config{BindAddress: "127.0.0.1:8080"}),
			},
			wantErr: "share port",
		},
		{
			name: "distinct loopback hosts on same port accepted",
			specs: []*ConnectionSpec{
				mcWg("a", nil, &Socks5Config{BindAddress: "127.0.0.1:8080"}),
				mcWg("b", nil, &Socks5Config{BindAddress: "127.0.0.2:8080"}),
			},
		},
		{
			name: "udp tunnel on tailscale connection rejected",
			specs: []*ConnectionSpec{
				mcTs("ts", &TailscaleConfig{Hostname: "node"}, &UDPProxyTunnelConfig{BindAddress: ":53", Target: "1.1.1.1:53"}),
			},
			wantErr: "UDPProxyTunnel is not supported",
		},
		{
			name: "malformed bind address rejected",
			specs: []*ConnectionSpec{
				mcWg("a", nil, &Socks5Config{BindAddress: "127.0.0.1"}),
			},
			wantErr: "invalid address",
		},
		{
			name: "tcp and udp listeners may share a port",
			specs: []*ConnectionSpec{
				mcWg("a", nil, &Socks5Config{BindAddress: "127.0.0.1:16053"}),
				mcWg("b", nil, &UDPProxyTunnelConfig{BindAddress: "127.0.0.1:16053", Target: "1.1.1.1:53"}),
			},
		},
		{
			name:     "health endpoint port conflict detected",
			specs:    []*ConnectionSpec{mcWg("a", nil, &Socks5Config{BindAddress: ":17000"})},
			infoAddr: ":17000",
			wantErr:  "share port",
		},
		{
			name:     "malformed health endpoint rejected",
			specs:    []*ConnectionSpec{mcWg("a", nil)},
			infoAddr: "no-port-here",
			wantErr:  "invalid address",
		},
		{
			name:    "invalid connection name rejected",
			specs:   []*ConnectionSpec{mcWg("Bad Name!", nil)},
			wantErr: "name must match",
		},
		{
			name:    "interface and tailscale mutually exclusive",
			specs:   []*ConnectionSpec{{Name: "mix", Conf: &Configuration{Device: &DeviceConfig{}, Tailscale: &TailscaleConfig{Hostname: "x"}}}},
			wantErr: "mutually exclusive",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateConnections(tc.specs, tc.infoAddr)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected success, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestEffectiveStateDir(t *testing.T) {
	explicit := &TailscaleConfig{StateDir: "/data/ts/node"}
	if got := explicit.EffectiveStateDir("ignored-name"); got != "/data/ts/node" {
		t.Fatalf("explicit StateDir must win verbatim, got %q", got)
	}

	base, err := os.UserCacheDir()
	if err != nil || base == "" {
		base = os.TempDir()
	}

	a := (&TailscaleConfig{}).EffectiveStateDir("alpha")
	b := (&TailscaleConfig{}).EffectiveStateDir("beta")
	if !strings.HasPrefix(a, base) {
		t.Fatalf("derived dir %q should live under base %q", a, base)
	}
	if want := filepath.Join("wireproxy", "tsnet", "alpha"); !strings.HasSuffix(a, want) {
		t.Fatalf("derived dir %q should end with %q", a, want)
	}
	if a == b {
		t.Fatalf("different connection names must derive distinct dirs, both %q", a)
	}
}

func TestNeedsOpenEgress(t *testing.T) {
	domains := []*regexp.Regexp{regexp.MustCompile(`^example\.com$`)}

	tests := []struct {
		name  string
		specs []*ConnectionSpec
		want  bool
	}{
		{"empty", nil, false},
		{"plain wireguard socks5", []*ConnectionSpec{mcWg("a", nil, &Socks5Config{BindAddress: ":1"})}, false},
		{"socks5 with tunnel domains", []*ConnectionSpec{mcWg("a", nil, &Socks5Config{BindAddress: ":1", TunnelDomains: domains})}, true},
		{"http with tunnel domains", []*ConnectionSpec{mcWg("a", nil, &HTTPConfig{BindAddress: ":1", TunnelDomains: domains})}, true},
		{"sni with tunnel domains", []*ConnectionSpec{mcWg("a", nil, &SNIConfig{BindAddress: ":1", TunnelDomains: domains})}, true},
		{"tailscale connection", []*ConnectionSpec{mcTs("ts", &TailscaleConfig{Hostname: "n"})}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := NeedsOpenEgress(tc.specs); got != tc.want {
				t.Fatalf("NeedsOpenEgress = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestTailscaleStateDirs(t *testing.T) {
	specs := []*ConnectionSpec{
		mcWg("wg", nil),
		mcTs("explicit", &TailscaleConfig{Hostname: "n1", StateDir: "/sd/explicit"}),
		mcTs("derived", &TailscaleConfig{Hostname: "n2"}),
	}

	dirs := TailscaleStateDirs(specs)
	if len(dirs) != 2 {
		t.Fatalf("expected 2 state dirs, got %v", dirs)
	}
	if dirs[0] != "/sd/explicit" {
		t.Fatalf("explicit state dir must be returned verbatim, got %q", dirs[0])
	}
	if want := filepath.Join("wireproxy", "tsnet", "derived"); !strings.HasSuffix(dirs[1], want) {
		t.Fatalf("derived state dir %q should end with %q", dirs[1], want)
	}

	if got := TailscaleStateDirs([]*ConnectionSpec{mcWg("wg", nil)}); len(got) != 0 {
		t.Fatalf("wireguard-only specs should yield no state dirs, got %v", got)
	}
}

func TestParseConfigSourceUnknownSectionType(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		wantErr string
	}{
		{
			name: "typo in default connection",
			config: `
[Interface]` + mcIfaceBody + `
[Peer]` + mcPeerBody + `
[Sokcs5]
BindAddress = 127.0.0.1:18001
`,
			wantErr: "unknown section type",
		},
		{
			name: "typo in grouped connection",
			config: `
[a.Interface]` + mcIfaceBody + `
[a.Peer]` + mcPeerBody + `
[a.Sokcs5]
BindAddress = 127.0.0.1:18002
`,
			wantErr: "unknown section type",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseConfigSource([]byte(tc.config), "/tmp/typo.conf")
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestParseConfigSourceWGConfigWithInlineKeysRejected(t *testing.T) {
	config := `
[Interface]
WGConfig = external.conf` + mcIfaceBody + `
[Peer]` + mcPeerBody
	_, err := parseConfigSource([]byte(config), "/tmp/mixed.conf")
	if err == nil || !strings.Contains(err.Error(), "must not combine WGConfig with inline PrivateKey") {
		t.Fatalf("expected WGConfig/inline mixing error, got %v", err)
	}
}

func TestParseConfigSourceResolveOverridePerGroup(t *testing.T) {
	config := `
[Interface]` + mcIfaceBody + `
[Peer]` + mcPeerBody + `
[Socks5]
BindAddress = 127.0.0.1:19001

[v4.Interface]` + mcIfaceBody + `
[v4.Peer]` + mcPeerBody + `
[v4.Socks5]
BindAddress = 127.0.0.1:19002
[v4.Resolve]
ResolveStrategy = ipv4

[x.Interface]` + mcIfaceBody + `
[x.Peer]` + mcPeerBody + `
[x.Resolve]
Unrelated = true
`
	specs := parseConfigFileHelperNamed(t, config, "/tmp/resolve.conf")

	strategy := map[string]string{}
	for _, s := range specs {
		strategy[s.Name] = s.Conf.Resolve.ResolveStrategy
	}
	if strategy["resolve"] != "auto" {
		t.Fatalf("default connection should fall back to auto, got %q", strategy["resolve"])
	}
	if strategy["v4"] != "ipv4" {
		t.Fatalf("per-group ResolveStrategy override not applied, got %q", strategy["v4"])
	}
	if v, ok := strategy["x"]; !ok || v != "auto" {
		t.Fatalf("[x.Resolve] without ResolveStrategy should fall back to auto, got %q (present=%v)", v, ok)
	}
}

func TestParseConfigSourceRootNameKey(t *testing.T) {
	config := `
Name = My Cool VPN
[Interface]` + mcIfaceBody + `
[Peer]` + mcPeerBody + `
[node.Tailscale]
Hostname = node-x
`
	specs := parseConfigFileHelperNamed(t, config, "/tmp/named.conf")
	if len(specs) != 2 {
		t.Fatalf("expected 2 connections, got %d", len(specs))
	}
	if specs[0].Name != "my-cool-vpn" {
		t.Fatalf("root Name key should name the default connection, got %q", specs[0].Name)
	}
	if specs[1].Name != "node" {
		t.Fatalf("root Name must not leak into grouped connections, got %q", specs[1].Name)
	}
}

func TestParseConfigSourceInvalidRootName(t *testing.T) {
	config := `
Name = !!!
[Interface]` + mcIfaceBody + `
[Peer]` + mcPeerBody
	_, err := parseConfigSource([]byte(config), "/tmp/badname.conf")
	if err == nil || !strings.Contains(err.Error(), "Name should not be empty") {
		t.Fatalf("expected invalid root Name rejection, got %v", err)
	}
}

func TestParseConfigSourcePreservesGroupOrder(t *testing.T) {
	config := `
[c.Tailscale]
Hostname = c-node

[b.Tailscale]
Hostname = b-node

[Interface]` + mcIfaceBody + `
[Peer]` + mcPeerBody + `

[a.Tailscale]
Hostname = a-node
`
	specs := parseConfigFileHelperNamed(t, config, "/tmp/ordercase.conf")
	var names []string
	for _, s := range specs {
		names = append(names, s.Name)
	}
	want := []string{"c", "b", "ordercase", "a"}
	if len(names) != len(want) {
		t.Fatalf("expected %v, got %v", want, names)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("connection order not preserved: got %v, want %v", names, want)
		}
	}
}

func TestParseConfigSourceGroupedTailscale(t *testing.T) {
	config := `
[node.Tailscale]
Hostname = node-a
AuthKey = tskey-auth-xyz
StateDir = /tmp/tsnet-node
Ephemeral = true
[node.Socks5]
BindAddress = 127.0.0.1:21001
`
	specs := parseConfigFileHelperNamed(t, config, "/tmp/tsgroup.conf")
	if len(specs) != 1 {
		t.Fatalf("expected 1 connection, got %d", len(specs))
	}
	spec := specs[0]
	if spec.Name != "node" {
		t.Fatalf("unexpected connection name %q", spec.Name)
	}
	if spec.Conf.Device != nil {
		t.Fatal("grouped Tailscale connection must have nil Device")
	}
	ts := spec.Conf.Tailscale
	if ts == nil {
		t.Fatal("grouped [x.Tailscale] should produce a Tailscale config")
	}
	if ts.Hostname != "node-a" || ts.AuthKey != "tskey-auth-xyz" || ts.StateDir != "/tmp/tsnet-node" || !ts.Ephemeral {
		t.Fatalf("tailscale config parsed incorrectly: %+v", ts)
	}
	if len(spec.Conf.Routines) != 1 {
		t.Fatalf("expected 1 routine, got %d", len(spec.Conf.Routines))
	}
	if _, ok := spec.Conf.Routines[0].(*Socks5Config); !ok {
		t.Fatalf("routine should be Socks5Config, got %T", spec.Conf.Routines[0])
	}
	if spec.Conf.Resolve.ResolveStrategy != "auto" {
		t.Fatalf("tailscale connection should default to auto resolve, got %q", spec.Conf.Resolve.ResolveStrategy)
	}
}

func TestParseConfigSourceExternalWGConfig(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "wg.conf"), []byte(mcExternalWGConf), 0o600); err != nil {
		t.Fatal(err)
	}
	privHex, pubHex := mustHexKey(t, mcPrivKey), mustHexKey(t, mcPubKey)

	t.Run("root WGConfig resolves bare filename against source dir", func(t *testing.T) {
		config := `
WGConfig = wg.conf
[Socks5]
BindAddress = 127.0.0.1:22001
`
		specs := parseConfigFileHelperNamed(t, config, filepath.Join(dir, "main.conf"))
		if len(specs) != 1 {
			t.Fatalf("expected 1 connection, got %d", len(specs))
		}
		dev := specs[0].Conf.Device
		if dev == nil {
			t.Fatal("external WGConfig should produce a Device")
		}
		if dev.SecretKey != privHex {
			t.Fatalf("SecretKey = %q, want %q", dev.SecretKey, privHex)
		}
		if dev.ListenPort == nil || *dev.ListenPort != 51820 {
			t.Fatalf("ListenPort not imported from external file: %v", dev.ListenPort)
		}
		if len(dev.Peers) != 1 || dev.Peers[0].PublicKey != pubHex {
			t.Fatalf("peers not imported from external file: %+v", dev.Peers)
		}
	})

	t.Run("grouped WGConfig resolves relative path", func(t *testing.T) {
		config := `
[vpn.Interface]
WGConfig = wg.conf
[vpn.Socks5]
BindAddress = 127.0.0.1:22002
`
		specs := parseConfigFileHelperNamed(t, config, filepath.Join(dir, "main.conf"))
		if len(specs) != 1 || specs[0].Name != "vpn" {
			t.Fatalf("unexpected specs: %+v", specs)
		}
		if specs[0].Conf.Device == nil || specs[0].Conf.Device.SecretKey != privHex {
			t.Fatalf("grouped external WGConfig not loaded: %+v", specs[0].Conf.Device)
		}
	})

	t.Run("missing external WGConfig errors", func(t *testing.T) {
		config := `
WGConfig = does-not-exist.conf
[Socks5]
BindAddress = 127.0.0.1:22003
`
		if _, err := parseConfigSource([]byte(config), filepath.Join(dir, "main.conf")); err == nil {
			t.Fatal("expected error loading missing external WGConfig")
		}
	})
}

func parseConfigFileHelperNamed(t *testing.T, config, sourcePath string) []*ConnectionSpec {
	t.Helper()
	specs, err := parseConfigSource([]byte(config), sourcePath)
	if err != nil {
		t.Fatalf("parse %s: %v", sourcePath, err)
	}
	return specs
}

func mustHexKey(t *testing.T, b64 string) string {
	t.Helper()
	hex, err := encodeBase64ToHex(b64)
	if err != nil {
		t.Fatal(err)
	}
	return hex
}
