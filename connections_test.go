package wireproxy

import (
	"sync"
	"testing"
	"time"

	"github.com/go-ini/ini"
)

func mustParseFile(t *testing.T, config string) (*ini.File, *ini.Section, []*connGroup) {
	t.Helper()
	iniData, err := loadIniConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	root, groups, err := splitIntoGroups(iniData)
	if err != nil {
		t.Fatal(err)
	}
	return iniData, root, groups
}

// ParseConfigFileHelper parses a config from a string, as if it were stored
// at /tmp/testfile.conf (so the default connection is named "testfile").
func ParseConfigFileHelper(t *testing.T, config string) []*ConnectionSpec {
	t.Helper()
	specs, err := parseConfigSource([]byte(config), "/tmp/testfile.conf")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return specs
}

const (
	testPrivKey = "LAr1aNSNF9d0MjwUgAVC4020T0N/E5NUtqVv5EnsSz0="
	testPubKey  = "e8LKAc+f9xEzq9Ar7+MfKRrs+gZ/4yzvpRJLRJ/VJ1w="

	ifaceBody = `
PrivateKey = ` + testPrivKey + `
Address = 10.5.0.2/32
`
	peerBody = `
PublicKey = ` + testPubKey + `
AllowedIPs = 0.0.0.0/0
Endpoint = 94.140.11.15:51820
`
)

func TestSplitIntoGroups(t *testing.T) {
	const config = `
[Interface]
` + ifaceBody + `
[Peer]` + peerBody + `
[Socks5]
BindAddress = 127.0.0.1:1081

[vpn2.Interface]
` + ifaceBody + `
[Peer]` + peerBody + `
[vpn2.Socks5]
BindAddress = 127.0.0.1:1082

[vpn3.HTTP]
BindAddress = 127.0.0.1:8081
`
	_, root, groups := mustParseFile(t, config)

	if len(groups) != 3 {
		t.Fatalf("expected 3 groups, got %d", len(groups))
	}
	if groups[0].name != "" || groups[1].name != "vpn2" || groups[2].name != "vpn3" {
		t.Fatalf("unexpected group order: %q %q %q", groups[0].name, groups[1].name, groups[2].name)
	}
	if len(groups[0].iface) != 1 || len(groups[1].iface) != 1 {
		t.Fatal("interface sections not grouped correctly")
	}
	if len(groups[2].iface) != 0 {
		t.Fatal("vpn3 should have no interface yet")
	}
	if root == nil {
		t.Fatal("root (DEFAULT) section missing")
	}
}

func TestGroupedConnectionParsing(t *testing.T) {
	const config = `
[Interface]
` + ifaceBody + `
[Peer]` + peerBody + `
[Socks5]
BindAddress = 127.0.0.1:1081

[vpn2.Interface]
` + ifaceBody + `
[vpn2.Peer]` + peerBody + `
[vpn2.Socks5]
BindAddress = 127.0.0.1:1082
Username = u
Password = p
`
	specs := ParseConfigFileHelper(t, config)
	if len(specs) != 2 {
		t.Fatalf("expected 2 connections, got %d", len(specs))
	}
	if specs[0].Name != "testfile" {
		t.Fatalf("default connection should be named after file stem, got %q", specs[0].Name)
	}
	if specs[1].Name != "vpn2" {
		t.Fatalf("second connection should be vpn2, got %q", specs[1].Name)
	}

	socks := specs[1].Conf.Routines[0].(*Socks5Config)
	if socks.BindAddress != "127.0.0.1:1082" || socks.Username != "u" {
		t.Fatalf("vpn2 socks5 parsed incorrectly: %+v", socks)
	}
	if specs[1].Conf.Device == nil {
		t.Fatal("vpn2 device should be set")
	}
}

func TestTailscaleAndInterfaceMutuallyExclusive(t *testing.T) {
	const config = `
[Tailscale]
Hostname = node-a
[Interface]
` + ifaceBody + `
[Peer]` + peerBody
	assert := func() bool {
		_, err := parseConfigSource([]byte(config), "/tmp/testfile.conf")
		return err != nil
	}
	if !assert() {
		t.Fatal("expected error mixing [Tailscale] with [Interface]")
	}
}

func TestTailscaleSectionParsing(t *testing.T) {
	const config = `
[Tailscale]
Hostname = node-a
AuthKey = tskey-auth-xyz
ControlURL = https://headscale.example.com
Ephemeral = true
StateDir = /tmp/tsnet-node-a
AdvertiseTags = tag:server, tag:proxy
[Socks5]
BindAddress = 127.0.0.1:1090
`
	specs := ParseConfigFileHelper(t, config)
	conf := specs[0].Conf
	if conf.Tailscale == nil {
		t.Fatal("Tailscale config should be set")
	}
	if conf.Device != nil {
		t.Fatal("Device must not be set for Tailscale connections")
	}
	ts := conf.Tailscale
	if ts.Hostname != "node-a" || ts.AuthKey != "tskey-auth-xyz" ||
		ts.ControlURL != "https://headscale.example.com" || !ts.Ephemeral ||
		ts.StateDir != "/tmp/tsnet-node-a" {
		t.Fatalf("tailscale config parsed incorrectly: %+v", ts)
	}
	if len(ts.AdvertiseTags) != 2 || ts.AdvertiseTags[0] != "tag:server" || ts.AdvertiseTags[1] != "tag:proxy" {
		t.Fatalf("advertise tags parsed incorrectly: %v", ts.AdvertiseTags)
	}
}

func TestValidateConnectionsDuplicateNames(t *testing.T) {
	mkSpec := func(name string) *ConnectionSpec {
		return &ConnectionSpec{
			Name: name,
			Conf: &Configuration{
				Tailscale: &TailscaleConfig{Hostname: name},
				Routines:  []RoutineSpawner{},
			},
		}
	}
	specs := []*ConnectionSpec{mkSpec("a"), mkSpec("a")}
	if err := ValidateConnections(specs, ""); err == nil {
		t.Fatal("expected duplicate name error")
	}
}

func TestValidateConnectionsDuplicateHostname(t *testing.T) {
	mkSpec := func(name string) *ConnectionSpec {
		return &ConnectionSpec{
			Name: name,
			Conf: &Configuration{
				Tailscale: &TailscaleConfig{Hostname: "same"},
				Routines:  []RoutineSpawner{},
			},
		}
	}
	if err := ValidateConnections([]*ConnectionSpec{mkSpec("a"), mkSpec("b")}, ""); err == nil {
		t.Fatal("expected duplicate tailscale hostname error")
	}
}

func TestValidateConnectionsPortConflict(t *testing.T) {
	socks := func(bind string) RoutineSpawner {
		return &Socks5Config{BindAddress: bind}
	}
	mkSpec := func(name string, binds ...RoutineSpawner) *ConnectionSpec {
		return &ConnectionSpec{
			Name: name,
			Conf: &Configuration{Tailscale: &TailscaleConfig{Hostname: name}, Routines: binds},
		}
	}

	// same port, both wildcard-ish → conflict
	err := ValidateConnections([]*ConnectionSpec{
		mkSpec("a", socks(":1080")),
		mkSpec("b", socks("127.0.0.1:1080")),
	}, "")
	if err == nil {
		t.Fatal("expected wildcard port conflict")
	}

	// different loopback hosts, same port → no conflict
	err = ValidateConnections([]*ConnectionSpec{
		mkSpec("a", socks("127.0.0.1:1080")),
		mkSpec("b", socks("127.0.0.2:1080")),
	}, "")
	if err != nil {
		t.Fatalf("distinct hosts on same port must not conflict: %v", err)
	}
}

func TestValidateConnectionsUDPTunnelOnTailscale(t *testing.T) {
	spec := &ConnectionSpec{
		Name: "ts",
		Conf: &Configuration{
			Tailscale: &TailscaleConfig{Hostname: "node"},
			Routines: []RoutineSpawner{
				&UDPProxyTunnelConfig{BindAddress: ":53", Target: "1.1.1.1:53"},
			},
		},
	}
	if err := ValidateConnections([]*ConnectionSpec{spec}, ""); err == nil {
		t.Fatal("expected UDP tunnel rejection for Tailscale connection")
	}
}

func TestValidateConnectionsTCPServerTunnelDupPorts(t *testing.T) {
	spec := &ConnectionSpec{
		Name: "wg",
		Conf: &Configuration{
			Device: &DeviceConfig{},
			Routines: []RoutineSpawner{
				&TCPServerTunnelConfig{ListenPort: 5000, Target: "a:80"},
				&TCPServerTunnelConfig{ListenPort: 5000, Target: "b:80"},
			},
		},
	}
	if err := ValidateConnections([]*ConnectionSpec{spec}, ""); err == nil {
		t.Fatal("expected duplicate TCPServerTunnel port error")
	}
}

func TestHealthRegistryAggregation(t *testing.T) {
	reg := NewHealthRegistry()

	vt1 := &VirtualTun{
		Name:           "wg1",
		Conf:           &DeviceConfig{CheckAliveInterval: 5},
		PingRecord:     map[string]uint64{"10.0.0.1": uint64(time.Now().Unix())},
		PingRecordLock: new(sync.Mutex),
	}
	vt2 := &VirtualTun{
		Name:           "ts1",
		Conf:           &DeviceConfig{},
		PingRecord:     make(map[string]uint64),
		PingRecordLock: new(sync.Mutex),
	}
	reg.Add(vt1)
	reg.Add(vt2)

	if reg.Count() != 2 {
		t.Fatalf("registry count = %d, want 2", reg.Count())
	}

	snaps := reg.snapshot()
	if len(snaps) != 2 || snaps[0].name != "wg1" || snaps[1].name != "ts1" {
		t.Fatalf("snapshot incorrect: %+v", snaps)
	}
	if snaps[0].stale() {
		t.Fatal("fresh ping must not be stale")
	}
	if snaps[1].checkAlive {
		t.Fatal("connection without CheckAlive must not be checkable")
	}
}
