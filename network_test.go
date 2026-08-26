package wireproxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

type fakeNetwork struct {
	addrs []string
}

var _ Network = (*fakeNetwork)(nil)
var _ Network = (*netstackNetwork)(nil)

func (f *fakeNetwork) Dial(network, address string) (net.Conn, error) {
	return nil, errors.New("fakeNetwork: Dial not implemented")
}

func (f *fakeNetwork) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return nil, errors.New("fakeNetwork: DialContext not implemented")
}

func (f *fakeNetwork) DialTCP(addr *net.TCPAddr) (net.Conn, error) {
	return nil, errors.New("fakeNetwork: DialTCP not implemented")
}

func (f *fakeNetwork) ListenTCP(addr *net.TCPAddr) (net.Listener, error) {
	return nil, errors.New("fakeNetwork: ListenTCP not implemented")
}

func (f *fakeNetwork) LookupContextHost(ctx context.Context, host string) ([]string, error) {
	return f.addrs, nil
}

func TestLookupAddrUsesNetwork(t *testing.T) {
	want := []string{"192.0.2.7", "2001:db8::7"}
	vt := VirtualTun{
		Name:          "test",
		Net:           &fakeNetwork{addrs: want},
		SystemDNS:     false,
		ResolveConfig: &ResolveConfig{ResolveStrategy: "ipv4"},
	}
	got, err := vt.LookupAddr(context.Background(), "host.internal")
	if err != nil {
		t.Fatalf("LookupAddr: %v", err)
	}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("LookupAddr = %v, want %v", got, want)
	}
}

func TestLookupAddrSystemDNSCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	vt := VirtualTun{
		Name:          "test",
		SystemDNS:     true,
		ResolveConfig: &ResolveConfig{ResolveStrategy: "ipv4"},
	}
	if _, err := vt.LookupAddr(ctx, "localhost"); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled from system resolver path, got %v", err)
	}
}

func TestResolveStrategyOrdering(t *testing.T) {
	mixed := []string{"192.0.2.10", "not-an-ip", "2001:db8::1"}

	tests := []struct {
		name     string
		addrs    []string
		strategy string
		want     string
		wantErr  string
	}{
		{"ipv4 preferred", mixed, "ipv4", "192.0.2.10", ""},
		{"ipv6 preferred", mixed, "ipv6", "2001:db8::1", ""},
		{"falls back to other family", []string{"2001:db8::2"}, "ipv4", "2001:db8::2", ""},
		{"unparseable addresses filtered", []string{"nope"}, "ipv4", "", "no address found"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			vt := VirtualTun{
				Name:          "test",
				Net:           &fakeNetwork{addrs: tc.addrs},
				SystemDNS:     false,
				ResolveConfig: &ResolveConfig{ResolveStrategy: tc.strategy},
			}
			addr, err := vt.ResolveAddrWithContext(context.Background(), "host.internal")
			if tc.wantErr != "" {
				if err == nil || !bytes.Contains([]byte(err.Error()), []byte(tc.wantErr)) {
					t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveAddrWithContext: %v", err)
			}
			if addr.String() != tc.want {
				t.Fatalf("resolved %q, want %q", addr.String(), tc.want)
			}
		})
	}
}

func TestNetstackNetworkLoopbackEcho(t *testing.T) {
	local := netip.MustParseAddr("10.77.0.1")
	tunDev, tns, err := netstack.CreateNetTUN([]netip.Addr{local}, []netip.Addr{}, 1420)
	if err != nil {
		t.Fatalf("CreateNetTUN: %v", err)
	}
	_ = tunDev
	nn := &netstackNetwork{tnet: tns}

	ln, err := nn.ListenTCP(&net.TCPAddr{Port: 0})
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer func() { _ = ln.Close() }()

	port := ln.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				_, _ = io.Copy(c, c)
				_ = c.Close()
			}(c)
		}
	}()

	target := net.JoinHostPort(local.String(), strconv.Itoa(port))
	tests := []struct {
		name    string
		dial    func() (net.Conn, error)
		wantErr bool
	}{
		{
			name: "DialTCP",
			dial: func() (net.Conn, error) {
				return nn.DialTCP(&net.TCPAddr{IP: net.IP(local.AsSlice()), Port: port})
			},
		},
		{
			name: "Dial",
			dial: func() (net.Conn, error) { return nn.Dial("tcp", target) },
		},
		{
			name: "DialContext",
			dial: func() (net.Conn, error) { return nn.DialContext(context.Background(), "tcp", target) },
		},
		{
			name: "DialContext canceled",
			dial: func() (net.Conn, error) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return nn.DialContext(ctx, "tcp", target)
			},
			wantErr: true,
		},
	}

	payload := []byte("hello-wireproxy")
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, err := tc.dial()
			if tc.wantErr {
				if err == nil {
					_ = c.Close()
					t.Fatal("expected dial error")
				}
				return
			}
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer func() { _ = c.Close() }()
			if err := c.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
				t.Fatalf("SetDeadline: %v", err)
			}
			if _, err := c.Write(payload); err != nil {
				t.Fatalf("write: %v", err)
			}
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(c, got); err != nil {
				t.Fatalf("read echo: %v", err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("echo mismatch: got %q, want %q", got, payload)
			}
		})
	}
}
