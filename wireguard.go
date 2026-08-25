package wireproxy

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"sync"

	"net/netip"

	"github.com/MakeNowJust/heredoc/v2"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// DeviceSetting contains the parameters for setting up a tun interface
type DeviceSetting struct {
	IpcRequest string
	DNS        []netip.Addr
	DeviceAddr []netip.Addr
	MTU        int
}

// netstackNetwork adapts the WireGuard gVisor netstack to the Network
// interface used by proxy routines.
type netstackNetwork struct {
	tnet *netstack.Net
}

func (n *netstackNetwork) Dial(network, address string) (net.Conn, error) {
	return n.tnet.Dial(network, address)
}

func (n *netstackNetwork) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return n.tnet.DialContext(ctx, network, address)
}

func (n *netstackNetwork) DialTCP(addr *net.TCPAddr) (net.Conn, error) {
	return n.tnet.DialTCP(addr)
}

func (n *netstackNetwork) ListenTCP(addr *net.TCPAddr) (net.Listener, error) {
	return n.tnet.ListenTCP(addr)
}

func (n *netstackNetwork) LookupContextHost(ctx context.Context, host string) ([]string, error) {
	return n.tnet.LookupContextHost(ctx, host)
}

// CreateIPCRequest serialize the config into an IPC request and DeviceSetting
func CreateIPCRequest(conf *DeviceConfig) (*DeviceSetting, error) {
	var request bytes.Buffer

	fmt.Fprintf(&request, "private_key=%s\n", conf.SecretKey)

	if conf.ListenPort != nil {
		fmt.Fprintf(&request, "listen_port=%d\n", *conf.ListenPort)
	}

	for _, peer := range conf.Peers {
		fmt.Fprintf(&request, heredoc.Doc(`
				public_key=%s
				persistent_keepalive_interval=%d
				preshared_key=%s
			`),
			peer.PublicKey, peer.KeepAlive, peer.PreSharedKey,
		)
		if peer.Endpoint != nil {
			fmt.Fprintf(&request, "endpoint=%s\n", *peer.Endpoint)
		}

		if len(peer.AllowedIPs) > 0 {
			for _, ip := range peer.AllowedIPs {
				fmt.Fprintf(&request, "allowed_ip=%s\n", ip.String())
			}
		} else {
			request.WriteString(heredoc.Doc(`
				allowed_ip=0.0.0.0/0
				allowed_ip=::0/0
			`))
		}
	}

	setting := &DeviceSetting{IpcRequest: request.String(), DNS: conf.DNS, DeviceAddr: conf.Endpoint, MTU: conf.MTU}
	return setting, nil
}

// StartWireguard creates a tun interface on netstack given a configuration
func StartWireguard(conf *Configuration, logLevel int) (*VirtualTun, error) {
	deviceConf := conf.Device
	setting, err := CreateIPCRequest(deviceConf)
	if err != nil {
		return nil, err
	}

	tun, tnet, err := netstack.CreateNetTUN(setting.DeviceAddr, setting.DNS, setting.MTU)
	if err != nil {
		return nil, err
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(logLevel, ""))
	// Ensure the device's goroutines and UDP bind are released whenever we
	// do not hand it over to a VirtualTun.
	success := false
	defer func() {
		if !success {
			dev.Close()
		}
	}()

	err = dev.IpcSet(setting.IpcRequest)
	if err != nil {
		return nil, err
	}

	err = dev.Up()
	if err != nil {
		return nil, err
	}

	// Resolve the strategy locally: "auto" depends on this device's
	// addresses and mutating the shared configuration would race with
	// other connections started concurrently.
	resolve := *conf.Resolve

	hasV4 := false
	hasV6 := false
	for _, addr := range setting.DeviceAddr {
		if addr.Is4() {
			hasV4 = true
		}
		if addr.Is6() {
			hasV6 = true
		}
	}

	if resolve.ResolveStrategy == "auto" {
		if hasV4 && !hasV6 {
			resolve.ResolveStrategy = "ipv4"
		} else {
			resolve.ResolveStrategy = "ipv6"
		}
	}
	vt := &VirtualTun{
		Name:           conf.Name,
		Tnet:           tnet,
		Net:            &netstackNetwork{tnet: tnet},
		Dev:            dev,
		Conf:           deviceConf,
		SystemDNS:      len(setting.DNS) == 0,
		PingRecord:     make(map[string]uint64),
		PingRecordLock: new(sync.Mutex),
	}
	vt.ResolveConfig = &resolve
	success = true
	return vt, nil
}
