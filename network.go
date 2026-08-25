package wireproxy

import (
	"context"
	"net"
)

// Network abstracts the dial/listen surface that proxy routines talk to.
//
// Implementations:
//   - netstackNetwork: a gVisor userspace netstack backed by a WireGuard
//     device (the classic wireproxy behaviour).
//   - tsnetNetwork (built with -tags tsnet): an embedded Tailscale node.
type Network interface {
	// Dial connects to the address on the named network ("tcp", "udp", ...).
	Dial(network, address string) (net.Conn, error)

	// DialContext is Dial with a context for cancellation.
	DialContext(ctx context.Context, network, address string) (net.Conn, error)

	// DialTCP dials a TCP connection to addr.
	DialTCP(addr *net.TCPAddr) (net.Conn, error)

	// ListenTCP listens for TCP connections on addr inside the network.
	ListenTCP(addr *net.TCPAddr) (net.Listener, error)

	// LookupContextHost resolves host using the network's resolver
	// (tunnel DNS or MagicDNS depending on the implementation).
	LookupContextHost(ctx context.Context, host string) ([]string, error)
}
