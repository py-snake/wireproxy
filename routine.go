package wireproxy

import (
	"bytes"
	"context"
	srand "crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.zx2c4.com/wireguard/device"

	"github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/bufferpool"

	"net/netip"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

// errorLogger is the logger to print error message
var errorLogger = log.New(os.Stderr, "ERROR: ", log.LstdFlags)

// CredentialValidator stores the authentication data of a socks5 proxy
type CredentialValidator struct {
	username string
	password string
}

// VirtualTun stores a reference to a network (netstack or tailnet) and DNS configuration
type VirtualTun struct {
	// Name identifies this connection in logs and health endpoints
	Name string
	// Net is the dial/listen surface used by proxy routines
	Net Network
	// Tnet is the raw gVisor netstack; it is only set for WireGuard
	// connections and is used for ICMP ping probes.
	Tnet          *netstack.Net
	Dev           *device.Device
	SystemDNS     bool
	Conf          *DeviceConfig
	ResolveConfig *ResolveConfig
	// PingRecord stores the last time an IP was pinged
	PingRecord     map[string]uint64
	PingRecordLock *sync.Mutex
}

// Logf logs a message prefixed with the connection name.
func (d VirtualTun) Logf(format string, args ...interface{}) {
	log.Printf("[%s] "+format, append([]interface{}{d.Name}, args...)...)
}

// Errorf logs an error message prefixed with the connection name.
func (d VirtualTun) Errorf(format string, args ...interface{}) {
	errorLogger.Printf("[%s] "+format, append([]interface{}{d.Name}, args...)...)
}

// RoutineSpawner spawns a routine (e.g. socks5, tcp static routes) after the configuration is parsed
type RoutineSpawner interface {
	SpawnRoutine(vt *VirtualTun)
}

type addressPort struct {
	address string
	port    uint16
}

// LookupAddr lookups a hostname.
// DNS traffic may or may not be routed depending on VirtualTun's setting
func (d VirtualTun) LookupAddr(ctx context.Context, name string) ([]string, error) {
	if d.SystemDNS {
		return net.DefaultResolver.LookupHost(ctx, name)
	}
	return d.Net.LookupContextHost(ctx, name)
}

// ResolveAddrWithContext resolves a hostname and returns an AddrPort.
// DNS traffic may or may not be routed depending on VirtualTun's setting
func (d VirtualTun) ResolveAddrWithContext(ctx context.Context, name string) (*netip.Addr, error) {
	addrs, err := d.LookupAddr(ctx, name)
	if err != nil {
		return nil, err
	}

	addrs_v4 := []netip.Addr{}
	addrs_v6 := []netip.Addr{}

	for _, saddr := range addrs {
		addr, err := netip.ParseAddr(saddr)
		if err == nil {
			if addr.Is4() {
				addrs_v4 = append(addrs_v4, addr)
			} else if addr.Is6() {
				addrs_v6 = append(addrs_v6, addr)
			}
		}
	}

	rand.Shuffle(len(addrs_v4), func(i, j int) {
		addrs_v4[i], addrs_v4[j] = addrs_v4[j], addrs_v4[i]
	})
	rand.Shuffle(len(addrs_v6), func(i, j int) {
		addrs_v6[i], addrs_v6[j] = addrs_v6[j], addrs_v6[i]
	})

	addrs_all := []netip.Addr{}

	switch d.ResolveConfig.ResolveStrategy {
	case "ipv4":
		addrs_all = append(addrs_v4, addrs_v6...)
	case "ipv6":
		addrs_all = append(addrs_v6, addrs_v4...)
	}

	if len(addrs_all) == 0 {
		return nil, errors.New("no address found for: " + name)
	}

	return &addrs_all[0], nil
}

// Resolve resolves a hostname and returns an IP.
// DNS traffic may or may not be routed depending on VirtualTun's setting
func (d VirtualTun) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	log.Printf("Resolving address for %s\n", name)

	addr, err := d.ResolveAddrWithContext(ctx, name)
	if err != nil {
		return nil, nil, err
	}

	return ctx, addr.AsSlice(), nil
}

func parseAddressPort(endpoint string) (*addressPort, error) {
	name, sport, err := net.SplitHostPort(endpoint)
	if err != nil {
		return nil, err
	}

	port, err := strconv.Atoi(sport)
	if err != nil || port < 0 || port > 65535 {
		return nil, &net.OpError{Op: "dial", Err: errors.New("port must be numeric")}
	}

	return &addressPort{address: name, port: uint16(port)}, nil
}

func (d VirtualTun) resolveToAddrPort(endpoint *addressPort) (*netip.AddrPort, error) {
	addr, err := d.ResolveAddrWithContext(context.Background(), endpoint.address)
	if err != nil {
		return nil, err
	}

	addrPort := netip.AddrPortFrom(*addr, endpoint.port)
	return &addrPort, nil
}

// passthroughResolver is a socks5 NameResolver that performs no resolution: it
// leaves the FQDN untouched (returns a nil IP) so the FQDN survives to the dial
// callback, where the domain-based routing decision is made. Resolution then
// happens on the chosen network — the tunnel netstack for tunnelled hosts, the
// system resolver for direct hosts.
type passthroughResolver struct{}

func (passthroughResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	return ctx, nil, nil
}

// RoutedDial returns a dialer that sends whitelisted hosts through the tunnel
// and dials everything else directly. Used by the HTTP and SNI proxies, whose
// dial callbacks receive the destination hostname intact.
func (d VirtualTun) RoutedDial(router *DomainRouter) func(network, address string) (net.Conn, error) {
	return func(network, address string) (net.Conn, error) {
		if router.route(hostFromAddr(address)) {
			return d.Net.Dial(network, address)
		}
		return net.Dial(network, address)
	}
}

// routedSocks5Dial returns a socks5 dial-with-request callback that routes based
// on the original destination FQDN (preserved on request.DestAddr), falling back
// to the address host for IP-literal targets.
func (d VirtualTun) routedSocks5Dial(router *DomainRouter) func(context.Context, string, string, *socks5.Request) (net.Conn, error) {
	return func(ctx context.Context, network, address string, request *socks5.Request) (net.Conn, error) {
		host := request.DestAddr.FQDN
		if host == "" {
			host = hostFromAddr(address)
		}
		if router.route(host) {
			return d.Net.DialContext(ctx, network, address)
		}
		var dialer net.Dialer
		return dialer.DialContext(ctx, network, address)
	}
}

// SpawnRoutine spawns a socks5 server.
func (config *Socks5Config) SpawnRoutine(vt *VirtualTun) {
	var authMethods []socks5.Authenticator
	if username := config.Username; username != "" {
		authMethods = append(authMethods, socks5.UserPassAuthenticator{
			Credentials: socks5.StaticCredentials{username: config.Password},
		})
	} else {
		authMethods = append(authMethods, socks5.NoAuthAuthenticator{})
	}

	options := []socks5.Option{
		socks5.WithAuthMethods(authMethods),
		socks5.WithBufferPool(bufferpool.NewPool(256 * 1024)),
	}

	if len(config.TunnelDomains) == 0 && !config.LogDomains {
		// Legacy path: everything through the tunnel, resolved via tunnel DNS.
		options = append(options,
			socks5.WithDial(vt.Net.DialContext),
			socks5.WithResolver(vt),
		)
	} else {
		// Split-routing path: keep the FQDN so we can decide per connection.
		router := NewDomainRouter(config.TunnelDomains, config.LogDomains)
		options = append(options,
			socks5.WithDialAndRequest(vt.routedSocks5Dial(router)),
			socks5.WithResolver(passthroughResolver{}),
		)
	}

	server := socks5.NewServer(options...)

	if err := server.ListenAndServe("tcp", config.BindAddress); err != nil {
		vt.Errorf("socks5 proxy: %s\n", err.Error())
	}
}

// SpawnRoutine spawns a http server.
func (config *HTTPConfig) SpawnRoutine(vt *VirtualTun) {
	router := NewDomainRouter(config.TunnelDomains, config.LogDomains)
	server := &HTTPServer{
		config: config,
		dial:   vt.RoutedDial(router),
		auth:   CredentialValidator{config.Username, config.Password},
	}
	if config.Username != "" || config.Password != "" {
		server.authRequired = true
	}

	if config.CertFile != "" && config.KeyFile != "" {
		server.tlsRequired = true
	}

	if err := server.ListenAndServe("tcp", config.BindAddress); err != nil {
		vt.Errorf("http proxy: %s\n", err.Error())
	}
}

// Valid checks the authentication data in CredentialValidator and compare them
// to username and password in constant time.
func (c CredentialValidator) Valid(username, password string) bool {
	u := subtle.ConstantTimeCompare([]byte(c.username), []byte(username))
	p := subtle.ConstantTimeCompare([]byte(c.password), []byte(password))
	return u&p == 1
}

// connForward copy data from `from` to `to`
func connForward(from io.ReadWriteCloser, to io.ReadWriteCloser) {
	defer func() { _ = from.Close() }()
	defer func() { _ = to.Close() }()

	_, err := io.Copy(to, from)
	if err != nil {
		errorLogger.Printf("Cannot forward traffic: %s\n", err.Error())
	}
}

// tcpClientForward starts a new connection via wireguard and forward traffic from `conn`
func tcpClientForward(vt *VirtualTun, raddr *addressPort, conn net.Conn) {
	target, err := vt.resolveToAddrPort(raddr)
	if err != nil {
		vt.Errorf("TCP client tunnel to %s: %s\n", raddr.address, err.Error())
		_ = conn.Close()
		return
	}

	tcpAddr := net.TCPAddrFromAddrPort(*target)

	sconn, err := vt.Net.DialTCP(tcpAddr)
	if err != nil {
		vt.Errorf("TCP client tunnel to %s: %s\n", target, err.Error())
		_ = conn.Close()
		return
	}

	go connForward(sconn, conn)
	go connForward(conn, sconn)
}

// nopFile wraps an io.Reader/io.Writer pair so that closing it is a no-op.
// Used by the STDIO tunnel, whose ends are the process' own stdin/stdout and
// must not be closed when a forwarded connection tears down.
type nopFile struct {
	io.Reader
	io.Writer
}

func (nopFile) Close() error { return nil }

// STDIOTcpForward starts a new connection via wireguard and forward traffic from `conn`
func STDIOTcpForward(vt *VirtualTun, raddr *addressPort, input *os.File, output *os.File) {
	target, err := vt.resolveToAddrPort(raddr)
	if err != nil {
		vt.Errorf("name resolution error for %s: %s\n", raddr.address, err.Error())
		return
	}

	tcpAddr := net.TCPAddrFromAddrPort(*target)
	sconn, err := vt.Net.DialTCP(tcpAddr)
	if err != nil {
		vt.Errorf("TCP client tunnel to %s (%s): %s\n", target, tcpAddr, err.Error())
		return
	}

	go connForward(nopFile{Reader: input}, sconn)
	go connForward(sconn, nopFile{Writer: output})
}

// SpawnRoutine spawns a local TCP server which acts as a proxy to the specified target
func (conf *TCPClientTunnelConfig) SpawnRoutine(vt *VirtualTun) {
	raddr, err := parseAddressPort(conf.Target)
	if err != nil {
		vt.Errorf("TCP client tunnel: %s\n", err.Error())
		return
	}

	server, err := net.ListenTCP("tcp", conf.BindAddress)
	if err != nil {
		vt.Errorf("TCP client tunnel on %s: %s\n", conf.BindAddress.String(), err.Error())
		return
	}

	for {
		conn, err := server.Accept()
		if err != nil {
			vt.Errorf("TCP client tunnel accept: %s\n", err.Error())
			return
		}
		go tcpClientForward(vt, raddr, conn)
	}
}

// SpawnRoutine connects to the specified target and plumbs it to STDIN / STDOUT
func (conf *STDIOTunnelConfig) SpawnRoutine(vt *VirtualTun) {
	raddr, err := parseAddressPort(conf.Target)
	if err != nil {
		vt.Errorf("STDIO tunnel: %s\n", err.Error())
		return
	}

	go STDIOTcpForward(vt, raddr, conf.Input, conf.Output)
}

// tcpServerForward starts a new connection locally and forward traffic from `conn`
func tcpServerForward(vt *VirtualTun, raddr *addressPort, conn net.Conn) {
	target, err := vt.resolveToAddrPort(raddr)
	if err != nil {
		vt.Errorf("TCP server tunnel to %s: %s\n", raddr.address, err.Error())
		_ = conn.Close()
		return
	}

	tcpAddr := net.TCPAddrFromAddrPort(*target)

	sconn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		vt.Errorf("TCP server tunnel to %s: %s\n", target, err.Error())
		_ = conn.Close()
		return
	}

	go connForward(sconn, conn)
	go connForward(conn, sconn)

}

// SpawnRoutine spawns a TCP server on wireguard which acts as a proxy to the specified target
func (conf *TCPServerTunnelConfig) SpawnRoutine(vt *VirtualTun) {
	raddr, err := parseAddressPort(conf.Target)
	if err != nil {
		vt.Errorf("TCP server tunnel: %s\n", err.Error())
		return
	}

	addr := &net.TCPAddr{Port: conf.ListenPort}
	server, err := vt.Net.ListenTCP(addr)
	if err != nil {
		vt.Errorf("TCP server tunnel on port %d: %s\n", conf.ListenPort, err.Error())
		return
	}

	for {
		conn, err := server.Accept()
		if err != nil {
			vt.Errorf("TCP server tunnel accept: %s\n", err.Error())
			return
		}
		go tcpServerForward(vt, raddr, conn)
	}
}

// SpawnRoutine spawns an SNI proxy server.
func (config *SNIConfig) SpawnRoutine(vt *VirtualTun) {
	router := NewDomainRouter(config.TunnelDomains, config.LogDomains)
	dial := vt.RoutedDial(router)

	listener, err := net.Listen("tcp", config.BindAddress)
	if err != nil {
		vt.Errorf("SNI proxy on %s: %s\n", config.BindAddress, err.Error())
		return
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			vt.Errorf("SNI proxy accept: %s\n", err.Error())
			return
		}
		go sniServe(dial, conn)
	}
}

func (d VirtualTun) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("Health metric request: %s\n", r.URL.Path)
	registry := NewHealthRegistry()
	vt := d
	registry.Add(&vt)
	registry.ServeHTTP(w, r)
}

func (d VirtualTun) pingIPs() {
	for _, addr := range d.Conf.CheckAlive {
		socket, err := d.Tnet.Dial("ping", addr.String())
		if err != nil {
			d.Errorf("failed to ping %s: %s\n", addr, err.Error())
			continue
		}

		data := make([]byte, 16)
		if _, err := srand.Read(data); err != nil {
			// Non-fatal: a zero-filled payload still identifies replies
			// by sequence number.
			data = make([]byte, 16)
		}

		requestPing := icmp.Echo{
			Seq:  rand.Intn(1 << 16),
			Data: data,
		}

		var (
			icmpBytes []byte
			proto     int
		)
		if addr.Is4() {
			icmpBytes, _ = (&icmp.Message{Type: ipv4.ICMPTypeEcho, Code: 0, Body: &requestPing}).Marshal(nil)
			proto = 1 // ICMP
		} else if addr.Is6() {
			icmpBytes, _ = (&icmp.Message{Type: ipv6.ICMPTypeEchoRequest, Code: 0, Body: &requestPing}).Marshal(nil)
			proto = 58 // ICMPv6
		} else {
			d.Errorf("failed to ping %s: invalid address: %s\n", addr, addr.String())
			_ = socket.Close()
			continue
		}

		addr := addr
		// The probe goroutine fully owns the socket: the read deadline
		// bounds the wait and Close releases it on every exit path.
		go func() {
			defer func() { _ = socket.Close() }()

			_ = socket.SetReadDeadline(time.Now().Add(time.Duration(d.Conf.CheckAliveInterval) * time.Second))
			if _, err := socket.Write(icmpBytes); err != nil {
				d.Errorf("failed to ping %s: %s\n", addr, err.Error())
				return
			}

			n, err := socket.Read(icmpBytes[:])
			if err != nil {
				// Expected when a pong does not arrive in time.
				return
			}

			replyPacket, err := icmp.ParseMessage(proto, icmpBytes[:n])
			if err != nil {
				d.Errorf("failed to parse ping response from %s: %s\n", addr, err.Error())
				return
			}

			if addr.Is4() {
				replyPing, ok := replyPacket.Body.(*icmp.Echo)
				if !ok {
					d.Errorf("failed to parse ping response from %s: invalid reply type: %s\n", addr, replyPacket.Type)
					return
				}
				if !bytes.Equal(replyPing.Data, requestPing.Data) || replyPing.Seq != requestPing.Seq {
					d.Errorf("failed to parse ping response from %s: invalid ping reply: %v\n", addr, replyPing)
					return
				}
			}

			if addr.Is6() {
				replyPing, ok := replyPacket.Body.(*icmp.RawBody)
				if !ok {
					d.Errorf("failed to parse ping response from %s: invalid reply type: %s\n", addr, replyPacket.Type)
					return
				}

				seq := binary.BigEndian.Uint16(replyPing.Data[2:4])
				pongBody := replyPing.Data[4:]
				if !bytes.Equal(pongBody, requestPing.Data) || int(seq) != requestPing.Seq {
					d.Errorf("failed to parse ping response from %s: invalid ping reply: %v\n", addr, replyPing)
					return
				}
			}

			d.PingRecordLock.Lock()
			d.PingRecord[addr.String()] = uint64(time.Now().Unix())
			d.PingRecordLock.Unlock()
		}()
	}
}

func (d VirtualTun) StartPingIPs() {
	if d.Tnet == nil || len(d.Conf.CheckAlive) == 0 {
		return
	}

	d.PingRecordLock.Lock()
	for _, addr := range d.Conf.CheckAlive {
		d.PingRecord[addr.String()] = 0
	}
	d.PingRecordLock.Unlock()

	go func() {
		for {
			d.pingIPs()
			time.Sleep(time.Duration(d.Conf.CheckAliveInterval) * time.Second)
		}
	}()
}
