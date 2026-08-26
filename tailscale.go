//go:build tsnet

// Package-level Tailscale support built on top of the official tsnet
// embedding library. This file is only compiled with `-tags tsnet`.
package wireproxy

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"tailscale.com/tsnet"
)

// tsnetNetwork adapts a tsnet.Server to the Network interface used by
// proxy routines.
type tsnetNetwork struct {
	s *tsnet.Server
}

func (n *tsnetNetwork) Dial(network, address string) (net.Conn, error) {
	return n.s.Dial(context.Background(), network, address)
}

func (n *tsnetNetwork) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return n.s.Dial(ctx, network, address)
}

func (n *tsnetNetwork) DialTCP(addr *net.TCPAddr) (net.Conn, error) {
	if addr == nil {
		return nil, errors.New("dial target is nil")
	}
	host := ""
	if addr.IP != nil {
		host = addr.IP.String()
	}
	return n.s.Dial(context.Background(), "tcp", net.JoinHostPort(host, strconv.Itoa(addr.Port)))
}

func (n *tsnetNetwork) ListenTCP(addr *net.TCPAddr) (net.Listener, error) {
	host := ""
	port := 0
	if addr != nil {
		if addr.IP != nil {
			host = addr.IP.String()
		}
		port = addr.Port
	}
	// Listening inside the tailnet makes the port reachable by other
	// peers; this mirrors the WireGuard TCPServerTunnel semantics.
	return n.s.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
}

// LookupContextHost resolves host to addresses. Tailnet peers resolve by
// their MagicDNS FQDN or bare hostname through the node's peer list;
// anything else falls back to the system resolver. Note that dialing by
// name works regardless, because tsnet resolves names internally too.
func (n *tsnetNetwork) LookupContextHost(ctx context.Context, host string) ([]string, error) {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")

	lc, err := n.s.LocalClient()
	if err == nil {
		st, statErr := lc.Status(ctx)
		if statErr == nil && st != nil {
			var addrs []string
			for _, p := range st.Peer {
				if p == nil {
					continue
				}
				dnsName := strings.TrimSuffix(strings.ToLower(p.DNSName), ".")
				hostname := strings.ToLower(p.HostName)
				if dnsName == "" && hostname == "" {
					continue
				}
				matched := host == dnsName || host == hostname ||
					(dnsName != "" && strings.HasSuffix(dnsName, "."+host))
				if !matched {
					continue
				}
				for _, ip := range p.TailscaleIPs {
					addrs = append(addrs, ip.String())
				}
			}
			if len(addrs) > 0 {
				return addrs, nil
			}
		}
	}

	addrs, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		// The tailnet peer list did not contain this name; surface why the
		// system fallback was used to keep DNS misbehaviour debuggable.
		fmt.Fprintf(os.Stderr, "[%s] DEBUG: %q not in tailnet peer list, system resolver said: %v\n", n.s.Hostname, host, err)
	}
	return addrs, err
}

// startTsnet boots an embedded Tailscale node and wraps it into a
// VirtualTun. On first run without an AuthKey, the login URL is printed to
// stderr; the connection finishes starting once the node is authorized.
func startTsnet(name string, conf *TailscaleConfig, logLevel int) (*VirtualTun, error) {
	_ = logLevel

	stateDir := conf.EffectiveStateDir(name)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, fmt.Errorf("creating state dir %s: %w", stateDir, err)
	}

	s := &tsnet.Server{
		Hostname:      conf.Hostname,
		AuthKey:       conf.AuthKey,
		ControlURL:    conf.ControlURL,
		Ephemeral:     conf.Ephemeral,
		Dir:           stateDir,
		AdvertiseTags: conf.AdvertiseTags,
		UserLogf: func(format string, args ...any) {
			log.New(os.Stderr, "["+name+"] ", log.LstdFlags).Printf(format, args...)
		},
	}

	if err := s.Start(); err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("starting tsnet node %q: %w", conf.Hostname, err)
	}

	// Wait briefly for the node to become usable so that "connection
	// started" is meaningful and later dials do not block indefinitely.
	// NeedsLogin (interactive auth pending) is accepted as started: the
	// login URL has been printed and the node will come up when the user
	// authorizes it.
	gateCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	lc, err := s.LocalClient()
	if err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("local api: %w", err)
	}
	for {
		st, err := lc.Status(gateCtx)
		if err != nil {
			break // status unavailable; proceed optimistically
		}
		switch st.BackendState {
		case "Running":
			log.Printf("[%s] tsnet node running\n", name)
			goto gated
		case "NeedsLogin":
			log.Printf("[%s] waiting for Tailscale login; authorize via the printed URL\n", name)
			goto gated
		}
		select {
		case <-gateCtx.Done():
			goto gated
		case <-time.After(250 * time.Millisecond):
		}
	}
gated:

	return &VirtualTun{
		Name:           name,
		Net:            &tsnetNetwork{s: s},
		SystemDNS:      false,
		Conf:           &DeviceConfig{},
		ResolveConfig:  &ResolveConfig{ResolveStrategy: "ipv4"},
		PingRecord:     make(map[string]uint64),
		PingRecordLock: new(sync.Mutex),
	}, nil
}
