package wireproxy

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// udpSession represents a UDP forwarding session, keyed by the local source address.
// remoteConn is the connection to the remote endpoint (on the WireGuard side).
type udpSession struct {
	remoteConn net.Conn
	// lastActive is guarded by the parent's sessionMu.
	lastActive time.Time
	closeChan  chan struct{}
}

// SpawnRoutine implements the RoutineSpawner interface.
// It starts listening on config.BindAddress, handling each unique source (client) address
// with its own udpSession. If InactivityTimeout > 0, sessions automatically close after inactivity
func (conf *UDPProxyTunnelConfig) SpawnRoutine(vt *VirtualTun) {
	addr, err := net.ResolveUDPAddr("udp", conf.BindAddress)
	if err != nil {
		vt.Errorf("UDP proxy tunnel: could not resolve bind address %s: %v", conf.BindAddress, err)
		return
	}

	listener, err := net.ListenUDP("udp", addr)
	if err != nil {
		vt.Errorf("UDP proxy tunnel: could not listen on %s: %v", conf.BindAddress, err)
		return
	}
	defer func() { _ = listener.Close() }()
	vt.Logf("UDP proxy tunnel listening on %s, forwarding to %s", conf.BindAddress, conf.Target)

	inactivityDur := time.Duration(conf.InactivityTimeout) * time.Second
	sessions := make(map[string]*udpSession)
	var sessionMu sync.Mutex

	closeSessionChan := func(sess *udpSession) {
		select {
		case <-sess.closeChan:
		default:
			close(sess.closeChan)
		}
	}

	removeSession := func(src string, sess *udpSession) {
		sessionMu.Lock()
		if current, ok := sessions[src]; ok && current == sess {
			closeSessionChan(current)
			delete(sessions, src)
		}
		sessionMu.Unlock()
	}

	// Periodically clean up expired sessions if inactivity timeout is enabled
	if conf.InactivityTimeout > 0 {
		go func() {
			ticker := time.NewTicker(10 * time.Second)
			defer ticker.Stop()
			for range ticker.C {
				now := time.Now()
				sessionMu.Lock()
				for key, sess := range sessions {
					if now.Sub(sess.lastActive) >= inactivityDur {
						vt.Logf("UDP proxy tunnel: closing inactive session for %s", key)
						closeSessionChan(sess)
						delete(sessions, key)
					}
				}
				sessionMu.Unlock()
			}
		}()
	}

	// Create or get a UDP session based on the local source address. The
	// remote dial happens without holding sessionMu so that a stalled
	// dial cannot block the reader loop or the cleaner.
	getOrCreateSession := func(srcAddr string) (*udpSession, error) {
		sessionMu.Lock()
		if s, ok := sessions[srcAddr]; ok {
			s.lastActive = time.Now()
			sessionMu.Unlock()
			return s, nil
		}
		sessionMu.Unlock()

		remoteConn, err := vt.Net.Dial("udp", conf.Target)
		if err != nil {
			return nil, fmt.Errorf("could not Dial(%s): %w", conf.Target, err)
		}

		s := &udpSession{
			remoteConn: remoteConn,
			lastActive: time.Now(),
			closeChan:  make(chan struct{}),
		}

		sessionMu.Lock()
		if existing, ok := sessions[srcAddr]; ok {
			// Another goroutine won the race; drop our duplicate.
			sessionMu.Unlock()
			_ = remoteConn.Close()
			existing.lastActive = time.Now()
			return existing, nil
		}
		sessions[srcAddr] = s
		sessionMu.Unlock()

		// Spin up a goroutine to handle traffic from remote -> local
		go conf.handleRemoteToLocal(listener, srcAddr, s, &sessionMu, removeSession)
		return s, nil
	}

	// Main loop to read from local client and forward to remote
	go func() {
		buf := make([]byte, 64*1024) // typical max UDP size
		for {
			n, src, err := listener.ReadFromUDP(buf)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				vt.Errorf("UDP proxy tunnel: error reading from UDP: %v", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}

			srcKey := src.String() // identify session by the local client's IP:port
			s, err := getOrCreateSession(srcKey)
			if err != nil {
				vt.Errorf("UDP proxy tunnel: getOrCreateSession failed for %s: %v", srcKey, err)
				continue
			}

			sessionMu.Lock()
			s.lastActive = time.Now()
			sessionMu.Unlock()
			_, err = s.remoteConn.Write(buf[:n])
			if err != nil {
				vt.Errorf("UDP proxy tunnel: could not write to remote (%s): %v", conf.Target, err)
			}
		}
	}()
}

// handles data from the remote WireGuard side back to the local client
// this function blocks until the session is closed
func (conf *UDPProxyTunnelConfig) handleRemoteToLocal(listener *net.UDPConn, srcAddr string, s *udpSession, sessionMu *sync.Mutex, removeSession func(string, *udpSession)) {
	defer func() {
		removeSession(srcAddr, s)
		_ = s.remoteConn.Close()
	}()
	buf := make([]byte, 64*1024)

	for {
		select {
		case <-s.closeChan:
			return
		default:
		}

		_ = s.remoteConn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := s.remoteConn.Read(buf)
		if err != nil {
			// If a timeout or temporary error, continue to see if the session is closed
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				select {
				case <-s.closeChan:
					return
				default:
					continue
				}
			}
			errorLogger.Printf("UDP proxy tunnel: read error from remote: %v", err)
			return
		}

		sessionMu.Lock()
		s.lastActive = time.Now()
		sessionMu.Unlock()

		dstUDPAddr, err := net.ResolveUDPAddr("udp", srcAddr)
		if err != nil {
			errorLogger.Printf("UDP proxy tunnel: cannot resolve local address %s: %v", srcAddr, err)
			return
		}

		_, err = listener.WriteToUDP(buf[:n], dstUDPAddr)
		if err != nil {
			errorLogger.Printf("UDP proxy tunnel: cannot write to local %s: %v", srcAddr, err)
			return
		}
	}
}
