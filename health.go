package wireproxy

import (
	"bytes"
	"encoding/json"
	"net/http"
	"path"
	"sort"
	"strings"
	"sync"
	"time"
)

// HealthRegistry aggregates health information of multiple connections and
// serves it over HTTP. It is installed on the address given by --info.
//
// Endpoints:
//
//	/readyz   JSON object keyed by connection name, each holding the last
//	          pong timestamps (unix seconds) of its CheckAlive addresses.
//	          Responds 503 when any WireGuard connection with CheckAlive
//	          set has a stale pong; Tailscale connections never fail it.
//	/metrics  `wg show`-style device output per connection, with private
//	          keys redacted.
type HealthRegistry struct {
	mu    sync.Mutex
	conns []*VirtualTun
}

func NewHealthRegistry() *HealthRegistry {
	return &HealthRegistry{}
}

// Add registers a started connection.
func (h *HealthRegistry) Add(vt *VirtualTun) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.conns = append(h.conns, vt)
}

// Count returns the number of registered connections.
func (h *HealthRegistry) Count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.conns)
}

type pingSnapshot struct {
	name       string
	checkAlive bool
	interval   int
	records    map[string]uint64
}

func (s pingSnapshot) stale() bool {
	if !s.checkAlive {
		return false
	}
	for _, record := range s.records {
		lastPong := time.Unix(int64(record), 0)
		// +2 seconds to account for the time it takes to ping the IP
		if time.Since(lastPong) > time.Duration(s.interval+2)*time.Second {
			return true
		}
	}
	return false
}

func (h *HealthRegistry) snapshot() []pingSnapshot {
	h.mu.Lock()
	conns := append([]*VirtualTun(nil), h.conns...)
	h.mu.Unlock()

	out := make([]pingSnapshot, len(conns))
	for i, vt := range conns {
		vt.PingRecordLock.Lock()
		records := make(map[string]uint64, len(vt.PingRecord))
		for k, v := range vt.PingRecord {
			records[k] = v
		}
		vt.PingRecordLock.Unlock()
		out[i] = pingSnapshot{
			name:       vt.Name,
			checkAlive: len(vt.Conf.CheckAlive) > 0 && vt.Dev != nil,
			interval:   vt.Conf.CheckAliveInterval,
			records:    records,
		}
	}
	// Deterministic output independent of connection start order.
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

func (h *HealthRegistry) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch path.Clean(r.URL.Path) {
	case "/readyz":
		status := http.StatusOK
		report := make(map[string]map[string]uint64)
		for _, snap := range h.snapshot() {
			report[snap.name] = snap.records
			if snap.stale() {
				status = http.StatusServiceUnavailable
			}
		}
		body, err := json.Marshal(report)
		if err != nil {
			errorLogger.Printf("Failed to marshal readyz report: %s\n", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.WriteHeader(status)
		_, _ = w.Write(body)
		_, _ = w.Write([]byte("\n"))
	case "/metrics":
		var buf bytes.Buffer
		for _, vt := range h.snapshotConns() {
			buf.WriteString("# connection: " + vt.Name + "\n")
			if vt.Dev == nil {
				buf.WriteString("# metrics unavailable for this connection type\n")
				continue
			}
			get, err := vt.Dev.IpcGet()
			if err != nil {
				errorLogger.Printf("[%s] Failed to get device metrics: %s\n", vt.Name, err.Error())
				continue
			}
			writeRedactedIpc(&buf, get)
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buf.Bytes())
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// snapshotConns copies the registered connections under lock, ordered by name.
func (h *HealthRegistry) snapshotConns() []*VirtualTun {
	h.mu.Lock()
	conns := append([]*VirtualTun(nil), h.conns...)
	h.mu.Unlock()
	sort.Slice(conns, func(i, j int) bool { return conns[i].Name < conns[j].Name })
	return conns
}

// writeRedactedIpc writes an IPC dump to buf, hiding secrets.
func writeRedactedIpc(buf *bytes.Buffer, ipc string) {
	for _, peer := range strings.Split(ipc, "\n") {
		pair := strings.SplitN(peer, "=", 2)
		if len(pair) != 2 {
			buf.WriteString(peer)
			continue
		}
		if pair[0] == "private_key" || pair[0] == "preshared_key" {
			pair[1] = "REDACTED"
		}
		buf.WriteString(pair[0])
		buf.WriteString("=")
		buf.WriteString(pair[1])
		buf.WriteString("\n")
	}
}
