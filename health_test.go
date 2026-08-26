package wireproxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn/bindtest"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

type deadTun struct {
	done   chan struct{}
	events chan tun.Event
	once   sync.Once
}

func newDeadTun() *deadTun {
	return &deadTun{done: make(chan struct{}), events: make(chan tun.Event, 1)}
}

func (d *deadTun) File() *os.File { return nil }

func (d *deadTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	<-d.done
	return 0, os.ErrClosed
}

func (d *deadTun) Write(bufs [][]byte, offset int) (int, error) {
	return 0, os.ErrClosed
}

func (d *deadTun) MTU() (int, error) { return 1420, nil }

func (d *deadTun) Name() (string, error) { return "dead0", nil }

func (d *deadTun) Events() <-chan tun.Event { return d.events }

func (d *deadTun) BatchSize() int { return 1 }

func (d *deadTun) Close() error {
	d.once.Do(func() { close(d.done) })
	return nil
}

func hNewDevice(t *testing.T) *device.Device {
	t.Helper()
	dev := device.NewDevice(newDeadTun(), bindtest.NewChannelBinds()[0], device.NewLogger(device.LogLevelSilent, ""))
	t.Cleanup(func() { dev.Close() })
	return dev
}

func hTestVT(name string) *VirtualTun {
	return &VirtualTun{
		Name:           name,
		Conf:           &DeviceConfig{CheckAliveInterval: 5},
		PingRecord:     map[string]uint64{"10.66.0.1": uint64(time.Now().Unix())},
		PingRecordLock: new(sync.Mutex),
	}
}

const hCheckAddr = "10.66.0.1"

func TestWriteRedactedIpc(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"private key redacted", "private_key=SECRETKEYMATERIAL\n", "private_key=REDACTED\n"},
		{"preshared key redacted", "preshared_key=SECRET\npublic_key=VISIBLE\n", "preshared_key=REDACTED\npublic_key=VISIBLE\n"},
		{"other fields verbatim", "listen_port=51820\nendpoint=94.140.11.15:51820\n", "listen_port=51820\nendpoint=94.140.11.15:51820\n"},
		{"malformed line passthrough", "not a key value pair\n", "not a key value pair"},
		{"value containing equals kept", "foo=a=b\n", "foo=a=b\n"},
		{"empty input", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			writeRedactedIpc(&buf, tc.in)
			if buf.String() != tc.want {
				t.Fatalf("writeRedactedIpc(%q) = %q, want %q", tc.in, buf.String(), tc.want)
			}
		})
	}
}

func TestPingSnapshotStale(t *testing.T) {
	now := time.Now().Unix()
	old := uint64(now) - 60

	tests := []struct {
		name      string
		snap      pingSnapshot
		wantStale bool
	}{
		{"fresh pong not stale", pingSnapshot{name: "a", checkAlive: true, interval: 5, records: map[string]uint64{hCheckAddr: uint64(now)}}, false},
		{"old pong stale", pingSnapshot{name: "a", checkAlive: true, interval: 5, records: map[string]uint64{hCheckAddr: old}}, true},
		{"any stale record fails the snapshot", pingSnapshot{name: "a", checkAlive: true, interval: 5, records: map[string]uint64{hCheckAddr: uint64(now), "10.66.0.2": old}}, true},
		{"checkAlive disabled never stale", pingSnapshot{name: "a", checkAlive: false, interval: 5, records: map[string]uint64{hCheckAddr: old}}, false},
		{"no records not stale", pingSnapshot{name: "a", checkAlive: true, interval: 5, records: map[string]uint64{}}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.snap.stale(); got != tc.wantStale {
				t.Fatalf("stale() = %v, want %v", got, tc.wantStale)
			}
		})
	}
}

func TestHealthRegistryConcurrentAddSnapshotCount(t *testing.T) {
	reg := NewHealthRegistry()

	const writers = 8
	const perWriter = 40

	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				reg.Add(hTestVT(fmt.Sprintf("conn-%d-%d", id, i)))
			}
		}(w)
	}

	finished := make(chan struct{})
	go func() {
		wg.Wait()
		close(finished)
	}()

	reads := 0
	for done := false; !done; {
		select {
		case <-finished:
			done = true
		default:
			before := reg.Count()
			snaps := reg.snapshot()
			after := reg.Count()
			if len(snaps) < before || len(snaps) > after {
				t.Fatalf("snapshot length %d outside registry count range [%d, %d]", len(snaps), before, after)
			}
			reads++
		}
	}

	if reg.Count() != writers*perWriter {
		t.Fatalf("final count = %d, want %d", reg.Count(), writers*perWriter)
	}
	snaps := reg.snapshot()
	if len(snaps) != writers*perWriter {
		t.Fatalf("final snapshot length = %d, want %d", len(snaps), writers*perWriter)
	}
	if reads == 0 {
		t.Fatal("reader loop never executed")
	}
}

func TestHealthRegistrySnapshotStaleDetection(t *testing.T) {
	addr := netip.MustParseAddr(hCheckAddr)

	mkVT := func(name string, record uint64) *VirtualTun {
		return &VirtualTun{
			Name: name,
			Dev:  hNewDevice(t),
			Conf: &DeviceConfig{CheckAlive: []netip.Addr{addr}, CheckAliveInterval: 5},
			PingRecord: map[string]uint64{
				hCheckAddr: record,
			},
			PingRecordLock: new(sync.Mutex),
		}
	}

	reg := NewHealthRegistry()
	reg.Add(mkVT("fresh", uint64(time.Now().Unix())))
	reg.Add(mkVT("stale", uint64(time.Now().Add(-60*time.Second).Unix())))

	snaps := reg.snapshot()
	if len(snaps) != 2 {
		t.Fatalf("expected 2 snapshots, got %d", len(snaps))
	}
	if !snaps[0].checkAlive || !snaps[1].checkAlive {
		t.Fatal("connections with CheckAlive and a device must be checkable")
	}
	if snaps[0].stale() {
		t.Fatal("fresh pong must not be stale")
	}
	if !snaps[1].stale() {
		t.Fatal("60s old pong with 5s interval must be stale")
	}
}

func TestHealthServeHTTPReadyz(t *testing.T) {
	addr := []netip.Addr{netip.MustParseAddr(hCheckAddr)}

	tests := []struct {
		name       string
		vt         *VirtualTun
		wantStatus int
	}{
		{
			name: "fresh pongs ready",
			vt: &VirtualTun{
				Name:           "wg-ok",
				Dev:            hNewDevice(t),
				Conf:           &DeviceConfig{CheckAlive: addr, CheckAliveInterval: 5},
				PingRecord:     map[string]uint64{hCheckAddr: uint64(time.Now().Unix())},
				PingRecordLock: new(sync.Mutex),
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "stale pongs unavailable",
			vt: &VirtualTun{
				Name:           "wg-stale",
				Dev:            hNewDevice(t),
				Conf:           &DeviceConfig{CheckAlive: addr, CheckAliveInterval: 5},
				PingRecord:     map[string]uint64{hCheckAddr: uint64(time.Now().Add(-60 * time.Second).Unix())},
				PingRecordLock: new(sync.Mutex),
			},
			wantStatus: http.StatusServiceUnavailable,
		},
		{
			name: "tailscale style connection never fails",
			vt: &VirtualTun{
				Name:           "ts-node",
				Conf:           &DeviceConfig{},
				PingRecord:     map[string]uint64{},
				PingRecordLock: new(sync.Mutex),
			},
			wantStatus: http.StatusOK,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reg := NewHealthRegistry()
			reg.Add(tc.vt)

			rec := httptest.NewRecorder()
			reg.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body: %s)", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if tc.wantStatus != http.StatusOK {
				return
			}
			var report map[string]map[string]uint64
			if err := json.Unmarshal(rec.Body.Bytes(), &report); err != nil {
				t.Fatalf("readyz body is not JSON: %v (%s)", err, rec.Body.String())
			}
			connReport, ok := report[tc.vt.Name]
			if !ok {
				t.Fatalf("readyz report missing connection %q: %s", tc.vt.Name, rec.Body.String())
			}
			if len(tc.vt.PingRecord) > 0 {
				if _, ok := connReport[hCheckAddr]; !ok {
					t.Fatalf("readyz report missing ping record for %s: %s", hCheckAddr, rec.Body.String())
				}
			}
		})
	}
}

func TestHealthServeHTTPMetricsRedaction(t *testing.T) {
	privHex := mustHexKey(t, mcPrivKey)

	dev := hNewDevice(t)
	if err := dev.IpcSet("private_key=" + privHex + "\nlisten_port=51820\n"); err != nil {
		t.Fatalf("IpcSet: %v", err)
	}

	reg := NewHealthRegistry()
	reg.Add(&VirtualTun{
		Name:           "wg-metrics",
		Dev:            dev,
		Conf:           &DeviceConfig{CheckAliveInterval: 5},
		PingRecord:     map[string]uint64{},
		PingRecordLock: new(sync.Mutex),
	})
	reg.Add(&VirtualTun{
		Name:           "ts-metrics",
		Conf:           &DeviceConfig{},
		PingRecord:     map[string]uint64{},
		PingRecordLock: new(sync.Mutex),
	})

	rec := httptest.NewRecorder()
	reg.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	if !bytes.Contains([]byte(body), []byte("# connection: wg-metrics")) ||
		!bytes.Contains([]byte(body), []byte("# connection: ts-metrics")) {
		t.Fatalf("metrics output missing connection headers:\n%s", body)
	}
	if bytes.Contains([]byte(body), []byte(privHex)) {
		t.Fatal("metrics output leaked the private key")
	}
	if !bytes.Contains([]byte(body), []byte("private_key=REDACTED")) {
		t.Fatalf("metrics output should contain redacted private key:\n%s", body)
	}
	if !bytes.Contains([]byte(body), []byte("# metrics unavailable for this connection type")) {
		t.Fatalf("device-less connection should report metrics unavailable:\n%s", body)
	}
}

func TestHealthServeHTTPUnknownPath(t *testing.T) {
	reg := NewHealthRegistry()
	reg.Add(hTestVT("wg"))

	rec := httptest.NewRecorder()
	reg.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/nope", nil))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}
