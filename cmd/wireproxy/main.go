package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/landlock-lsm/go-landlock/landlock"

	"github.com/akamensky/argparse"
	"github.com/windtf/wireproxy"
	"golang.zx2c4.com/wireguard/device"
	"suah.dev/protect"
)

// an argument to denote that this process was spawned by -d
const daemonProcess = "daemon-process"

// default paths for wireproxy config file
var default_config_paths = []string{
	"/etc/wireproxy/wireproxy.conf",
	os.Getenv("HOME") + "/.config/wireproxy.conf",
}

var version = "1.0.8-dev"

func panicIfError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

// attempts to pledge and panic if it fails
// this does nothing on non-OpenBSD systems
func pledgeOrPanic(promises string) {
	panicIfError(protect.Pledge(promises))
}

// attempts to unveil and panic if it fails
// this does nothing on non-OpenBSD systems
func unveilOrPanic(path string, flags string) {
	panicIfError(protect.Unveil(path, flags))
}

// get the executable path via syscalls or infer it from argv
func executablePath() string {
	programPath, err := os.Executable()
	if err != nil {
		return os.Args[0]
	}
	return programPath
}

// check if default config file paths exist
func configFilePath() (string, bool) {
	for _, path := range default_config_paths {
		if _, err := os.Stat(path); err == nil {
			return path, true
		}
	}
	return "", false
}

// get the file paths for TLS cert and key from the config
func tlsFilePaths(specs []*wireproxy.ConnectionSpec) []string {
	var paths []string
	for _, spec := range specs {
		for _, routine := range spec.Conf.Routines {
			http, ok := routine.(*wireproxy.HTTPConfig)
			if !ok {
				continue
			}
			if http.CertFile != "" {
				paths = append(paths, http.CertFile)
			}
			if http.KeyFile != "" {
				paths = append(paths, http.KeyFile)
			}
		}
	}
	return paths
}

// lockOptions carries the per-run sandbox requirements derived from the
// parsed configuration.
type lockOptions struct {
	// roFiles are extra read-only file paths (TLS cert/key material).
	roFiles []string
	// rwDirs are directories that must stay writable (Tailscale state).
	rwDirs []string
	// needsWriteAccess relaxes the OpenBSD pledge to allow writes.
	needsWriteAccess bool
}

func lock(stage string, opts lockOptions) {
	switch stage {
	case "boot":
		exePath := executablePath()
		// OpenBSD
		unveilOrPanic("/", "r")
		unveilOrPanic(exePath, "x")
		// only allow standard stdio operation, file reading, networking, and exec
		// also remove unveil permission to lock unveil
		// NOTE: wpath/cpath are kept until the "ready" stage because Tailscale
		// connections may need them; they are dropped there.
		pledgeOrPanic("stdio rpath inet dns proc exec wpath cpath")
		// Linux: filesystem lockdown is deferred entirely to the "ready"
		// stage, where all dynamic requirements (TLS material, Tailscale
		// state dirs) are known. Applying RODirs("/") here would make it
		// impossible to grant write access later: Landlock layers intersect.
	case "boot-daemon":
	case "read-config":
		// OpenBSD: pledge can only narrow, so wpath/cpath must survive this
		// stage for the ready stage to re-request them (Tailscale state).
		pledgeOrPanic("stdio rpath inet dns wpath cpath")
	case "ready":
		// no file access is allowed from now on, only networking
		// OpenBSD
		pledge := "stdio inet dns"
		if opts.needsWriteAccess {
			pledge = "stdio inet dns wpath cpath"
		}
		pledgeOrPanic(pledge)
		// Linux
		net.DefaultResolver.PreferGo = true // needed to lock down dependencies

		// We need to define the static rules beforehand,
		// so we can add the provided dynamic rules

		rules := []landlock.Rule{
			landlock.ROFiles("/etc/resolv.conf").IgnoreIfMissing(),
			landlock.ROFiles("/dev/fd").IgnoreIfMissing(),
			landlock.ROFiles("/dev/zero").IgnoreIfMissing(),
			landlock.ROFiles("/dev/urandom").IgnoreIfMissing(),
			landlock.ROFiles("/etc/localtime").IgnoreIfMissing(),
			landlock.ROFiles("/proc/self/stat").IgnoreIfMissing(),
			landlock.ROFiles("/proc/self/status").IgnoreIfMissing(),
			landlock.ROFiles("/usr/share/locale").IgnoreIfMissing(),
			landlock.ROFiles("/proc/self/cmdline").IgnoreIfMissing(),
			landlock.ROFiles("/usr/share/zoneinfo").IgnoreIfMissing(),
			landlock.ROFiles("/proc/sys/kernel/version").IgnoreIfMissing(),
			landlock.ROFiles("/proc/sys/kernel/ngroups_max").IgnoreIfMissing(),
			landlock.ROFiles("/proc/sys/kernel/cap_last_cap").IgnoreIfMissing(),
			landlock.ROFiles("/proc/sys/vm/overcommit_memory").IgnoreIfMissing(),
			landlock.RWFiles("/dev/log").IgnoreIfMissing(),
			landlock.RWFiles("/dev/null").IgnoreIfMissing(),
			landlock.RWFiles("/dev/full").IgnoreIfMissing(),
			landlock.RWFiles("/proc/self/fd").IgnoreIfMissing(),
		}

		for _, file := range opts.roFiles {
			rules = append(rules, landlock.ROFiles(file).IgnoreIfMissing())
		}
		for _, dir := range opts.rwDirs {
			rules = append(rules, landlock.RWDirs(dir))
		}

		panicIfError(landlock.V1.BestEffort().RestrictPaths(rules...))

	default:
		panic("invalid stage")
	}
}

// extractPort parses the port of addr, rejecting out-of-range values that
// would silently truncate to a different port when narrowed to uint16.
func extractPort(addr string) (uint16, error) {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, fmt.Errorf("failed to extract port from %s: %w", addr, err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return 0, fmt.Errorf("failed to extract port from %s: invalid port", addr)
	}

	return uint16(port), nil
}

func lockNetwork(specs []*wireproxy.ConnectionSpec, infoAddr *string) error {
	// Tailscale connections dial arbitrary control/DERP endpoints and
	// split-routed proxies dial non-matching destinations directly; the
	// TCP connect restriction cannot express these policies.
	if wireproxy.NeedsOpenEgress(specs) {
		log.Println("WARNING: skipping Landlock network restrictions: " +
			"the configuration contains a Tailscale connection or split-routed proxy that requires arbitrary outbound connectivity")
		return nil
	}

	var rules []landlock.Rule
	if infoAddr != nil && *infoAddr != "" {
		port, err := extractPort(*infoAddr)
		if err != nil {
			return err
		}
		rules = append(rules, landlock.BindTCP(port))
	}

	for _, spec := range specs {
		for _, section := range spec.Conf.Routines {
			switch section := section.(type) {
			case *wireproxy.TCPServerTunnelConfig:
				host, portStr, err := net.SplitHostPort(section.Target)
				if err != nil {
					return fmt.Errorf("connection %q: TCPServerTunnel target %q: %w", spec.Name, section.Target, err)
				}
				port, err := extractPort(net.JoinHostPort(host, portStr))
				if err != nil {
					return fmt.Errorf("connection %q: %w", spec.Name, err)
				}
				rules = append(rules, landlock.ConnectTCP(port))
			case *wireproxy.HTTPConfig:
				port, err := extractPort(section.BindAddress)
				if err != nil {
					return fmt.Errorf("connection %q: %w", spec.Name, err)
				}
				rules = append(rules, landlock.BindTCP(port))
			case *wireproxy.TCPClientTunnelConfig:
				if section.BindAddress == nil {
					return fmt.Errorf("connection %q: TCPClientTunnel has no bind address", spec.Name)
				}
				rules = append(rules, landlock.BindTCP(uint16(section.BindAddress.Port)))
			case *wireproxy.Socks5Config:
				port, err := extractPort(section.BindAddress)
				if err != nil {
					return fmt.Errorf("connection %q: %w", spec.Name, err)
				}
				rules = append(rules, landlock.BindTCP(port))
			case *wireproxy.SNIConfig:
				port, err := extractPort(section.BindAddress)
				if err != nil {
					return fmt.Errorf("connection %q: %w", spec.Name, err)
				}
				rules = append(rules, landlock.BindTCP(port))
			case *wireproxy.UDPProxyTunnelConfig:
				// UDP is outside Landlock V4's TCP-only net rules.
			}
		}
	}

	panicIfError(landlock.V4.BestEffort().RestrictNet(rules...))
	return nil
}

func main() {
	s := make(chan os.Signal, 1)
	signal.Notify(s, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM)
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		<-s
		cancel()
	}()

	exePath := executablePath()
	lock("boot", lockOptions{})

	isDaemonProcess := len(os.Args) > 1 && os.Args[1] == daemonProcess
	// Copy argv before mutating it: args aliases os.Args' backing array.
	args := append([]string(nil), os.Args...)
	if isDaemonProcess {
		lock("boot-daemon", lockOptions{})
		args = append([]string{args[0]}, os.Args[2:]...)
	}
	parser := argparse.NewParser("wireproxy", "Userspace wireguard client for proxying")

	config := parser.StringList("c", "config", &argparse.Options{Help: "Path of configuration file (repeatable; directories are expanded to their *.conf files)"})
	silent := parser.Flag("s", "silent", &argparse.Options{Help: "Silent mode"})
	daemon := parser.Flag("d", "daemon", &argparse.Options{Help: "Make wireproxy run in background"})
	info := parser.String("i", "info", &argparse.Options{Help: "Specify the address and port for exposing health status"})
	printVerison := parser.Flag("v", "version", &argparse.Options{Help: "Print version"})
	configTest := parser.Flag("n", "configtest", &argparse.Options{Help: "Configtest mode. Only check the configuration file(s) for validity."})

	err := parser.Parse(args)
	if err != nil {
		fmt.Print(parser.Usage(err))
		return
	}

	if *printVerison {
		fmt.Printf("wireproxy, version %s\n", version)
		return
	}

	configPaths := *config
	if len(configPaths) == 0 {
		if path, config_exist := configFilePath(); config_exist {
			configPaths = []string{path}
		} else {
			fmt.Println("configuration path is required")
			return
		}
	}

	if !*daemon {
		lock("read-config", lockOptions{})
	}

	specs, err := wireproxy.LoadConfigSources(configPaths, *info)
	if err != nil {
		log.Fatal(err)
	}

	if *configTest {
		fmt.Printf("Config OK (%d connection(s):", len(specs))
		for _, spec := range specs {
			fmt.Printf(" %s", spec.Name)
		}
		fmt.Println(")")
		return
	}

	if err := lockNetwork(specs, info); err != nil {
		log.Fatal(err)
	}

	if isDaemonProcess {
		os.Stdout, _ = os.Open(os.DevNull)
		os.Stderr, _ = os.Open(os.DevNull)
		*daemon = false
	}

	if *daemon {
		args[0] = daemonProcess
		cmd := exec.Command(exePath, args...)
		err = cmd.Start()
		if err != nil {
			fmt.Println(err.Error())
		}
		return
	}

	// Wireguard doesn't allow configuring which FD to use for logging
	// https://github.com/WireGuard/wireguard-go/blob/master/device/logger.go#L39
	// so redirect STDOUT to STDERR, we don't want to print anything to STDOUT anyways
	os.Stdout = os.Stderr
	logLevel := device.LogLevelVerbose
	if *silent {
		logLevel = device.LogLevelSilent
	}

	readyOpts := lockOptions{
		roFiles: tlsFilePaths(specs),
	}
	tsDirs := wireproxy.TailscaleStateDirs(specs)
	if len(tsDirs) > 0 {
		// Create state dirs before lockdown: Landlock rules must reference
		// existing paths, and tsnet only creates them later.
		for _, dir := range tsDirs {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				log.Fatalf("cannot create Tailscale state dir %s: %s\n", dir, err.Error())
			}
			readyOpts.rwDirs = append(readyOpts.rwDirs, dir)
		}
		readyOpts.needsWriteAccess = true
	}
	lock("ready", readyOpts)

	// Bind the health endpoint (if requested) BEFORE starting connections:
	// a failed bind then aborts deterministically instead of killing a
	// running daemon from inside a goroutine later on.
	var healthListener net.Listener
	if *info != "" {
		healthListener, err = net.Listen("tcp", *info)
		if err != nil {
			log.Fatalf("cannot bind health endpoint on %s: %s\n", *info, err.Error())
		}
	}

	registry := wireproxy.NewHealthRegistry()
	var wg sync.WaitGroup
	started := int32(0)
	for _, spec := range specs {
		wg.Add(1)
		go func(spec *wireproxy.ConnectionSpec) {
			defer wg.Done()
			tun, err := wireproxy.StartConnection(spec, logLevel)
			if err != nil {
				log.Printf("ERROR: connection %q failed to start, skipping: %s\n", spec.Name, err.Error())
				return
			}
			registry.Add(tun)
			tun.StartPingIPs()

			log.Printf("connection %q started\n", spec.Name)
			for _, spawner := range spec.Conf.Routines {
				go spawner.SpawnRoutine(tun)
			}
			atomic.AddInt32(&started, 1)
		}(spec)
	}
	wg.Wait()

	if atomic.LoadInt32(&started) == 0 {
		log.Fatal("no connections could be started")
	}

	if healthListener != nil {
		go func() {
			if err := http.Serve(healthListener, registry); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("health endpoint stopped: %s\n", err.Error())
			}
		}()
	}

	<-ctx.Done()
}
