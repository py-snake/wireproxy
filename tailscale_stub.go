//go:build !tsnet

package wireproxy

import "errors"

// startTsnet is a placeholder for binaries built without the "tsnet" build
// tag: configuration parsing and validation still work (so --configtest can
// verify such files), but Tailscale connections cannot be started.
func startTsnet(name string, conf *TailscaleConfig, logLevel int) (*VirtualTun, error) {
	_ = name
	_ = conf
	_ = logLevel
	return nil, errors.New("this binary was built without Tailscale support; rebuild with `-tags tsnet` (or `make wireproxy-tsnet`)")
}
