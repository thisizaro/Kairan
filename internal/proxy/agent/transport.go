package agent

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"syscall"
	"time"
)

const maxCAFileBytes = 1 << 20

// NewHTTPClient builds the client the agent talks to the control plane with
// (M-D31, PRD J2).
//
//   - Outbound only. The proxy honours HTTPS_PROXY, HTTP_PROXY and NO_PROXY
//     through http.ProxyFromEnvironment, so a corporate egress proxy works
//     (CONNECT for https). Go never proxies loopback addresses, which is why
//     the local demo and tests talk straight to localhost.
//   - TLS 1.2 minimum, the system roots plus the PEM certificates in caFile
//     (optional). InsecureSkipVerify is never set.
//   - No overall Timeout: the agent puts a deadline on each request itself
//     (wire.PollClientTimeout for a poll, 10s for a status report).
//   - Redirects are not followed, so the bearer token never goes to a host
//     the operator did not configure. A 3xx is an error to the agent.
func NewHTTPClient(caFile string) (*http.Client, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pem, err := readCAFile(caFile)
		if err != nil {
			return nil, err
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("agent: ca_file holds no PEM certificate")
		}
		cfg.RootCAs = pool
	}
	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:       cfg,
		TLSHandshakeTimeout:   10 * time.Second,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          2,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	return &http.Client{
		Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

func readCAFile(path string) ([]byte, error) {
	// Non-blocking so a FIFO at the path cannot hang startup; the type is
	// checked on the open descriptor.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("agent: ca_file: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("agent: ca_file: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return nil, errors.New("agent: ca_file is not a regular file")
	}
	b, err := io.ReadAll(io.LimitReader(f, maxCAFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("agent: ca_file: %w", err)
	}
	if len(b) > maxCAFileBytes {
		return nil, errors.New("agent: ca_file too large")
	}
	return b, nil
}
