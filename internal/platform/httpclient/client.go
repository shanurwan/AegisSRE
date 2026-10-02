// Package httpclient provides the hardened HTTP defaults used at outbound
// trust boundaries. Internal service traffic bypasses ambient proxy settings,
// and redirects never carry structured incident data to another endpoint.
package httpclient

import (
	"crypto/tls"
	"errors"
	"net/http"
	"time"
)

func Direct(timeout time.Duration) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &http.Client{Timeout: timeout, Transport: transport, CheckRedirect: rejectRedirect}
}

func DirectTLS(timeout time.Duration, config *tls.Config) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	if config != nil {
		transport.TLSClientConfig = config.Clone()
	}
	return &http.Client{Timeout: timeout, Transport: transport, CheckRedirect: rejectRedirect}
}

func External(timeout time.Duration) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	return &http.Client{Timeout: timeout, Transport: transport, CheckRedirect: rejectRedirect}
}

func rejectRedirect(*http.Request, []*http.Request) error {
	return errors.New("HTTP redirects are disabled at AegisSRE trust boundaries")
}
