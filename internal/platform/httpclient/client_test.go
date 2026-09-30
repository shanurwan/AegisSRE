package httpclient

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestDirectClientRejectsRedirects(t *testing.T) {
	t.Parallel()
	var targetCalls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		targetCalls.Add(1)
	}))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()

	response, err := Direct(time.Second).Get(redirect.URL)
	if response != nil {
		response.Body.Close()
	}
	if err == nil {
		t.Fatal("redirect unexpectedly crossed the configured trust boundary")
	}
	if targetCalls.Load() != 0 {
		t.Fatalf("redirect target received %d requests", targetCalls.Load())
	}
}

func TestDirectClientDisablesAmbientProxy(t *testing.T) {
	t.Parallel()
	transport, ok := Direct(time.Second).Transport.(*http.Transport)
	if !ok || transport.Proxy != nil {
		t.Fatalf("direct client retained an ambient proxy: %#v", transport)
	}
}
