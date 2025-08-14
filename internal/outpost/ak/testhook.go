package ak

import "net/http"

func SetTLSTransportForTests(rt http.RoundTripper) {
	tlsTransport = &rt
}
