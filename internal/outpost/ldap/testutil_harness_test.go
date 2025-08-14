package ldap

import (
	"net"
	"sync"
	"testing"

	"goauthentik.io/api/v3"
	"goauthentik.io/internal/outpost/ak"
	memorybind "goauthentik.io/internal/outpost/ldap/bind/memory"
	flags "goauthentik.io/internal/outpost/ldap/flags"
)

type Harness struct {
	Server   *LDAPServer
	Provider *ProviderInstance
	Scenario *BackendScenario
}

type harnessConfig struct{ scenario *BackendScenario }

func NewHarness(t *testing.T) *Harness {
	t.Helper()
	cfg := &harnessConfig{}

	cfg.scenario = &BackendScenario{BackendUp: true}

	ak.SetTLSTransportForTests(NewFakeTransport(cfg.scenario))

	outpost := *api.NewOutpostWithDefaults()
	outpost.SetName("test-outpost")
	ac := ak.MockAK(outpost, ak.MockConfig())

	srv := NewServer(ac).(*LDAPServer)

	pi := &ProviderInstance{
		BaseDN:                 "dc=example,dc=com",
		UserDN:                 "ou=users,dc=example,dc=com",
		VirtualGroupDN:         "ou=vg,dc=example,dc=com",
		GroupDN:                "ou=groups,dc=example,dc=com",
		appSlug:                "test-app",
		authenticationFlowSlug: "default-authentication-flow",
		invalidationFlowSlug:   nil,
		s:                      srv,
		outpostName:            outpost.GetName(),
		providerPk:             1,
		boundUsersMutex:        &sync.RWMutex{},
		boundUsers:             make(map[string]*flags.UserFlags),
		mfaSupport:             false,
	}

	pi.binder = memorybind.NewSessionBinder(pi, nil)

	srv.providers = []*ProviderInstance{pi}
	return &Harness{Server: srv, Provider: pi, Scenario: cfg.scenario}
}

func (h *Harness) NewConn(t *testing.T) net.Conn {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	_ = b.Close()
	return a
}
