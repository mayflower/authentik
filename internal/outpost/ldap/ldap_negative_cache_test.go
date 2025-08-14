package ldap

import (
	"testing"

	"beryju.io/ldap"
)

func TestLDAPBind_NegativeCachePersistsInvalidCredentials(t *testing.T) {
	h := NewHarness(t)
	srv := h.Server

	bindDN := "cn=alice,dc=example,dc=com"
	bindPW := "correct-horse-battery-staple"

	h.Scenario.BackendUp = false
	c1 := h.NewConn(t)
	rc, err := srv.Bind(bindDN, bindPW, c1)
	if err != nil {
		t.Fatalf("unexpected error on first bind: %v", err)
	}
	if rc == ldap.LDAPResultSuccess {
		t.Fatalf("unexpected LDAPResultSuccess on first bind")
	}

	h.Scenario.BackendUp = true
	c2 := h.NewConn(t)
	rc2, err := srv.Bind(bindDN, bindPW, c2)
	if err != nil {
		t.Fatalf("unexpected error on second bind: %v", err)
	}
	if rc2 != ldap.LDAPResultSuccess {
		t.Fatalf("expected Success on second bind after backend recovery, got %v", rc2)
	}

	h.Scenario.BackendUp = false
	c3 := h.NewConn(t)
	rc3, err := srv.Bind(bindDN, bindPW, c3)
	if err != nil {
		t.Fatalf("unexpected error on third bind: %v", err)
	}
	if rc3 != ldap.LDAPResultSuccess {
		t.Fatalf("expected Success on third bind from session cache with backend down, got %v", rc3)
	}

}
