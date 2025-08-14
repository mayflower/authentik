package ldap

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	api "goauthentik.io/packages/client-go"
)

type BackendScenario struct {
	BackendUp bool
}

func NewFakeTransport(s *BackendScenario) http.RoundTripper {
	return &fakeTransport{scenario: s}
}

type fakeTransport struct {
	scenario *BackendScenario
}

func (f *fakeTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	s := f.scenario
	p := r.URL.Path
	header := f.sessionHeaders()

	if !s.BackendUp {
		return f.json(r, http.StatusBadGateway, header, nil)
	}

	if strings.Contains(p, "/flows/executor/") {
		return f.json(r, http.StatusOK, header, api.NewRedirectChallenge("/"))
	}

	if strings.Contains(p, "/outposts/ldap/") {
		return f.json(r, http.StatusOK, header, &api.LDAPCheckAccess{
			Access: api.PolicyTestResult{Passing: true},
		})
	}

	if strings.Contains(p, "/core/users/me/") {
		// /core/users/me/ returns a SessionUser; the generated client enforces
		// its required fields on unmarshal, so return a fully-populated one.
		self := api.NewUserSelf(
			1, "alice", "Alice", true, false, true,
			[]api.UserSelfGroups{}, []api.UserSelfRoles{},
			"", "alice", map[string]any{}, []string{},
		)
		return f.json(r, http.StatusOK, header, api.NewSessionUser(*self, []api.UserSelf{*self}))
	}

	return &http.Response{
		StatusCode: http.StatusNotFound,
		Header:     header,
		Body:       io.NopCloser(strings.NewReader("not found")),
		Request:    r,
	}, nil
}

func (f *fakeTransport) sessionHeaders() http.Header {
	header := make(http.Header)
	cookie := &http.Cookie{
		Name:    "authentik_session",
		Value:   "testing-session",
		Expires: time.Now().Add(1 * time.Second).UTC(),
		Path:    "/",
	}
	header.Set("Set-Cookie", cookie.String())
	header.Set("Content-Type", "application/json")
	return header
}

func (f *fakeTransport) json(r *http.Request, status int, h http.Header, v any) (*http.Response, error) {
	b, _ := json.Marshal(v)
	return &http.Response{
		StatusCode: status,
		Header:     h,
		Body:       io.NopCloser(bytes.NewReader(b)),
		Request:    r,
	}, nil
}
