package httpsession

import (
	"github.com/timob/httpsession/store"
	"github.com/timob/httpsession/token"
	"github.com/timob/httpsession/token/sessioncookie"
	"net/http"
	"time"
)

type CookieSession struct {
	store        store.SessionEntryStore
	name         string
	sessionToken token.Token
	cookie       *sessioncookie.SessionCookie
	*Session
}

type AuthCookieSession struct {
	authCookie *sessioncookie.SessionCookie
	authToken  token.Token
	*CookieSession
}

func OpenCookieSession(name string, store store.SessionEntryStore, w http.ResponseWriter, r *http.Request) (*CookieSession, error) {
	cs := new(CookieSession)
	cs.init(name, store, w, r)
	s, t, err := OpenSession(cs.cookie.GetToken(), store)
	if err != nil {
		return nil, err
	}
	cs.Session = s
	cs.sessionToken = t
	return cs, nil
}

func OpenCookieSessionWithAuth(name string, authenticationTimeout time.Duration, store store.SessionEntryStore, w http.ResponseWriter, r *http.Request) (*AuthCookieSession, error) {
	cs := &AuthCookieSession{authCookie: &sessioncookie.SessionCookie{name + "_auth", w, r}, CookieSession: &CookieSession{}}
	cs.init(name, store, w, r)
	s, t, a, err := OpenSessionWithAuth(cs.cookie.GetToken(), cs.authCookie.GetToken(), authenticationTimeout, store)
	if err != nil {
		return nil, err
	}
	cs.Session = s
	cs.sessionToken = t
	cs.authToken = a
	return cs, nil

}

func (c *CookieSession) init(name string, store store.SessionEntryStore, w http.ResponseWriter, r *http.Request) {
	c.name = name
	c.store = store
	c.cookie = &sessioncookie.SessionCookie{name + "_session", w, r}
}

func (c *CookieSession) Save(timeout time.Duration) {
	c.Session.Save(timeout)
	c.cookie.SetToken(c.sessionToken)
}

func (c *CookieSession) New() {
	c.Session.Save(0)
	c.Session.Clear()
	c.sessionToken = c.Session.Recreate()
}

func (c *CookieSession) RemoveCookie() {
	c.cookie.Remove()
}

func (a *AuthCookieSession) Save(timeout time.Duration) {
	a.CookieSession.Save(timeout)
	a.authCookie.SetToken(a.authToken)
}

func (a *AuthCookieSession) RemoveCookie() {
	a.CookieSession.RemoveCookie()
	a.authCookie.Remove()
}
