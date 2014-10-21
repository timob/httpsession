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
	authCookie   *sessioncookie.SessionCookie
	authToken    token.Token
	*AuthSession
}

type AuthTimeout time.Duration

var DeaultAuthTimeout = AuthTimeout(time.Minute * 10)

func OpenCookieSession(name string, store store.SessionEntryStore, w http.ResponseWriter, r *http.Request) (*CookieSession, error) {
	return DeaultAuthTimeout.OpenCookieSession(name, store, w, r)
}

func (a AuthTimeout) OpenCookieSession(name string, store store.SessionEntryStore, w http.ResponseWriter, r *http.Request) (*CookieSession, error) {
	c := new(CookieSession)
	c.name = name
	c.store = store
	c.cookie = &sessioncookie.SessionCookie{name + "_session", w, r}
	c.authCookie = &sessioncookie.SessionCookie{name + "_auth", w, r}
	s, t, at, err := OpenSessionWithAuth(c.cookie.GetToken(), c.authCookie.GetToken(), time.Duration(a), store)
	if err != nil {
		return nil, err
	}
	c.AuthSession = s
	c.sessionToken = t
	c.authToken = at
	return c, nil
}

func (c *CookieSession) Save(timeout time.Duration) {
	c.Session.Save(timeout)
	if c.InGracePeriod() == false {
		c.cookie.SetToken(c.sessionToken, timeout)
		c.authCookie.SetToken(c.authToken, timeout)
	}
}

func (c *CookieSession) New() {
	c.Session.Save(0)
	c.Session.Clear()
	c.sessionToken = c.Session.Recreate()
}

func (c *CookieSession) RemoveCookie() {
	c.cookie.Remove()
	c.authCookie.Remove()
}
