package httpsession

import (
	"github.com/timob/httpsession/store"
	"github.com/timob/httpsession/token/sessioncookie"
	"log"
	"net/http"
	"time"
)

type CookieSession struct {
	cookie *sessioncookie.SessionCookie
	sessionExternal
	sessionInternal *Session
	saved           bool
}

func (c *CookieSession) Save(timeout time.Duration) {
	c.sessionInternal.Save(timeout)
	if timeout == 0 {
		c.cookie.Remove()
	}
	c.saved = true
}

func (c *CookieSession) Recreate() {
	token := c.sessionInternal.Recreate()
	c.cookie.SetToken(token)
}

// HTTP handler with *Session
type Handler interface {
	ServeHTTP(http.ResponseWriter, *http.Request, *CookieSession)
}

// Function to be used as Handler
type HandlerFunc func(http.ResponseWriter, *http.Request, *CookieSession)

//Calls h(w, r, s)
func (h HandlerFunc) ServeHTTP(w http.ResponseWriter, r *http.Request, c *CookieSession) {
	h(w, r, c)
}

// Server to serve Handlers.
type SessionServer struct {
	Name             string
	Store            store.SessionEntryStore
	AuthTokenTimeout time.Duration
}

// Specify a Handler h for the SessionServer. h does not need to call Save()
// on the *Session.
func (s *SessionServer) Handle(h Handler) http.Handler {
	if s.AuthTokenTimeout == 0 {
		s.AuthTokenTimeout = time.Minute * 30
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		defer func() {
			if err != nil {
				log.Print(err)
				http.Error(w, "error", 500)
			}
		}()

		cookie := &sessioncookie.SessionCookie{s.Name + "_session", w, r}
		authCookie := &sessioncookie.SessionCookie{s.Name + "_auth", w, r}

		session, token, authToken, err := OpenSessionWithAuth(cookie.GetToken(), authCookie.GetToken(), s.AuthTokenTimeout, s.Store)
		if err != nil {
			return
		}
		if token != cookie.GetToken() {
			cookie.SetToken(token)
		}
		if authToken != authCookie.GetToken() {
			authCookie.SetToken(authToken)
		}

		cs := &CookieSession{cookie, session, session, false}
		h.ServeHTTP(w, r, cs)
		if cs.saved == false {
			session.Save(time.Minute * 30)
			err = session.GetLastError()
		}
	})
}
