package httpsession

import (
	"github.com/timob/httpsession/token"
	"net/http"
)

// HTTP handler with *Session
type Handler interface {
	ServeHTTP(http.ResponseWriter, *http.Request, *Session)
}

// Function to be used as Handler
type HandlerFunc func(http.ResponseWriter, *http.Request, *Session)

//Calls h(w, r, s)
func (h HandlerFunc) ServeHTTP(w http.ResponseWriter, r *http.Request, s *Session) {
	h(w, r, s)
}

// Server to serve Handlers.
type SessionServer struct {
	SessionDB   *SessionDB
	TokenServer token.Server
}

// Specify a Handler h for the SessionServer. h does not need to call Save()
// on the *Session.
func (s *SessionServer) Handle(h Handler) http.Handler {
	f := func(w http.ResponseWriter, r *http.Request, t token.SessionToken) {
		session, err := s.SessionDB.GetSession(t)
		if err != nil {
			http.Error(w, "error", 500)
			return
		}
		err = session.SetToken()
		if err != nil {
			http.Error(w, "error", 500)
			return
		}
		h.ServeHTTP(w, r, session)
		err = session.Save()
		if err != nil {
			http.Error(w, "error", 500)
			return
		}
	}

	return s.TokenServer.Handle(token.HandlerFunc(f))
}
