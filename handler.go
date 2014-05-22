package httpsession

import (
	"github.com/timob/httpsession/store"
	"github.com/timob/httpsession/token"
	"net/http"
	"time"
)

// HTTP handler with *Session
type Handler interface {
	ServeHTTP(http.ResponseWriter, *http.Request, *Session)
}

// Function to be used as Handler
type HandlerFunc func(http.ResponseWriter, *http.Request, *Session)

//Calls h(w, r, s)
func (h HandlerFunc) ServeHTTP(w http.ResponseWriter, r *http.Request, t *Session) {
	h(w, r, t)
}

// Server to serve Handlers.
type SessionServer struct {
	Category    *SessionCategory
	TokenServer token.Server
}

func NewSessionServer(name string, sessionEntryStore store.SessionEntryStore, tokenServer token.Server, sessionTimeout, authTimeout time.Duration) *SessionServer {
	sessionCat := NewSessionCategory(name, sessionEntryStore, sessionTimeout, authTimeout)
	return &SessionServer{sessionCat, tokenServer}
}

// Specify a Handler h for the SessionServer. h does not need to call Save()
// on the *Session.
func (s *SessionServer) Handle(h Handler) http.Handler {
	f := func(w http.ResponseWriter, r *http.Request, t token.SessionToken) {
		session, err := s.Category.GetSession(t)
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
